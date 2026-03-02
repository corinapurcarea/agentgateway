use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use ::http::{HeaderMap, StatusCode};
use prost_types::Timestamp;

use crate::cel::{self, Expression, RequestSnapshot};
use crate::http::HeaderOrPseudo;
use crate::http::ext_authz::proto::attribute_context::HttpRequest;
use crate::http::ext_authz::proto::authorization_client::AuthorizationClient;
use crate::http::ext_authz::proto::check_response::HttpResponse;
use crate::http::ext_authz::proto::{
	AttributeContext, CheckRequest, DeniedHttpResponse, Metadata, OkHttpResponse,
};
use crate::http::ext_authz::{
	ExtAuthz, ExtAuthzDynamicMetadata, FailureMode, Protocol, collect_header_values, json_to_struct,
	process_headers,
};
use crate::http::ext_proc::GrpcReferenceChannel;
use crate::mcp::ResourceType;
use crate::proxy::httpproxy::PolicyClient;
use crate::*;

#[derive(Debug, thiserror::Error)]
#[error("mcp ext_authz denied")]
pub struct McpExtAuthzDenied {
	pub response_headers: HeaderMap,
	pub status_code: StatusCode,
	pub body: String,
}

impl Default for McpExtAuthzDenied {
	fn default() -> Self {
		Self {
			response_headers: HeaderMap::new(),
			status_code: StatusCode::FORBIDDEN,
			body: String::new(),
		}
	}
}

#[derive(Debug, Default)]
pub struct McpExtAuthzOkResponse {
	pub request_headers_to_add: HeaderMap,
	pub request_headers_to_remove: Vec<String>,
	pub response_headers_to_add: HeaderMap,
	pub dynamic_metadata: Option<ExtAuthzDynamicMetadata>,
}

#[apply(schema!)]
#[serde(transparent)]
pub struct McpExtAuthz(pub(crate) ExtAuthz);

impl McpExtAuthz {
	pub fn expressions(&self) -> Box<dyn Iterator<Item = &Expression> + '_> {
		self.0.expressions()
	}

	/// Check external authorization using a request snapshot (for MCP backend-level authorization).
	/// This uses the snapshot + optional MCP ResourceType to build the CEL context, allowing
	/// ext_authz metadata expressions to reference MCP CEL variables like `mcp.tool.name`.
	///
	/// Only gRPC protocol is supported for MCP-aware ext_authz. The check sends the original
	/// request headers/path from the snapshot and evaluates metadata CEL expressions with
	/// MCP context.
	pub async fn check(
		&self,
		client: PolicyClient,
		snapshot: &RequestSnapshot,
		mcp: Option<&ResourceType>,
	) -> Result<McpExtAuthzOkResponse, McpExtAuthzDenied> {
		let Protocol::Grpc { context, metadata } = &self.0.protocol else {
			return Err(McpExtAuthzDenied {
				status_code: StatusCode::INTERNAL_SERVER_ERROR,
				body: "mcp_ext_authz only supports gRPC protocol".to_string(),
				..Default::default()
			});
		};
		trace!(
			protocol = "grpc",
			"mcp ext_authz connecting to {:?}", self.0.target
		);

		let chan = GrpcReferenceChannel {
			target: self.0.target.clone(),
			policies: self.0.policies.clone(),
			client,
		};
		let mut grpc_client = AuthorizationClient::new(chan);

		let mut headers = HashMap::new();
		if self.0.include_request_headers.is_empty() {
			for name in snapshot.headers.keys() {
				collect_header_values(&snapshot.headers, name, &mut headers);
			}
		} else {
			for header_spec in &self.0.include_request_headers {
				if let HeaderOrPseudo::Header(header_name) = header_spec {
					collect_header_values(&snapshot.headers, header_name, &mut headers);
				}
			}
		}

		let request = crate::http::ext_authz::proto::attribute_context::Request {
			time: Some(Timestamp::from(SystemTime::now())),
			http: Some(HttpRequest {
				id: String::new(),
				method: snapshot.method.to_string(),
				headers,
				path: snapshot
					.path
					.path_and_query()
					.map(|pq| pq.to_string())
					.unwrap_or_else(|| snapshot.path.path().to_string()),
				host: snapshot
					.host
					.as_ref()
					.map(|h| h.to_string())
					.unwrap_or_default(),
				scheme: snapshot
					.scheme
					.as_ref()
					.map(|s| s.to_string())
					.unwrap_or_else(|| "http".to_string()),
				protocol: "HTTP/1.1".to_string(),
				query: String::new(),
				fragment: String::new(),
				size: 0,
				body: String::new(),
				raw_body: Vec::new(),
			}),
		};

		let metadata_context = build_metadata_from_snapshot(metadata, snapshot, mcp);

		let authz_req = CheckRequest {
			attributes: Some(AttributeContext {
				source: None,
				destination: None,
				request: Some(request),
				metadata_context,
				context_extensions: context.clone().unwrap_or_default(),
				tls_session: None,
			}),
		};

		let resp = grpc_client.check(authz_req).await;
		trace!("mcp ext_authz check response: {:?}", resp);

		let cr = match resp {
			Ok(response) => response,
			Err(e) => {
				warn!("mcp ext_authz request failed: {}", e);
				return match &self.0.failure_mode {
					FailureMode::Allow => {
						debug!("Allowing MCP request due to FailureMode::Allow");
						Ok(McpExtAuthzOkResponse::default())
					},
					FailureMode::Deny => Err(McpExtAuthzDenied {
						status_code: StatusCode::FORBIDDEN,
						body: "authorization service unavailable".to_string(),
						..Default::default()
					}),
					FailureMode::DenyWithStatus(code) => Err(McpExtAuthzDenied {
						status_code: StatusCode::from_u16(*code).unwrap_or(StatusCode::FORBIDDEN),
						body: "authorization service unavailable".to_string(),
						..Default::default()
					}),
				};
			},
		};
		let cr = cr.into_inner();

		let dynamic_metadata = cr.dynamic_metadata.and_then(|metadata| {
			let mut dm = ExtAuthzDynamicMetadata::default();
			for (key, value) in metadata.fields {
				match serde_json::to_value(&value) {
					Ok(json_val) => {
						dm.0.insert(key, json_val);
					},
					Err(e) => {
						tracing::warn!(key = %key, error = %e, "mcp ext_authz: failed to convert dynamic_metadata value");
					},
				}
			}
			if dm.0.is_empty() { None } else { Some(dm) }
		});

		let status = cr.status.as_ref().map(|status| status.code).unwrap_or(0);

		if status != 0 {
			debug!("mcp ext_authz denied: status={status}");
			if let Some(HttpResponse::DeniedResponse(denied)) = cr.http_response {
				let DeniedHttpResponse {
					status: http_status,
					headers: resp_headers,
					body,
				} = denied;
				let code = http_status
					.and_then(|s| StatusCode::from_u16(s.code as u16).ok())
					.unwrap_or(StatusCode::FORBIDDEN);
				let mut hm = HeaderMap::new();
				process_headers(&mut hm, resp_headers, None);
				return Err(McpExtAuthzDenied {
					response_headers: hm,
					status_code: code,
					body,
				});
			}
			return Err(McpExtAuthzDenied {
				status_code: StatusCode::FORBIDDEN,
				body: "external authorization denied".to_string(),
				..Default::default()
			});
		}

		let mut ok_resp = McpExtAuthzOkResponse {
			dynamic_metadata,
			..Default::default()
		};
		if let Some(HttpResponse::OkResponse(OkHttpResponse {
			headers,
			headers_to_remove,
			response_headers_to_add,
			..
		})) = cr.http_response
		{
			if !headers.is_empty() {
				process_headers(&mut ok_resp.request_headers_to_add, headers, None);
			}
			ok_resp.request_headers_to_remove = headers_to_remove;
			if !response_headers_to_add.is_empty() {
				process_headers(
					&mut ok_resp.response_headers_to_add,
					response_headers_to_add,
					None,
				);
			}
		}
		Ok(ok_resp)
	}
}

pub(crate) fn build_metadata_from_snapshot(
	metadata: &Option<HashMap<String, Arc<cel::Expression>>>,
	snapshot: &RequestSnapshot,
	mcp: Option<&ResourceType>,
) -> Option<Metadata> {
	match metadata {
		Some(meta) => {
			let m = meta
				.iter()
				.filter_map(|(k, v)| {
					let exec = match mcp {
						Some(mcp) => cel::Executor::new_mcp(Some(snapshot), mcp),
						None => cel::Executor::new_snapshot(snapshot),
					};
					match exec.eval(v) {
						Ok(res) => {
							let js = res.json().ok()?;
							json_to_struct(js).ok().map(|pb| (k.to_string(), pb))
						},
						Err(e) => {
							trace!("failed to evaluate mcp ext_authz metadata: {e}");
							None
						},
					}
				})
				.collect();
			Some(Metadata { filter_metadata: m })
		},
		None => {
			let mut filter_metadata = HashMap::new();
			if let Some(claims) = &snapshot.jwt
				&& let Ok(pb) = json_to_struct(serde_json::json!({"jwt_payload": claims.inner.clone()}))
			{
				filter_metadata.insert("envoy.filters.http.jwt_authn".to_string(), pb);
			}
			if let Some(mcp) = mcp
				&& let Ok(mcp_json) = serde_json::to_value(mcp)
				&& let Ok(pb) = json_to_struct(mcp_json)
			{
				filter_metadata.insert("agentgateway.filters.mcp".to_string(), pb);
			}
			if filter_metadata.is_empty() {
				None
			} else {
				Some(Metadata { filter_metadata })
			}
		},
	}
}
