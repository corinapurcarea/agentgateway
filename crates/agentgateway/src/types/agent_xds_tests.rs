use crate::http;
use crate::types::agent::*;
use crate::types::proto;
use crate::types::proto::ProtoError;

fn make_backend_ref(name: &str) -> proto::agent::BackendReference {
	proto::agent::BackendReference {
		kind: Some(proto::agent::backend_reference::Kind::Backend(
			name.to_string(),
		)),
		port: 0,
	}
}

fn make_grpc_ext_authz(
	target: proto::agent::BackendReference,
) -> proto::agent::traffic_policy_spec::ExternalAuth {
	use proto::agent::traffic_policy_spec::external_auth;
	proto::agent::traffic_policy_spec::ExternalAuth {
		target: Some(target),
		protocol: Some(external_auth::Protocol::Grpc(
			proto::agent::traffic_policy_spec::external_auth::GrpcProtocol {
				context: [("x-source".to_string(), "test".to_string())]
					.into_iter()
					.collect(),
				metadata: [("env".to_string(), "'production'".to_string())]
					.into_iter()
					.collect(),
			},
		)),
		failure_mode: external_auth::FailureMode::Deny as i32,
		status_on_error: None,
		include_request_headers: vec!["authorization".to_string(), "x-request-id".to_string()],
		include_request_body: Some(
			proto::agent::traffic_policy_spec::external_auth::BodyOptions {
				max_request_bytes: 4096,
				allow_partial_message: true,
				pack_as_bytes: false,
			},
		),
	}
}

fn make_http_ext_authz(
	target: proto::agent::BackendReference,
) -> proto::agent::traffic_policy_spec::ExternalAuth {
	use proto::agent::traffic_policy_spec::external_auth;
	proto::agent::traffic_policy_spec::ExternalAuth {
		target: Some(target),
		protocol: Some(external_auth::Protocol::Http(
			proto::agent::traffic_policy_spec::external_auth::HttpProtocol {
				path: Some("'/check'".to_string()),
				redirect: None,
				include_response_headers: vec!["x-auth-user".to_string()],
				add_request_headers: [("x-custom".to_string(), "'value'".to_string())]
					.into_iter()
					.collect(),
				metadata: [("tenant".to_string(), "'default'".to_string())]
					.into_iter()
					.collect(),
			},
		)),
		failure_mode: external_auth::FailureMode::Allow as i32,
		status_on_error: None,
		include_request_headers: vec![],
		include_request_body: None,
	}
}

#[test]
fn test_backend_policy_mcp_ext_authz_grpc() -> Result<(), ProtoError> {
	let ea = make_grpc_ext_authz(make_backend_ref("ext-authz-server"));
	let spec = proto::agent::BackendPolicySpec {
		kind: Some(proto::agent::backend_policy_spec::Kind::McpExtAuthz(ea)),
	};
	let policy = BackendPolicy::try_from(&spec)?;
	match policy {
		BackendPolicy::McpExtAuthz(mcp_ea) => {
			let inner = &mcp_ea.0;
			assert!(
				matches!(&inner.protocol, http::ext_authz::Protocol::Grpc { context, metadata }
					if context.is_some() && metadata.is_some()
				),
				"expected gRPC protocol with context and metadata"
			);
			assert!(
				matches!(&inner.failure_mode, http::ext_authz::FailureMode::Deny),
				"expected Deny failure mode"
			);
			assert_eq!(inner.include_request_headers.len(), 2);
			let body = inner
				.include_request_body
				.as_ref()
				.expect("body options should be set");
			assert_eq!(body.max_request_bytes, 4096);
			assert!(body.allow_partial_message);
			assert!(!body.pack_as_bytes);
		},
		other => panic!("Expected McpExtAuthz, got: {other:?}"),
	}
	Ok(())
}

#[test]
fn test_backend_policy_mcp_ext_authz_http() -> Result<(), ProtoError> {
	let ea = make_http_ext_authz(make_backend_ref("ext-authz-http"));
	let spec = proto::agent::BackendPolicySpec {
		kind: Some(proto::agent::backend_policy_spec::Kind::McpExtAuthz(ea)),
	};
	let policy = BackendPolicy::try_from(&spec)?;
	match policy {
		BackendPolicy::McpExtAuthz(mcp_ea) => {
			let inner = &mcp_ea.0;
			assert!(
				matches!(&inner.protocol, http::ext_authz::Protocol::Http { .. }),
				"expected HTTP protocol"
			);
			assert!(
				matches!(&inner.failure_mode, http::ext_authz::FailureMode::Allow),
				"expected Allow failure mode"
			);
			assert!(inner.include_request_body.is_none());
		},
		other => panic!("Expected McpExtAuthz, got: {other:?}"),
	}
	Ok(())
}

#[test]
fn test_traffic_policy_ext_authz_uses_convert() -> Result<(), ProtoError> {
	let ea = make_grpc_ext_authz(make_backend_ref("ext-authz-traffic"));
	let spec = proto::agent::TrafficPolicySpec {
		phase: proto::agent::traffic_policy_spec::PolicyPhase::Route as i32,
		kind: Some(proto::agent::traffic_policy_spec::Kind::ExtAuthz(ea)),
	};
	let policy = TrafficPolicy::try_from(&spec)?;
	match policy {
		TrafficPolicy::ExtAuthz(ea) => {
			assert!(
				matches!(&ea.protocol, http::ext_authz::Protocol::Grpc { .. }),
				"expected gRPC protocol"
			);
			assert!(
				matches!(&ea.failure_mode, http::ext_authz::FailureMode::Deny),
				"expected Deny failure mode"
			);
			assert_eq!(ea.include_request_headers.len(), 2);
		},
		other => panic!("Expected ExtAuthz, got: {other:?}"),
	}
	Ok(())
}

#[test]
fn test_backend_policy_mcp_ext_authz_deny_with_status() -> Result<(), ProtoError> {
	use proto::agent::traffic_policy_spec::external_auth;
	let mut ea = make_grpc_ext_authz(make_backend_ref("ext-authz-server"));
	ea.failure_mode = external_auth::FailureMode::DenyWithStatus as i32;
	ea.status_on_error = Some(503);
	let spec = proto::agent::BackendPolicySpec {
		kind: Some(proto::agent::backend_policy_spec::Kind::McpExtAuthz(ea)),
	};
	let policy = BackendPolicy::try_from(&spec)?;
	match policy {
		BackendPolicy::McpExtAuthz(mcp_ea) => {
			assert!(
				matches!(
					&mcp_ea.0.failure_mode,
					http::ext_authz::FailureMode::DenyWithStatus(503)
				),
				"expected DenyWithStatus(503)"
			);
		},
		other => panic!("Expected McpExtAuthz, got: {other:?}"),
	}
	Ok(())
}

#[test]
fn test_backend_policy_mcp_ext_authz_missing_protocol() {
	let ea = proto::agent::traffic_policy_spec::ExternalAuth {
		target: Some(make_backend_ref("ext-authz-server")),
		protocol: None,
		failure_mode: 0,
		status_on_error: None,
		include_request_headers: vec![],
		include_request_body: None,
	};
	let spec = proto::agent::BackendPolicySpec {
		kind: Some(proto::agent::backend_policy_spec::Kind::McpExtAuthz(ea)),
	};
	let result = BackendPolicy::try_from(&spec);
	assert!(result.is_err(), "missing protocol should produce an error");
}
