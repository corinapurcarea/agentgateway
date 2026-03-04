use std::net::SocketAddr;

use agent_core::strng;
use itertools::Itertools;
use rmcp::RoleClient;
use rmcp::model::InitializeRequestParams;
use rmcp::service::RunningService;
use rmcp::transport::StreamableHttpServerConfig;
use secrecy::SecretString;

use crate::http::auth::BackendAuth;
use crate::http::authorization::{PolicySet, RuleSet};
use crate::mcp::McpAuthorization;
use crate::test_helpers::proxymock::{
	BIND_KEY, TestBind, basic_named_route, basic_route, setup_proxy_test, simple_bind,
};
use crate::types::agent::BackendPolicy;
use crate::*;

#[tokio::test]
async fn stream_to_stream_single() {
	let mock = mock_streamable_http_server(true).await;
	let (_bind, io) = setup_proxy(&mock, true, false).await;
	let client = mcp_streamable_client(io).await;
	standard_assertions(client).await;
}

#[tokio::test]
async fn sse_to_stream_single() {
	let mock = mock_streamable_http_server(true).await;
	let (_bind, io) = setup_proxy(&mock, true, false).await;
	let client = mcp_sse_client(io).await;
	standard_sse_assertions(client).await;
}

#[tokio::test]
async fn stream_to_sse_single() {
	let mock = mock_sse_server().await;
	let (_bind, io) = setup_proxy(&mock, true, true).await;
	let client = mcp_streamable_client(io).await;
	standard_assertions(client).await;
}

#[tokio::test]
async fn sse_to_sse_single() {
	let mock = mock_sse_server().await;
	let (_bind, io) = setup_proxy(&mock, true, true).await;
	let client = mcp_sse_client(io).await;
	standard_sse_assertions(client).await;
}

#[tokio::test]
async fn stream_to_multiplex() {
	let mock_stream = mock_streamable_http_server(true).await;
	let mock_sse = mock_sse_server().await;
	let t = setup_proxy_test("{}")
		.unwrap()
		.with_multiplex_mcp_backend(
			"mcp",
			vec![
				("sse", mock_sse.addr, true),
				("mcp", mock_stream.addr, false),
			],
			true,
		)
		.with_bind(simple_bind(basic_named_route(strng::new("/mcp"))));
	let io = t.serve_real_listener(strng::new("bind")).await;
	let client = mcp_streamable_client(io).await;
	let tools = client.list_tools(None).await.unwrap();
	let t = tools
		.tools
		.into_iter()
		.map(|t| t.name.to_string())
		.sorted()
		.filter(|n| n.contains("decrement") || n.contains("echo"))
		.collect_vec();
	assert_eq!(
		t,
		vec![
			"mcp_decrement".to_string(),
			"mcp_echo".to_string(),
			"mcp_echo_http".to_string(),
			"sse_decrement".to_string(),
			"sse_echo".to_string(),
			"sse_echo_http".to_string()
		]
	);

	let ctr = client
		.call_tool(rmcp::model::CallToolRequestParams {
			meta: None,
			task: None,
			name: "mcp_echo".into(),
			arguments: serde_json::json!({"hi": "world"}).as_object().cloned(),
		})
		.await
		.unwrap();
	assert_eq!(
		&ctr.content[0].raw.as_text().unwrap().text,
		r#"{"hi":"world"}"#
	);

	let ctr = client
		.call_tool(rmcp::model::CallToolRequestParams {
			meta: None,
			task: None,
			name: "sse_echo".into(),
			arguments: serde_json::json!({"hi": "world"}).as_object().cloned(),
		})
		.await
		.unwrap();
	assert_eq!(
		&ctr.content[0].raw.as_text().unwrap().text,
		r#"{"hi":"world"}"#
	);

	// No target set...
	assert!(
		client
			.call_tool(rmcp::model::CallToolRequestParams {
				meta: None,
				task: None,
				name: "echo".into(),
				arguments: serde_json::json!({"hi": "world"}).as_object().cloned(),
			})
			.await
			.is_err()
	);
}

#[tokio::test]
async fn stateless_to_stateful() {
	let mock = mock_streamable_http_server(true).await;
	let (_bind, io) = setup_proxy(&mock, false, false).await;
	let client = mcp_streamable_client(io).await;
	standard_assertions(client).await;
}

#[tokio::test]
async fn stateless_to_stateless() {
	let mock = mock_streamable_http_server(false).await;
	let (_bind, io) = setup_proxy(&mock, false, false).await;
	let client = mcp_streamable_client(io).await;
	standard_assertions(client).await;
}

#[tokio::test]
async fn stream_to_stream_single_tls() {
	let mock = mock_streamable_http_server(true).await;
	let (_bind, io) = setup_proxy_policies(
		&mock,
		true,
		false,
		vec![BackendPolicy::BackendAuth(BackendAuth::Key(
			SecretString::new("my-key".into()),
		))],
	)
	.await;
	let client = mcp_streamable_client(io).await;
	let ctr = client
		.call_tool(rmcp::model::CallToolRequestParams {
			meta: None,
			task: None,
			name: "echo_http".into(),
			arguments: serde_json::json!({"hi": "world"}).as_object().cloned(),
		})
		.await
		.unwrap();
	assert_eq!(
		&ctr.content[0].raw.as_text().unwrap().text,
		r#"Bearer my-key"#
	);
}

/// Test that calling a tool denied by MCP authorization policy returns proper JSON-RPC error
/// with INVALID_PARAMS error code (-32602) and message "Unknown tool: {tool_name}"
#[tokio::test]
async fn authorization_denied_returns_unknown_tool_error() {
	let mock = mock_streamable_http_server(true).await;

	// Create an MCP authorization policy that denies all tools
	// The deny rule matches all tools; no allow rules means everything is denied
	let deny_all_policy = McpAuthorization::new(RuleSet::new(PolicySet::new(
		vec![],                                                       // no allow rules
		vec![Arc::new(cel::Expression::new_strict("true").unwrap())], // deny all
	)));

	let (_bind, io) = setup_proxy_policies(
		&mock,
		true,
		false,
		vec![BackendPolicy::McpAuthorization(deny_all_policy)],
	)
	.await;

	let client = mcp_streamable_client(io).await;

	// Attempt to call a tool - should fail with "Unknown tool" error
	let result = client
		.call_tool(rmcp::model::CallToolRequestParams {
			meta: None,
			task: None,
			name: "echo".into(),
			arguments: serde_json::json!({"hi": "world"}).as_object().cloned(),
		})
		.await;

	// The call should fail
	assert!(
		result.is_err(),
		"Expected tool call to fail due to authorization denial"
	);

	let err = result.unwrap_err();

	// Verify error code is INVALID_PARAMS (-32602) and message format
	match &err {
		rmcp::ServiceError::McpError(mcp_error) => {
			assert_eq!(
				mcp_error.code.0, -32602,
				"Expected INVALID_PARAMS error code (-32602), got: {}",
				mcp_error.code.0
			);
			assert_eq!(
				mcp_error.message.as_ref(),
				"Unknown tool: echo",
				"Expected error message 'Unknown tool: echo', got: {}",
				mcp_error.message
			);
		},
		other => panic!("Expected ServiceError::McpError, got: {:?}", other),
	}
}

/// Test that getting a prompt denied by MCP authorization policy returns proper JSON-RPC error
/// with INVALID_PARAMS error code (-32602) and message "Unknown prompt: {prompt_name}"
#[tokio::test]
async fn authorization_denied_returns_unknown_prompt_error() {
	let mock = mock_streamable_http_server(true).await;

	// Create an MCP authorization policy that denies all prompts
	let deny_all_policy = McpAuthorization::new(RuleSet::new(PolicySet::new(
		vec![],                                                       // no allow rules
		vec![Arc::new(cel::Expression::new_strict("true").unwrap())], // deny all
	)));

	let (_bind, io) = setup_proxy_policies(
		&mock,
		true,
		false,
		vec![BackendPolicy::McpAuthorization(deny_all_policy)],
	)
	.await;

	let client = mcp_streamable_client(io).await;

	// Attempt to get a prompt - should fail with "Unknown prompt" error
	let result = client
		.get_prompt(rmcp::model::GetPromptRequestParams {
			meta: None,
			name: "example_prompt".into(),
			arguments: None,
		})
		.await;

	// The call should fail
	assert!(
		result.is_err(),
		"Expected get_prompt call to fail due to authorization denial"
	);

	let err = result.unwrap_err();

	// Verify error code is INVALID_PARAMS (-32602) and message format
	match &err {
		rmcp::ServiceError::McpError(mcp_error) => {
			assert_eq!(
				mcp_error.code.0, -32602,
				"Expected INVALID_PARAMS error code (-32602), got: {}",
				mcp_error.code.0
			);
			assert_eq!(
				mcp_error.message.as_ref(),
				"Unknown prompt: example_prompt",
				"Expected error message 'Unknown prompt: example_prompt', got: {}",
				mcp_error.message
			);
		},
		other => panic!("Expected ServiceError::McpError, got: {:?}", other),
	}
}

/// Test that reading a resource denied by MCP authorization policy returns proper JSON-RPC error
/// with INVALID_PARAMS error code (-32602) and message "Unknown resource: {resource_uri}"
#[tokio::test]
async fn authorization_denied_returns_unknown_resource_error() {
	let mock = mock_streamable_http_server(true).await;

	// Create an MCP authorization policy that denies all resources
	let deny_all_policy = McpAuthorization::new(RuleSet::new(PolicySet::new(
		vec![],                                                       // no allow rules
		vec![Arc::new(cel::Expression::new_strict("true").unwrap())], // deny all
	)));

	let (_bind, io) = setup_proxy_policies(
		&mock,
		true,
		false,
		vec![BackendPolicy::McpAuthorization(deny_all_policy)],
	)
	.await;

	let client = mcp_streamable_client(io).await;

	// Attempt to read a resource - should fail with "Unknown resource" error
	let result = client
		.read_resource(rmcp::model::ReadResourceRequestParams {
			meta: None,
			uri: "memo://insights".into(),
		})
		.await;

	// The call should fail
	assert!(
		result.is_err(),
		"Expected read_resource call to fail due to authorization denial"
	);

	let err = result.unwrap_err();

	// Verify error code is INVALID_PARAMS (-32602) and message format
	match &err {
		rmcp::ServiceError::McpError(mcp_error) => {
			assert_eq!(
				mcp_error.code.0, -32602,
				"Expected INVALID_PARAMS error code (-32602), got: {}",
				mcp_error.code.0
			);
			assert_eq!(
				mcp_error.message.as_ref(),
				"Unknown resource: memo://insights",
				"Expected error message 'Unknown resource: memo://insights', got: {}",
				mcp_error.message
			);
		},
		other => panic!("Expected ServiceError::McpError, got: {:?}", other),
	}
}

#[test]
fn ext_authz_denied_error_maps_to_ext_auth_reason() {
	use crate::proxy::{ProxyError, ProxyResponse, ProxyResponseReason};
	use rmcp::model::RequestId;

	let err = ProxyError::MCP(crate::mcp::Error::ExtAuthzDenied(Box::new(
		crate::mcp::ExtAuthzDeniedInfo {
			req_id: RequestId::Number(1),
			response_headers: http::HeaderMap::new(),
			status_code: http::StatusCode::FORBIDDEN,
			body: String::new(),
		},
	)));
	let resp = ProxyResponse::Error(err);
	assert_eq!(
		resp.as_reason(),
		ProxyResponseReason::ExtAuth,
		"ExtAuthzDenied should map to ExtAuth reason"
	);
}

#[tokio::test]
async fn ext_authz_denied_error_produces_json_rpc_response() {
	use crate::proxy::ProxyError;
	use rmcp::model::RequestId;

	let mut headers = http::HeaderMap::new();
	headers.insert("x-custom", "test-value".parse().unwrap());

	let err = ProxyError::MCP(crate::mcp::Error::ExtAuthzDenied(Box::new(
		crate::mcp::ExtAuthzDeniedInfo {
			req_id: RequestId::Number(42),
			response_headers: headers,
			status_code: http::StatusCode::UNAUTHORIZED,
			body: "insufficient permissions".to_string(),
		},
	)));
	let resp = err.into_response();
	assert_eq!(
		resp.status(),
		http::StatusCode::UNAUTHORIZED,
		"should propagate status_code from ext_authz DeniedResponse"
	);
	assert_eq!(
		resp.headers().get("x-custom").unwrap().to_str().unwrap(),
		"test-value"
	);
	assert_eq!(
		resp
			.headers()
			.get("content-type")
			.unwrap()
			.to_str()
			.unwrap(),
		"application/json"
	);

	let body_bytes = crate::http::body_to_bytes(resp.into_body()).await.unwrap();
	let json: serde_json::Value = serde_json::from_slice(&body_bytes).expect("body should be valid JSON");
	assert_eq!(json["jsonrpc"], "2.0");
	assert_eq!(json["id"], 42);
	assert_eq!(json["error"]["code"], rmcp::model::ErrorCode::INTERNAL_ERROR.code());
	assert_eq!(json["error"]["message"], "insufficient permissions");
}

#[test]
fn mcp_ext_authz_denied_error_default() {
	use crate::mcp::ext_authz::McpExtAuthzDenied;

	let denied = McpExtAuthzDenied::default();
	assert!(denied.response_headers.is_empty());
	assert_eq!(denied.status_code, http::StatusCode::FORBIDDEN);
	assert!(denied.body.is_empty());
}

#[test]
fn cel_exec_wrapper_stores_extauthz_dynamic_metadata() {
	use crate::http::ext_authz::ExtAuthzDynamicMetadata;
	use crate::mcp::rbac::CelExecWrapper;

	let mut cel = CelExecWrapper::new(Arc::new(None));

	let dm: ExtAuthzDynamicMetadata =
		serde_json::from_value(serde_json::json!({"role": "admin"})).unwrap();
	cel.set_extauthz(dm);

	let serialized = serde_json::to_value(cel.extauthz.as_ref().unwrap()).unwrap();
	assert_eq!(serialized, serde_json::json!({"role": "admin"}));
}

#[test]
fn mcp_authorization_validates_using_extauthz_metadata() {
	use crate::http::authorization::{PolicySet, RuleSet, RuleSets};
	use crate::http::ext_authz::ExtAuthzDynamicMetadata;
	use crate::mcp::rbac::{CelExecWrapper, McpAuthorizationSet, ResourceId, ResourceType};

	// Allow rule: extauthz.tier == "premium"
	let allow_expr = Arc::new(cel::Expression::new_permissive(
		r#"extauthz.tier == "premium""#,
	));
	let policy_set = PolicySet::new(vec![allow_expr], vec![]);
	let rule_set = RuleSet::new(policy_set);
	let authz = McpAuthorizationSet::new(RuleSets::from(vec![rule_set]));

	let resource = ResourceType::Tool(ResourceId::new("server".to_string(), "my_tool".to_string()));

	// Without extauthz metadata -> should deny (allow rule can't match)
	let cel_no_meta = CelExecWrapper::new(Arc::new(None));
	assert!(
		!authz.validate(&resource, &cel_no_meta),
		"should deny when extauthz metadata is absent"
	);

	// With extauthz metadata that doesn't match -> should deny
	let mut cel_wrong_meta = CelExecWrapper::new(Arc::new(None));
	let wrong_dm: ExtAuthzDynamicMetadata =
		serde_json::from_value(serde_json::json!({"tier": "basic"})).unwrap();
	cel_wrong_meta.set_extauthz(wrong_dm);
	assert!(
		!authz.validate(&resource, &cel_wrong_meta),
		"should deny when extauthz.tier != 'premium'"
	);

	// With extauthz metadata that matches -> should allow
	let mut cel_match = CelExecWrapper::new(Arc::new(None));
	let matching_dm: ExtAuthzDynamicMetadata =
		serde_json::from_value(serde_json::json!({"tier": "premium"})).unwrap();
	cel_match.set_extauthz(matching_dm);
	assert!(
		authz.validate(&resource, &cel_match),
		"should allow when extauthz.tier == 'premium'"
	);
}

#[test]
fn extauthz_dynamic_metadata_merges_route_and_mcp_levels() {
	use crate::cel::RequestSnapshot;
	use crate::http::authorization::{PolicySet, RuleSet, RuleSets};
	use crate::http::ext_authz::ExtAuthzDynamicMetadata;
	use crate::mcp::rbac::{CelExecWrapper, McpAuthorizationSet, ResourceId, ResourceType};

	// Simulate route-level ext_authz returning {"tenant": "acme", "tier": "basic"}
	let route_dm: ExtAuthzDynamicMetadata =
		serde_json::from_value(serde_json::json!({"tenant": "acme", "tier": "basic"})).unwrap();

	let snapshot = RequestSnapshot {
		method: http::Method::POST,
		path: http::Uri::from_static("/mcp"),
		host: None,
		scheme: None,
		version: ::http::Version::HTTP_11,
		headers: http::HeaderMap::new(),
		body: None,
		jwt: None,
		api_key: None,
		basic_auth: None,
		backend: None,
		source: None,
		start_time: None,
		extauthz: Some(route_dm),
		extproc: None,
		llm: None,
	};

	let mut cel = CelExecWrapper::new(Arc::new(Some(snapshot)));

	// Simulate MCP-level ext_authz returning {"tier": "premium", "role": "admin"}
	// "tier" should override route-level; "tenant" from route-level should be preserved
	let mcp_dm: ExtAuthzDynamicMetadata =
		serde_json::from_value(serde_json::json!({"tier": "premium", "role": "admin"})).unwrap();
	cel.set_extauthz(mcp_dm);

	let merged = serde_json::to_value(cel.extauthz.as_ref().unwrap()).unwrap();
	assert_eq!(
		merged,
		serde_json::json!({"tenant": "acme", "tier": "premium", "role": "admin"}),
		"should merge route-level and MCP-level metadata with MCP taking precedence"
	);

	// Verify CEL expressions can access both route-level and MCP-level keys
	let resource = ResourceType::Tool(ResourceId::new("server".to_string(), "my_tool".to_string()));

	// Allow rule that requires both route-level "tenant" and MCP-level "role"
	let allow_expr = Arc::new(cel::Expression::new_permissive(
		r#"extauthz.tenant == "acme" && extauthz.role == "admin""#,
	));
	let policy_set = PolicySet::new(vec![allow_expr], vec![]);
	let rule_set = RuleSet::new(policy_set);
	let authz = McpAuthorizationSet::new(RuleSets::from(vec![rule_set]));

	assert!(
		authz.validate(&resource, &cel),
		"should allow when merged metadata satisfies rule referencing keys from both levels"
	);
}

#[test]
fn set_extauthz_without_snapshot_extauthz_stores_mcp_only() {
	use crate::cel::RequestSnapshot;
	use crate::http::ext_authz::ExtAuthzDynamicMetadata;
	use crate::mcp::rbac::CelExecWrapper;

	let snapshot = RequestSnapshot {
		method: http::Method::POST,
		path: http::Uri::from_static("/mcp"),
		host: None,
		scheme: None,
		version: ::http::Version::HTTP_11,
		headers: http::HeaderMap::new(),
		body: None,
		jwt: None,
		api_key: None,
		basic_auth: None,
		backend: None,
		source: None,
		start_time: None,
		extauthz: None,
		extproc: None,
		llm: None,
	};

	let mut cel = CelExecWrapper::new(Arc::new(Some(snapshot)));

	let mcp_dm: ExtAuthzDynamicMetadata =
		serde_json::from_value(serde_json::json!({"role": "admin"})).unwrap();
	cel.set_extauthz(mcp_dm);

	let serialized = serde_json::to_value(cel.extauthz.as_ref().unwrap()).unwrap();
	assert_eq!(
		serialized,
		serde_json::json!({"role": "admin"}),
		"should store MCP-only metadata when snapshot has no extauthz"
	);
}

#[test]
fn route_level_extauthz_preserved_when_no_mcp_extauthz() {
	use crate::cel::RequestSnapshot;
	use crate::http::authorization::{PolicySet, RuleSet, RuleSets};
	use crate::http::ext_authz::ExtAuthzDynamicMetadata;
	use crate::mcp::rbac::{CelExecWrapper, McpAuthorizationSet, ResourceId, ResourceType};

	let route_dm: ExtAuthzDynamicMetadata =
		serde_json::from_value(serde_json::json!({"tenant": "acme"})).unwrap();

	let snapshot = RequestSnapshot {
		method: http::Method::POST,
		path: http::Uri::from_static("/mcp"),
		host: None,
		scheme: None,
		version: ::http::Version::HTTP_11,
		headers: http::HeaderMap::new(),
		body: None,
		jwt: None,
		api_key: None,
		basic_auth: None,
		backend: None,
		source: None,
		start_time: None,
		extauthz: Some(route_dm),
		extproc: None,
		llm: None,
	};

	// Do NOT call set_extauthz -- simulates no MCP ext_authz configured
	let cel = CelExecWrapper::new(Arc::new(Some(snapshot)));

	let resource = ResourceType::Tool(ResourceId::new("server".to_string(), "my_tool".to_string()));

	// Allow rule referencing route-level metadata
	let allow_expr = Arc::new(cel::Expression::new_permissive(
		r#"extauthz.tenant == "acme""#,
	));
	let policy_set = PolicySet::new(vec![allow_expr], vec![]);
	let rule_set = RuleSet::new(policy_set);
	let authz = McpAuthorizationSet::new(RuleSets::from(vec![rule_set]));

	assert!(
		authz.validate(&resource, &cel),
		"route-level extauthz should be accessible when no MCP extauthz is set"
	);
}

#[test]
fn resource_type_serialization_all_variants() {
	use crate::mcp::rbac::{ResourceId, ResourceType};

	let tool = ResourceType::Tool(ResourceId::new("srv".to_string(), "my_tool".to_string()));
	let tool_json = serde_json::to_value(&tool).unwrap();
	assert_eq!(
		tool_json,
		serde_json::json!({"tool": {"target": "srv", "name": "my_tool"}})
	);

	let prompt = ResourceType::Prompt(ResourceId::new("srv".to_string(), "summarize".to_string()));
	let prompt_json = serde_json::to_value(&prompt).unwrap();
	assert_eq!(
		prompt_json,
		serde_json::json!({"prompt": {"target": "srv", "name": "summarize"}})
	);

	let resource = ResourceType::Resource(ResourceId::new(
		"default".to_string(),
		"memo://insights".to_string(),
	));
	let resource_json = serde_json::to_value(&resource).unwrap();
	assert_eq!(
		resource_json,
		serde_json::json!({"resource": {"target": "default", "name": "memo://insights"}})
	);
}

#[test]
fn mcp_ok_response_carries_dynamic_metadata() {
	use crate::http::ext_authz::ExtAuthzDynamicMetadata;
	use crate::mcp::ext_authz::McpExtAuthzOkResponse;

	let dm: ExtAuthzDynamicMetadata = serde_json::from_value(serde_json::json!({
		"request_id": "abc-123",
		"tags": ["audit", "trace"]
	}))
	.unwrap();

	let ok_resp = McpExtAuthzOkResponse {
		dynamic_metadata: Some(dm),
		..Default::default()
	};

	let meta_json = serde_json::to_value(ok_resp.dynamic_metadata.as_ref().unwrap()).unwrap();
	assert_eq!(meta_json["request_id"], serde_json::json!("abc-123"));
	assert_eq!(meta_json["tags"], serde_json::json!(["audit", "trace"]));
	assert!(ok_resp.request_headers_to_add.is_empty());
	assert!(ok_resp.request_headers_to_remove.is_empty());
	assert!(ok_resp.response_headers_to_add.is_empty());
}

/// Test that a deny policy targeting a specific tool filters only that tool from list_tools,
/// while leaving all other tools accessible.
#[tokio::test]
async fn authorization_deny_specific_tool_filters_only_that_tool() {
	let mock = mock_streamable_http_server(true).await;

	// Create a deny policy that only denies the "echo" tool
	let deny_echo_policy = McpAuthorization::new(RuleSet::new(PolicySet::new(
		vec![],
		vec![Arc::new(
			cel::Expression::new_strict(r#"mcp.tool.name == "echo""#).unwrap(),
		)],
	)));

	let (_bind, io) = setup_proxy_policies(
		&mock,
		true,
		false,
		vec![BackendPolicy::McpAuthorization(deny_echo_policy)],
	)
	.await;

	let client = mcp_streamable_client(io).await;

	// List tools - "echo" should be filtered out, all others should remain
	let tools = client.list_tools(None).await.unwrap();
	let tool_names: Vec<String> = tools
		.tools
		.into_iter()
		.map(|t| t.name.to_string())
		.sorted()
		.collect();

	// The mock server has: increment, decrement, get_value, say_hello, echo, sum, echo_http
	// After denying "echo", we should have all except "echo"
	assert!(
		!tool_names.contains(&"echo".to_string()),
		"echo should be denied but was found in tools: {:?}",
		tool_names
	);
	assert!(
		tool_names.contains(&"increment".to_string()),
		"increment should be allowed but was not found in tools: {:?}",
		tool_names
	);
	assert!(
		tool_names.contains(&"decrement".to_string()),
		"decrement should be allowed but was not found in tools: {:?}",
		tool_names
	);
	assert!(
		tool_names.len() >= 5,
		"Expected at least 5 tools after denying 1, got {}: {:?}",
		tool_names.len(),
		tool_names
	);
}

/// Test that a deny policy using request.headers correctly filters tools per-agent.
/// This exercises the router.rs fix that registers authorization policies on the log's
/// CEL context so the request snapshot includes headers needed by CEL expressions.
#[tokio::test]
async fn authorization_deny_with_request_header_filters_per_agent() {
	use std::collections::HashMap;

	use ::http::{HeaderName, HeaderValue};
	use rmcp::ServiceExt;
	use rmcp::model::{ClientCapabilities, ClientInfo, Implementation};
	use rmcp::transport::StreamableHttpClientTransport;
	use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;

	let mock = mock_streamable_http_server(true).await;

	// Deny "echo" only when request header x-agent-name == "agent-one"
	let deny_policy = McpAuthorization::new(RuleSet::new(PolicySet::new(
		vec![],
		vec![Arc::new(
			cel::Expression::new_strict(
				r#"mcp.tool.name == "echo" && request.headers["x-agent-name"] == "agent-one""#,
			)
			.unwrap(),
		)],
	)));

	let (_bind, io) = setup_proxy_policies(
		&mock,
		true,
		false,
		vec![BackendPolicy::McpAuthorization(deny_policy)],
	)
	.await;

	// Helper to create a client with custom headers
	let make_client = |addr: SocketAddr, agent_name: &'static str| async move {
		let mut headers = HashMap::new();
		headers.insert(
			HeaderName::from_static("x-agent-name"),
			HeaderValue::from_static(agent_name),
		);
		let config = StreamableHttpClientTransportConfig::with_uri(format!("http://{addr}/mcp"))
			.custom_headers(headers);
		let transport = StreamableHttpClientTransport::from_config(config);
		let client_info = ClientInfo {
			meta: None,
			protocol_version: Default::default(),
			capabilities: ClientCapabilities::default(),
			client_info: Implementation {
				name: format!("test-{agent_name}"),
				version: "0.0.1".to_string(),
				title: None,
				website_url: None,
				icons: None,
				description: None,
			},
		};
		client_info
			.serve(transport)
			.await
			.expect("client should connect")
	};

	// Agent-one: "echo" should be denied
	let client1 = make_client(io, "agent-one").await;
	let tools1: Vec<String> = client1
		.list_tools(None)
		.await
		.unwrap()
		.tools
		.into_iter()
		.map(|t| t.name.to_string())
		.sorted()
		.collect();

	assert!(
		!tools1.contains(&"echo".to_string()),
		"agent-one should NOT see 'echo' but tools were: {:?}",
		tools1
	);
	assert!(
		tools1.contains(&"increment".to_string()),
		"agent-one should still see 'increment' but tools were: {:?}",
		tools1
	);

	// Agent-two: "echo" should be allowed (header doesn't match deny rule)
	let client2 = make_client(io, "agent-two").await;
	let tools2: Vec<String> = client2
		.list_tools(None)
		.await
		.unwrap()
		.tools
		.into_iter()
		.map(|t| t.name.to_string())
		.sorted()
		.collect();

	assert!(
		tools2.contains(&"echo".to_string()),
		"agent-two SHOULD see 'echo' but tools were: {:?}",
		tools2
	);
	assert!(
		tools2.contains(&"increment".to_string()),
		"agent-two should still see 'increment' but tools were: {:?}",
		tools2
	);
}
async fn standard_assertions(client: RunningService<RoleClient, InitializeRequestParams>) {
	let tools = client.list_tools(None).await.unwrap();
	let t = tools
		.tools
		.into_iter()
		.map(|t| t.name.to_string())
		.sorted()
		.take(2)
		.collect_vec();
	assert_eq!(t, vec!["decrement".to_string(), "echo".to_string()]);
	let ctr = client
		.call_tool(rmcp::model::CallToolRequestParams {
			meta: None,
			task: None,
			name: "echo".into(),
			arguments: serde_json::json!({"hi": "world"}).as_object().cloned(),
		})
		.await
		.unwrap();
	assert_eq!(
		&ctr.content[0].raw.as_text().unwrap().text,
		r#"{"hi":"world"}"#
	);
}

async fn standard_sse_assertions(client: LegacyService) {
	let tools = client.list_tools(None).await.unwrap();
	let t = tools
		.tools
		.into_iter()
		.map(|t| t.name.to_string())
		.sorted()
		.take(2)
		.collect_vec();
	assert_eq!(t, vec!["decrement".to_string(), "echo".to_string()]);
	let ctr = client
		.call_tool(legacy_rmcp::model::CallToolRequestParam {
			name: "echo".into(),
			arguments: serde_json::json!({"hi": "world"}).as_object().cloned(),
		})
		.await
		.unwrap();
	assert_eq!(
		&ctr.content[0].raw.as_text().unwrap().text,
		r#"{"hi":"world"}"#
	);
}

async fn setup_proxy(
	mock: &MockServer,
	stateful: bool,
	legacy_sse: bool,
) -> (TestBind, SocketAddr) {
	setup_proxy_policies(mock, stateful, legacy_sse, vec![]).await
}

async fn setup_proxy_policies(
	mock: &MockServer,
	stateful: bool,
	legacy_sse: bool,
	policies: Vec<BackendPolicy>,
) -> (TestBind, SocketAddr) {
	let t = setup_proxy_test("{}")
		.unwrap()
		.with_mcp_backend_policies(mock.addr, stateful, legacy_sse, policies)
		.with_bind(simple_bind(basic_route(mock.addr)));
	let io = t.serve_real_listener(BIND_KEY).await;
	(t, io)
}

pub async fn mcp_streamable_client(
	s: SocketAddr,
) -> RunningService<RoleClient, InitializeRequestParams> {
	use rmcp::ServiceExt;
	use rmcp::model::{ClientCapabilities, ClientInfo, Implementation};
	use rmcp::transport::StreamableHttpClientTransport;
	let transport =
		StreamableHttpClientTransport::<reqwest::Client>::from_uri(format!("http://{s}/mcp"));
	let client_info = ClientInfo {
		meta: None,
		protocol_version: Default::default(),
		capabilities: ClientCapabilities::default(),
		client_info: Implementation {
			name: "test client".to_string(),
			version: "0.0.1".to_string(),
			title: None,
			website_url: None,
			icons: None,
			description: None,
		},
	};

	client_info
		.serve(transport)
		.await
		.inspect_err(|e| {
			tracing::error!("client error: {:?}", e);
		})
		.unwrap()
}

type LegacyService = legacy_rmcp::service::RunningService<
	legacy_rmcp::RoleClient,
	legacy_rmcp::model::InitializeRequestParam,
>;

pub async fn mcp_sse_client(s: SocketAddr) -> LegacyService {
	use legacy_rmcp::ServiceExt;
	use legacy_rmcp::model::{ClientCapabilities, ClientInfo, Implementation};
	use legacy_rmcp::transport::SseClientTransport;
	let transport = SseClientTransport::<legacyreqwest::Client>::start(format!("http://{s}/sse"))
		.await
		.unwrap();
	let client_info = ClientInfo {
		protocol_version: Default::default(),
		capabilities: ClientCapabilities::default(),
		client_info: Implementation {
			name: "test client".to_string(),
			version: "0.0.1".to_string(),
			title: None,
			website_url: None,
			icons: None,
		},
	};

	client_info.serve(transport).await.unwrap()
}

struct MockServer {
	addr: SocketAddr,
	_cancel: tokio::sync::oneshot::Sender<()>,
}

async fn mock_streamable_http_server(stateful: bool) -> MockServer {
	use mockserver::Counter;
	use rmcp::transport::streamable_http_server::StreamableHttpService;
	use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
	agent_core::telemetry::testing::setup_test_logging();

	let service = StreamableHttpService::new(
		|| Ok(Counter::new()),
		LocalSessionManager::default().into(),
		StreamableHttpServerConfig {
			sse_retry: None,
			sse_keep_alive: None,
			stateful_mode: stateful,
			cancellation_token: Default::default(),
		},
	);

	let (tx, rx) = tokio::sync::oneshot::channel();
	let router = axum::Router::new().nest_service("/mcp", service);
	let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = tcp_listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(tcp_listener, router)
			.with_graceful_shutdown(async { rx.await.unwrap() })
			.await;
		info!("server stopped");
	});
	MockServer { addr, _cancel: tx }
}

async fn mock_sse_server() -> MockServer {
	use legacy_rmcp::transport::sse_server::{SseServer, SseServerConfig};
	use tokio_util::sync::CancellationToken;

	agent_core::telemetry::testing::setup_test_logging();
	let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = tcp_listener.local_addr().unwrap();
	let ct = CancellationToken::new();
	let (sse_server, service) = SseServer::new(SseServerConfig {
		bind: addr,
		sse_path: "/sse".to_string(),
		post_path: "/message".to_string(),
		ct: ct.child_token(),
		sse_keep_alive: None,
	});

	let (tx, rx) = tokio::sync::oneshot::channel();
	let ct2 = sse_server.with_service_directly(legacymockserver::Counter::new);
	tokio::spawn(async move {
		let _ = axum::serve(tcp_listener, service)
			.with_graceful_shutdown(async move {
				rx.await.unwrap();
				ct.cancel();
				ct2.cancel();
				tracing::info!("sse server cancelled");
			})
			.await;
	});
	MockServer { addr, _cancel: tx }
}
mod mockserver {
	use std::sync::Arc;

	use http::request::Parts;
	use rmcp::handler::server::router::prompt::PromptRouter;
	use rmcp::handler::server::router::tool::ToolRouter;
	use rmcp::handler::server::wrapper::Parameters;
	use rmcp::model::*;
	use rmcp::service::RequestContext;
	use rmcp::{
		ErrorData as McpError, RoleServer, ServerHandler, prompt, prompt_handler, prompt_router,
		schemars, tool, tool_handler, tool_router,
	};
	use serde_json::json;
	use tokio::sync::Mutex;

	#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
	pub struct ExamplePromptArgs {
		/// A message to put in the prompt
		pub message: String,
	}

	#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
	pub struct CounterAnalysisArgs {
		/// The target value you're trying to reach
		pub goal: i32,
		/// Preferred strategy: 'fast' or 'careful'
		#[serde(skip_serializing_if = "Option::is_none")]
		pub strategy: Option<String>,
	}

	#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
	pub struct StructRequest {
		pub a: i32,
		pub b: i32,
	}

	#[derive(Clone)]
	pub struct Counter {
		counter: Arc<Mutex<i32>>,
		tool_router: ToolRouter<Counter>,
		prompt_router: PromptRouter<Counter>,
	}

	#[tool_router]
	impl Counter {
		#[allow(dead_code)]
		pub fn new() -> Self {
			Self {
				counter: Arc::new(Mutex::new(0)),
				tool_router: Self::tool_router(),
				prompt_router: Self::prompt_router(),
			}
		}

		fn _create_resource_text(&self, uri: &str, name: &str) -> Resource {
			RawResource::new(uri, name.to_string()).no_annotation()
		}

		#[tool(description = "Increment the counter by 1")]
		async fn increment(&self) -> Result<CallToolResult, McpError> {
			let mut counter = self.counter.lock().await;
			*counter += 1;
			Ok(CallToolResult::success(vec![Content::text(
				counter.to_string(),
			)]))
		}

		#[tool(description = "Decrement the counter by 1")]
		async fn decrement(&self) -> Result<CallToolResult, McpError> {
			let mut counter = self.counter.lock().await;
			*counter -= 1;
			Ok(CallToolResult::success(vec![Content::text(
				counter.to_string(),
			)]))
		}

		#[tool(description = "Get the current counter value")]
		async fn get_value(&self) -> Result<CallToolResult, McpError> {
			let counter = self.counter.lock().await;
			Ok(CallToolResult::success(vec![Content::text(
				counter.to_string(),
			)]))
		}

		#[tool(description = "Say hello to the client")]
		fn say_hello(&self) -> Result<CallToolResult, McpError> {
			Ok(CallToolResult::success(vec![Content::text("hello")]))
		}

		#[tool(description = "Repeat what you say")]
		fn echo(&self, Parameters(object): Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
			Ok(CallToolResult::success(vec![Content::text(
				serde_json::Value::Object(object).to_string(),
			)]))
		}

		#[tool(description = "Calculate the sum of two numbers")]
		fn sum(
			&self,
			Parameters(StructRequest { a, b }): Parameters<StructRequest>,
		) -> Result<CallToolResult, McpError> {
			Ok(CallToolResult::success(vec![Content::text(
				(a + b).to_string(),
			)]))
		}

		#[tool(description = "Echo HTTP attributes")]
		fn echo_http(&self, rq: RequestContext<RoleServer>) -> Result<CallToolResult, McpError> {
			let ext = rq.extensions.get::<Parts>();
			Ok(CallToolResult::success(vec![Content::text(
				ext
					.unwrap()
					.headers
					.get("authorization")
					.map(|s| String::from_utf8_lossy(s.as_bytes()))
					.unwrap_or_default(),
			)]))
		}
	}

	#[prompt_router]
	impl Counter {
		/// This is an example prompt that takes one required argument, message
		#[prompt(name = "example_prompt")]
		async fn example_prompt(
			&self,
			Parameters(args): Parameters<ExamplePromptArgs>,
			_ctx: RequestContext<RoleServer>,
		) -> Result<Vec<PromptMessage>, McpError> {
			let prompt = format!(
				"This is an example prompt with your message here: '{}'",
				args.message
			);
			Ok(vec![PromptMessage {
				role: PromptMessageRole::User,
				content: PromptMessageContent::text(prompt),
			}])
		}

		/// Analyze the current counter value and suggest next steps
		#[prompt(name = "counter_analysis")]
		async fn counter_analysis(
			&self,
			Parameters(args): Parameters<CounterAnalysisArgs>,
			_ctx: RequestContext<RoleServer>,
		) -> Result<GetPromptResult, McpError> {
			let strategy = args.strategy.unwrap_or_else(|| "careful".to_string());
			let current_value = *self.counter.lock().await;
			let difference = args.goal - current_value;

			let messages = vec![
				PromptMessage::new_text(
					PromptMessageRole::Assistant,
					"I'll analyze the counter situation and suggest the best approach.",
				),
				PromptMessage::new_text(
					PromptMessageRole::User,
					format!(
						"Current counter value: {}\nGoal value: {}\nDifference: {}\nStrategy preference: {}\n\nPlease analyze the situation and suggest the best approach to reach the goal.",
						current_value, args.goal, difference, strategy
					),
				),
			];

			Ok(GetPromptResult {
				description: Some(format!(
					"Counter analysis for reaching {} from {}",
					args.goal, current_value
				)),
				messages,
			})
		}
	}

	#[tool_handler]
	#[prompt_handler]
	impl ServerHandler for Counter {
		fn get_info(&self) -> ServerInfo {
			ServerInfo {
				protocol_version: ProtocolVersion::V_2025_06_18,
				capabilities: ServerCapabilities::builder()
					.enable_prompts()
					.enable_resources()
					.enable_tools()
					.build(),
				server_info: Implementation::from_build_env(),
				instructions: Some("This server provides counter tools and prompts.".to_string()),
			}
		}

		async fn list_resources(
			&self,
			_request: Option<PaginatedRequestParams>,
			_: RequestContext<RoleServer>,
		) -> Result<ListResourcesResult, McpError> {
			Ok(ListResourcesResult {
				resources: vec![
					self._create_resource_text("str:////Users/to/some/path/", "cwd"),
					self._create_resource_text("memo://insights", "memo-name"),
				],
				next_cursor: None,
				meta: None,
			})
		}

		async fn read_resource(
			&self,
			ReadResourceRequestParams { uri, .. }: ReadResourceRequestParams,
			_: RequestContext<RoleServer>,
		) -> Result<ReadResourceResult, McpError> {
			match uri.as_str() {
				"str:////Users/to/some/path/" => {
					let cwd = "/Users/to/some/path/";
					Ok(ReadResourceResult {
						contents: vec![ResourceContents::text(cwd, uri)],
					})
				},
				"memo://insights" => {
					let memo = "Business Intelligence Memo\n\nAnalysis has revealed 5 key insights ...";
					Ok(ReadResourceResult {
						contents: vec![ResourceContents::text(memo, uri)],
					})
				},
				_ => Err(McpError::resource_not_found(
					"resource_not_found",
					Some(json!({
							"uri": uri
					})),
				)),
			}
		}

		async fn list_resource_templates(
			&self,
			_request: Option<PaginatedRequestParams>,
			_: RequestContext<RoleServer>,
		) -> Result<ListResourceTemplatesResult, McpError> {
			Ok(ListResourceTemplatesResult {
				next_cursor: None,
				resource_templates: Vec::new(),
				meta: None,
			})
		}

		async fn initialize(
			&self,
			_request: InitializeRequestParams,
			_: RequestContext<RoleServer>,
		) -> Result<InitializeResult, McpError> {
			Ok(self.get_info())
		}
	}
}

mod legacymockserver {
	use std::sync::Arc;

	use http::request::Parts;
	use legacy_rmcp as rmcp;
	use rmcp::handler::server::router::prompt::PromptRouter;
	use rmcp::handler::server::router::tool::ToolRouter;
	use rmcp::handler::server::wrapper::Parameters;
	use rmcp::model::*;
	use rmcp::service::RequestContext;
	use rmcp::{
		ErrorData as McpError, RoleServer, ServerHandler, prompt, prompt_handler, prompt_router,
		schemars, tool, tool_handler, tool_router,
	};
	use serde_json::json;
	use tokio::sync::Mutex;

	#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
	pub struct ExamplePromptArgs {
		/// A message to put in the prompt
		pub message: String,
	}

	#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
	pub struct CounterAnalysisArgs {
		/// The target value you're trying to reach
		pub goal: i32,
		/// Preferred strategy: 'fast' or 'careful'
		#[serde(skip_serializing_if = "Option::is_none")]
		pub strategy: Option<String>,
	}

	#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
	pub struct StructRequest {
		pub a: i32,
		pub b: i32,
	}

	#[derive(Clone)]
	pub struct Counter {
		counter: Arc<Mutex<i32>>,
		tool_router: ToolRouter<Counter>,
		prompt_router: PromptRouter<Counter>,
	}

	#[tool_router]
	impl Counter {
		#[allow(dead_code)]
		pub fn new() -> Self {
			Self {
				counter: Arc::new(Mutex::new(0)),
				tool_router: Self::tool_router(),
				prompt_router: Self::prompt_router(),
			}
		}

		fn _create_resource_text(&self, uri: &str, name: &str) -> Resource {
			RawResource::new(uri, name.to_string()).no_annotation()
		}

		#[tool(description = "Increment the counter by 1")]
		async fn increment(&self) -> Result<CallToolResult, McpError> {
			let mut counter = self.counter.lock().await;
			*counter += 1;
			Ok(CallToolResult::success(vec![Content::text(
				counter.to_string(),
			)]))
		}

		#[tool(description = "Decrement the counter by 1")]
		async fn decrement(&self) -> Result<CallToolResult, McpError> {
			let mut counter = self.counter.lock().await;
			*counter -= 1;
			Ok(CallToolResult::success(vec![Content::text(
				counter.to_string(),
			)]))
		}

		#[tool(description = "Get the current counter value")]
		async fn get_value(&self) -> Result<CallToolResult, McpError> {
			let counter = self.counter.lock().await;
			Ok(CallToolResult::success(vec![Content::text(
				counter.to_string(),
			)]))
		}

		#[tool(description = "Say hello to the client")]
		fn say_hello(&self) -> Result<CallToolResult, McpError> {
			Ok(CallToolResult::success(vec![Content::text("hello")]))
		}

		#[tool(description = "Repeat what you say")]
		fn echo(&self, Parameters(object): Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
			Ok(CallToolResult::success(vec![Content::text(
				serde_json::Value::Object(object).to_string(),
			)]))
		}

		#[tool(description = "Calculate the sum of two numbers")]
		fn sum(
			&self,
			Parameters(StructRequest { a, b }): Parameters<StructRequest>,
		) -> Result<CallToolResult, McpError> {
			Ok(CallToolResult::success(vec![Content::text(
				(a + b).to_string(),
			)]))
		}

		#[tool(description = "Echo HTTP attributes")]
		fn echo_http(&self, rq: RequestContext<RoleServer>) -> Result<CallToolResult, McpError> {
			let ext = rq.extensions.get::<Parts>();
			Ok(CallToolResult::success(vec![Content::text(
				ext
					.unwrap()
					.headers
					.get("authorization")
					.map(|s| String::from_utf8_lossy(s.as_bytes()))
					.unwrap_or_default(),
			)]))
		}
	}

	#[prompt_router]
	impl Counter {
		/// This is an example prompt that takes one required argument, message
		#[prompt(name = "example_prompt")]
		async fn example_prompt(
			&self,
			Parameters(args): Parameters<ExamplePromptArgs>,
			_ctx: RequestContext<RoleServer>,
		) -> Result<Vec<PromptMessage>, McpError> {
			let prompt = format!(
				"This is an example prompt with your message here: '{}'",
				args.message
			);
			Ok(vec![PromptMessage {
				role: PromptMessageRole::User,
				content: PromptMessageContent::text(prompt),
			}])
		}

		/// Analyze the current counter value and suggest next steps
		#[prompt(name = "counter_analysis")]
		async fn counter_analysis(
			&self,
			Parameters(args): Parameters<CounterAnalysisArgs>,
			_ctx: RequestContext<RoleServer>,
		) -> Result<GetPromptResult, McpError> {
			let strategy = args.strategy.unwrap_or_else(|| "careful".to_string());
			let current_value = *self.counter.lock().await;
			let difference = args.goal - current_value;

			let messages = vec![
				PromptMessage::new_text(
					PromptMessageRole::Assistant,
					"I'll analyze the counter situation and suggest the best approach.",
				),
				PromptMessage::new_text(
					PromptMessageRole::User,
					format!(
						"Current counter value: {}\nGoal value: {}\nDifference: {}\nStrategy preference: {}\n\nPlease analyze the situation and suggest the best approach to reach the goal.",
						current_value, args.goal, difference, strategy
					),
				),
			];

			Ok(GetPromptResult {
				description: Some(format!(
					"Counter analysis for reaching {} from {}",
					args.goal, current_value
				)),
				messages,
			})
		}
	}

	#[tool_handler]
	#[prompt_handler]
	impl ServerHandler for Counter {
		fn get_info(&self) -> ServerInfo {
			ServerInfo {
				protocol_version: ProtocolVersion::V_2025_06_18,
				capabilities: ServerCapabilities::builder()
					.enable_prompts()
					.enable_resources()
					.enable_tools()
					.build(),
				server_info: Implementation::from_build_env(),
				instructions: Some("This server provides counter tools and prompts.".to_string()),
			}
		}

		async fn list_resources(
			&self,
			_request: Option<PaginatedRequestParam>,
			_: RequestContext<RoleServer>,
		) -> Result<ListResourcesResult, McpError> {
			Ok(ListResourcesResult {
				resources: vec![
					self._create_resource_text("str:////Users/to/some/path/", "cwd"),
					self._create_resource_text("memo://insights", "memo-name"),
				],
				next_cursor: None,
			})
		}

		async fn read_resource(
			&self,
			ReadResourceRequestParam { uri }: ReadResourceRequestParam,
			_: RequestContext<RoleServer>,
		) -> Result<ReadResourceResult, McpError> {
			match uri.as_str() {
				"str:////Users/to/some/path/" => {
					let cwd = "/Users/to/some/path/";
					Ok(ReadResourceResult {
						contents: vec![ResourceContents::text(cwd, uri)],
					})
				},
				"memo://insights" => {
					let memo = "Business Intelligence Memo\n\nAnalysis has revealed 5 key insights ...";
					Ok(ReadResourceResult {
						contents: vec![ResourceContents::text(memo, uri)],
					})
				},
				_ => Err(McpError::resource_not_found(
					"resource_not_found",
					Some(json!({
							"uri": uri
					})),
				)),
			}
		}

		async fn list_resource_templates(
			&self,
			_request: Option<PaginatedRequestParam>,
			_: RequestContext<RoleServer>,
		) -> Result<ListResourceTemplatesResult, McpError> {
			Ok(ListResourceTemplatesResult {
				next_cursor: None,
				resource_templates: Vec::new(),
			})
		}

		async fn initialize(
			&self,
			_request: InitializeRequestParam,
			_: RequestContext<RoleServer>,
		) -> Result<InitializeResult, McpError> {
			Ok(self.get_info())
		}
	}
}

#[test]
fn test_build_metadata_from_snapshot_mcp_fallback_tool() {
	use crate::cel::RequestSnapshot;
	use crate::mcp::ext_authz::build_metadata_from_snapshot;
	use crate::mcp::{ResourceId, ResourceType};

	let snapshot = RequestSnapshot {
		method: ::http::Method::POST,
		path: ::http::Uri::from_static("/mcp"),
		host: None,
		scheme: None,
		version: ::http::Version::HTTP_11,
		headers: ::http::HeaderMap::new(),
		body: None,
		jwt: None,
		api_key: None,
		basic_auth: None,
		backend: None,
		source: None,
		start_time: None,
		extauthz: None,
		extproc: None,
		llm: None,
	};

	let resource = ResourceType::Tool(ResourceId::new(
		"my_server".to_string(),
		"my_tool".to_string(),
	));

	let metadata = build_metadata_from_snapshot(&None, &snapshot, Some(&resource));

	let meta = metadata.expect("should produce metadata for MCP resource");
	assert!(
		meta
			.filter_metadata
			.contains_key("agentgateway.filters.mcp"),
		"should contain agentgateway.filters.mcp key"
	);
	assert!(
		!meta
			.filter_metadata
			.contains_key("envoy.filters.http.jwt_authn"),
		"should not contain JWT key when no JWT claims"
	);

	let mcp_struct = meta
		.filter_metadata
		.get("agentgateway.filters.mcp")
		.unwrap();
	let mcp_json = serde_json::to_value(mcp_struct).unwrap();
	assert_eq!(mcp_json["tool"]["target"], "my_server");
	assert_eq!(mcp_json["tool"]["name"], "my_tool");
}

#[test]
fn test_build_metadata_from_snapshot_mcp_fallback_prompt() {
	use crate::cel::RequestSnapshot;
	use crate::mcp::ext_authz::build_metadata_from_snapshot;
	use crate::mcp::{ResourceId, ResourceType};

	let snapshot = RequestSnapshot {
		method: ::http::Method::POST,
		path: ::http::Uri::from_static("/mcp"),
		host: None,
		scheme: None,
		version: ::http::Version::HTTP_11,
		headers: ::http::HeaderMap::new(),
		body: None,
		jwt: None,
		api_key: None,
		basic_auth: None,
		backend: None,
		source: None,
		start_time: None,
		extauthz: None,
		extproc: None,
		llm: None,
	};

	let resource = ResourceType::Prompt(ResourceId::new(
		"backend".to_string(),
		"summarize".to_string(),
	));

	let metadata = build_metadata_from_snapshot(&None, &snapshot, Some(&resource));

	let meta = metadata.unwrap();
	let mcp_struct = meta
		.filter_metadata
		.get("agentgateway.filters.mcp")
		.unwrap();
	let mcp_json = serde_json::to_value(mcp_struct).unwrap();
	assert_eq!(mcp_json["prompt"]["target"], "backend");
	assert_eq!(mcp_json["prompt"]["name"], "summarize");
}

#[test]
fn test_build_metadata_from_snapshot_mcp_fallback_resource() {
	use crate::cel::RequestSnapshot;
	use crate::mcp::ext_authz::build_metadata_from_snapshot;
	use crate::mcp::{ResourceId, ResourceType};

	let snapshot = RequestSnapshot {
		method: ::http::Method::POST,
		path: ::http::Uri::from_static("/mcp"),
		host: None,
		scheme: None,
		version: ::http::Version::HTTP_11,
		headers: ::http::HeaderMap::new(),
		body: None,
		jwt: None,
		api_key: None,
		basic_auth: None,
		backend: None,
		source: None,
		start_time: None,
		extauthz: None,
		extproc: None,
		llm: None,
	};

	let resource = ResourceType::Resource(ResourceId::new(
		"default".to_string(),
		"memo://insights".to_string(),
	));

	let metadata = build_metadata_from_snapshot(&None, &snapshot, Some(&resource));

	let meta = metadata.unwrap();
	let mcp_struct = meta
		.filter_metadata
		.get("agentgateway.filters.mcp")
		.unwrap();
	let mcp_json = serde_json::to_value(mcp_struct).unwrap();
	assert_eq!(mcp_json["resource"]["target"], "default");
	assert_eq!(mcp_json["resource"]["name"], "memo://insights");
}

#[test]
fn test_build_metadata_no_mcp_no_jwt_returns_none() {
	use crate::cel::RequestSnapshot;
	use crate::mcp::ext_authz::build_metadata_from_snapshot;

	let snapshot = RequestSnapshot {
		method: ::http::Method::POST,
		path: ::http::Uri::from_static("/mcp"),
		host: None,
		scheme: None,
		version: ::http::Version::HTTP_11,
		headers: ::http::HeaderMap::new(),
		body: None,
		jwt: None,
		api_key: None,
		basic_auth: None,
		backend: None,
		source: None,
		start_time: None,
		extauthz: None,
		extproc: None,
		llm: None,
	};

	let metadata = build_metadata_from_snapshot(&None, &snapshot, None);

	assert!(
		metadata.is_none(),
		"should return None when no MCP resource and no JWT"
	);
}

#[test]
fn test_build_metadata_from_snapshot_jwt_and_mcp_both_present() {
	use crate::cel::RequestSnapshot;
	use crate::http::jwt::Claims;
	use crate::mcp::ext_authz::build_metadata_from_snapshot;
	use crate::mcp::{ResourceId, ResourceType};
	use secrecy::SecretString;

	let mut claims_map = serde_json::Map::new();
	claims_map.insert("sub".to_string(), serde_json::json!("user@example.com"));
	claims_map.insert(
		"iss".to_string(),
		serde_json::json!("https://auth.example.com"),
	);

	let snapshot = RequestSnapshot {
		method: ::http::Method::POST,
		path: ::http::Uri::from_static("/mcp"),
		host: None,
		scheme: None,
		version: ::http::Version::HTTP_11,
		headers: ::http::HeaderMap::new(),
		body: None,
		jwt: Some(Claims {
			inner: claims_map,
			jwt: SecretString::from("fake.jwt.token"),
		}),
		api_key: None,
		basic_auth: None,
		backend: None,
		source: None,
		start_time: None,
		extauthz: None,
		extproc: None,
		llm: None,
	};

	let resource = ResourceType::Tool(ResourceId::new("server".to_string(), "my_tool".to_string()));

	let metadata = build_metadata_from_snapshot(&None, &snapshot, Some(&resource));

	let meta = metadata.unwrap();
	assert!(
		meta
			.filter_metadata
			.contains_key("envoy.filters.http.jwt_authn"),
		"should contain JWT metadata"
	);
	assert!(
		meta
			.filter_metadata
			.contains_key("agentgateway.filters.mcp"),
		"should contain MCP metadata"
	);

	let jwt_struct = meta
		.filter_metadata
		.get("envoy.filters.http.jwt_authn")
		.unwrap();
	let jwt_json = serde_json::to_value(jwt_struct).unwrap();
	assert_eq!(jwt_json["jwt_payload"]["sub"], "user@example.com");

	let mcp_struct = meta
		.filter_metadata
		.get("agentgateway.filters.mcp")
		.unwrap();
	let mcp_json = serde_json::to_value(mcp_struct).unwrap();
	assert_eq!(mcp_json["tool"]["name"], "my_tool");
}

#[test]
fn test_extract_body_no_opts_returns_empty() {
	use crate::mcp::ext_authz::extract_body;

	let (body, raw, size) = extract_body(&None, None);
	assert!(body.is_empty());
	assert!(raw.is_empty());
	assert_eq!(size, 0);
}

#[test]
fn test_extract_body_no_buffered_body_returns_empty() {
	use crate::http::ext_authz::BodyOptions;
	use crate::mcp::ext_authz::extract_body;

	let opts = Some(BodyOptions {
		max_request_bytes: 1024,
		allow_partial_message: false,
		pack_as_bytes: false,
	});
	let (body, raw, size) = extract_body(&opts, None);
	assert!(body.is_empty());
	assert!(raw.is_empty());
	assert_eq!(size, 0);
}

#[test]
fn test_extract_body_as_string() {
	use crate::cel::BufferedBody;
	use crate::http::ext_authz::BodyOptions;
	use crate::mcp::ext_authz::extract_body;
	use bytes::Bytes;

	let opts = Some(BodyOptions {
		max_request_bytes: 1024,
		allow_partial_message: false,
		pack_as_bytes: false,
	});
	let payload = r#"{"jsonrpc":"2.0","method":"tools/call"}"#;
	let buffered = BufferedBody(Bytes::from(payload));
	let (body, raw, size) = extract_body(&opts, Some(&buffered));
	assert_eq!(body, payload);
	assert!(
		raw.is_empty(),
		"raw_body should be empty when pack_as_bytes=false"
	);
	assert_eq!(size, payload.len() as i64);
}

#[test]
fn test_extract_body_as_raw_bytes() {
	use crate::cel::BufferedBody;
	use crate::http::ext_authz::BodyOptions;
	use crate::mcp::ext_authz::extract_body;
	use bytes::Bytes;

	let opts = Some(BodyOptions {
		max_request_bytes: 1024,
		allow_partial_message: false,
		pack_as_bytes: true,
	});
	let payload = b"binary-payload";
	let buffered = BufferedBody(Bytes::from(&payload[..]));
	let (body, raw, size) = extract_body(&opts, Some(&buffered));
	assert!(
		body.is_empty(),
		"body string should be empty when pack_as_bytes=true"
	);
	assert_eq!(raw, payload.to_vec());
	assert_eq!(size, payload.len() as i64);
}

#[test]
fn test_extract_body_truncated_with_allow_partial() {
	use crate::cel::BufferedBody;
	use crate::http::ext_authz::BodyOptions;
	use crate::mcp::ext_authz::extract_body;
	use bytes::Bytes;

	let opts = Some(BodyOptions {
		max_request_bytes: 5,
		allow_partial_message: true,
		pack_as_bytes: false,
	});
	let payload = "hello world";
	let buffered = BufferedBody(Bytes::from(payload));
	let (body, raw, size) = extract_body(&opts, Some(&buffered));
	assert_eq!(
		body, "hello",
		"body should be truncated to max_request_bytes"
	);
	assert!(raw.is_empty());
	assert_eq!(
		size,
		payload.len() as i64,
		"size should report original body length"
	);
}

#[test]
fn test_extract_body_truncated_without_allow_partial_returns_empty() {
	use crate::cel::BufferedBody;
	use crate::http::ext_authz::BodyOptions;
	use crate::mcp::ext_authz::extract_body;
	use bytes::Bytes;

	let opts = Some(BodyOptions {
		max_request_bytes: 5,
		allow_partial_message: false,
		pack_as_bytes: false,
	});
	let payload = "hello world";
	let buffered = BufferedBody(Bytes::from(payload));
	let (body, raw, size) = extract_body(&opts, Some(&buffered));
	assert!(
		body.is_empty(),
		"body should be empty when too large and allow_partial=false"
	);
	assert!(raw.is_empty());
	assert_eq!(
		size,
		payload.len() as i64,
		"size should still report original body length"
	);
}

#[test]
fn test_extract_body_exact_limit_not_truncated() {
	use crate::cel::BufferedBody;
	use crate::http::ext_authz::BodyOptions;
	use crate::mcp::ext_authz::extract_body;
	use bytes::Bytes;

	let opts = Some(BodyOptions {
		max_request_bytes: 5,
		allow_partial_message: false,
		pack_as_bytes: false,
	});
	let payload = "hello";
	let buffered = BufferedBody(Bytes::from(payload));
	let (body, _, size) = extract_body(&opts, Some(&buffered));
	assert_eq!(body, "hello", "body at exact limit should not be truncated");
	assert_eq!(size, 5);
}

// MARK: handle_auth_failure tests

#[test]
fn handle_auth_failure_allow_returns_ok() {
	use crate::http::ext_authz::{ExtAuthz, FailureMode};
	use crate::mcp::ext_authz::McpExtAuthz;

	let ea = McpExtAuthz(ExtAuthz {
		failure_mode: FailureMode::Allow,
		..Default::default()
	});
	let result = ea.handle_auth_failure("test unavailable");
	assert!(result.is_ok(), "FailureMode::Allow should return Ok");
	let ok = result.unwrap();
	assert!(ok.request_headers_to_add.is_empty());
	assert!(ok.request_headers_to_remove.is_empty());
	assert!(ok.response_headers_to_add.is_empty());
	assert!(ok.dynamic_metadata.is_none());
}

#[test]
fn handle_auth_failure_deny_returns_403() {
	use crate::http::ext_authz::{ExtAuthz, FailureMode};
	use crate::mcp::ext_authz::McpExtAuthz;

	let ea = McpExtAuthz(ExtAuthz {
		failure_mode: FailureMode::Deny,
		..Default::default()
	});
	let result = ea.handle_auth_failure("test unavailable");
	assert!(result.is_err(), "FailureMode::Deny should return Err");
	let denied = result.unwrap_err();
	assert_eq!(denied.status_code, ::http::StatusCode::FORBIDDEN);
	assert_eq!(denied.body, "external authorization denied");
	assert!(denied.response_headers.is_empty());
}

#[test]
fn handle_auth_failure_deny_with_status_returns_custom_code() {
	use crate::http::ext_authz::{ExtAuthz, FailureMode};
	use crate::mcp::ext_authz::McpExtAuthz;

	let ea = McpExtAuthz(ExtAuthz {
		failure_mode: FailureMode::DenyWithStatus(503),
		..Default::default()
	});
	let result = ea.handle_auth_failure("test unavailable");
	assert!(
		result.is_err(),
		"FailureMode::DenyWithStatus should return Err"
	);
	let denied = result.unwrap_err();
	assert_eq!(
		denied.status_code,
		::http::StatusCode::SERVICE_UNAVAILABLE,
		"should use the configured 503 status"
	);
	assert_eq!(denied.body, "external authorization denied");
}

#[test]
fn handle_auth_failure_deny_with_invalid_status_falls_back_to_403() {
	use crate::http::ext_authz::{ExtAuthz, FailureMode};
	use crate::mcp::ext_authz::McpExtAuthz;

	let ea = McpExtAuthz(ExtAuthz {
		failure_mode: FailureMode::DenyWithStatus(9999),
		..Default::default()
	});
	let result = ea.handle_auth_failure("bad status");
	assert!(result.is_err());
	let denied = result.unwrap_err();
	assert_eq!(
		denied.status_code,
		::http::StatusCode::FORBIDDEN,
		"invalid status code should fall back to 403"
	);
}

// MARK: check() protocol rejection tests

fn make_test_snapshot() -> crate::cel::RequestSnapshot {
	crate::cel::RequestSnapshot {
		method: ::http::Method::POST,
		path: ::http::Uri::from_static("/mcp"),
		host: None,
		scheme: None,
		version: ::http::Version::HTTP_11,
		headers: ::http::HeaderMap::new(),
		body: None,
		jwt: None,
		api_key: None,
		basic_auth: None,
		backend: None,
		source: None,
		start_time: None,
		extauthz: None,
		extproc: None,
		llm: None,
	}
}

fn make_test_policy_client() -> crate::proxy::httpproxy::PolicyClient {
	use crate::proxy::httpproxy::PolicyClient;
	use crate::test_helpers::proxymock::setup_proxy_test;
	PolicyClient {
		inputs: setup_proxy_test("{}").unwrap().inputs(),
	}
}

#[tokio::test]
async fn check_with_http_protocol_returns_internal_server_error() {
	use crate::http::ext_authz::ExtAuthz;
	use crate::mcp::ext_authz::McpExtAuthz;

	let ea = McpExtAuthz(ExtAuthz {
		protocol: crate::http::ext_authz::Protocol::Http {
			path: None,
			redirect: None,
			include_response_headers: Vec::new(),
			add_request_headers: Default::default(),
			metadata: Default::default(),
		},
		..Default::default()
	});

	let snapshot = make_test_snapshot();
	let client = make_test_policy_client();
	let result = ea.check(client, &snapshot, None).await;
	assert!(result.is_err(), "HTTP protocol should be rejected");
	let denied = result.unwrap_err();
	assert_eq!(
		denied.status_code,
		::http::StatusCode::INTERNAL_SERVER_ERROR
	);
	assert!(
		denied.body.contains("only supports gRPC"),
		"error should mention gRPC requirement, got: {}",
		denied.body
	);
}

// MARK: check() transport failure tests

#[tokio::test]
async fn check_with_unreachable_server_respects_failure_mode_allow() {
	use crate::http::ext_authz::{ExtAuthz, FailureMode};
	use crate::mcp::ext_authz::McpExtAuthz;

	let ea = McpExtAuthz(ExtAuthz {
		failure_mode: FailureMode::Allow,
		..Default::default()
	});

	let snapshot = make_test_snapshot();
	let client = make_test_policy_client();
	let result = ea.check(client, &snapshot, None).await;
	assert!(
		result.is_ok(),
		"FailureMode::Allow should let request through on transport failure, got: {:?}",
		result.unwrap_err()
	);
}

#[tokio::test]
async fn check_with_unreachable_server_respects_failure_mode_deny() {
	use crate::http::ext_authz::{ExtAuthz, FailureMode};
	use crate::mcp::ext_authz::McpExtAuthz;

	let ea = McpExtAuthz(ExtAuthz {
		failure_mode: FailureMode::Deny,
		..Default::default()
	});

	let snapshot = make_test_snapshot();
	let client = make_test_policy_client();
	let result = ea.check(client, &snapshot, None).await;
	assert!(
		result.is_err(),
		"FailureMode::Deny should reject on transport failure"
	);
	let denied = result.unwrap_err();
	assert_eq!(denied.status_code, ::http::StatusCode::FORBIDDEN);
}
