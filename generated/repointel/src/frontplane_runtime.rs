#![allow(dead_code)]
#![allow(unused_imports)]
// Generated facade runtime copied by the Frontplane generator. Product logic lives in frontplane_backing modules.
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::Router;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
#[cfg(feature = "frontplane_security")]
use std::fs;
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "sealed_ids")]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Clone, Copy)]
pub struct Route {
    pub operation: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub input: &'static str,
    pub status: u16,
    pub auth_required: bool,
}

#[derive(Clone, Copy)]
pub struct RouteRateLimit {
    pub operation: &'static str,
    pub by: &'static str,
    pub requests: u32,
    pub window_seconds: u64,
}

#[derive(Clone, Copy)]
pub struct CallDeclaration {
    pub name: &'static str,
    pub kind: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub auth: &'static str,
}

#[derive(Clone, Copy)]
pub struct FlowStep {
    pub kind: &'static str,
    pub raw: &'static str,
    pub target: &'static str,
    pub args: &'static str,
    pub binding: &'static str,
}

#[derive(Clone, Copy)]
pub struct OperationFlow {
    pub operation: &'static str,
    pub steps: &'static [FlowStep],
}

#[derive(Clone, Copy)]
pub struct AuthzRule {
    pub name: &'static str,
    pub cel: &'static str,
}

#[derive(Clone, Copy)]
pub struct FieldDeclaration {
    pub name: &'static str,
    pub shape: &'static str,
    pub required: bool,
}

#[derive(Clone, Copy)]
pub struct ShapeDeclaration {
    pub name: &'static str,
    pub fields: &'static [FieldDeclaration],
}

#[derive(Clone, Copy)]
pub struct FlowResult {
    pub steps: usize,
    pub calls: usize,
    pub rest_calls: usize,
    pub provider_calls: usize,
}

pub struct FlowExecution {
    pub result: FlowResult,
    pub output: Value,
}

pub struct FlowContext {
    pub operation: String,
    pub input: Value,
    pub path: BTreeMap<String, String>,
    pub query: BTreeMap<String, String>,
    pub auth: Value,
    pub bindings: BTreeMap<String, Value>,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

pub struct FacadeResponse {
    pub status: u16,
    pub body: Value,
}

#[derive(Clone, Default)]
pub struct RuntimeState {
    pub request_counts: BTreeMap<String, usize>,
    pub provider_call_counts: BTreeMap<String, usize>,
    pub provider_calls: usize,
    pub rate_limited_requests: usize,
    rate_limit_buckets: BTreeMap<String, RateLimitBucket>,
}

#[derive(Clone, Copy, Debug)]
struct RateLimitBucket {
    window_start_millis: u128,
    requests: u32,
}

pub struct FrontplaneRuntime {
    state: Mutex<RuntimeState>,
    providers: ProviderClient,
}

#[derive(Clone)]
pub struct ProviderEndpoint {
    pub provider: String,
    pub package: String,
    pub purpose: String,
    pub url: Option<String>,
    pub base_url: Option<String>,
    pub host_header: Option<String>,
    pub fp_call: Option<String>,
}

pub struct ProviderClient {
    pub endpoints: Vec<ProviderEndpoint>,
    http: reqwest::Client,
}

pub async fn run() -> std::io::Result<()> {
    let mut host = "127.0.0.1".to_string();
    let mut port = "18080".to_string();
    let mut healthcheck = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => host = args.next().unwrap_or(host),
            "--port" => port = args.next().unwrap_or(port),
            "--healthcheck" => healthcheck = args.next(),
            _ => {}
        }
    }

    if let Some(addr) = healthcheck {
        return check_health(&addr).await;
    }

    let runtime = Arc::new(FrontplaneRuntime::new());
    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}")).await?;
    let app = Router::new().fallback(handle).with_state(runtime);
    println!(
        "{} REST facade listening on http://{host}:{port}",
        service_name()
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

fn service_name() -> &'static str {
    crate::SERVICE_NAME
}

async fn handle(
    State(runtime): State<Arc<FrontplaneRuntime>>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    method: axum::http::Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let method = method.as_str();
    let raw_path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(uri.path());
    let path = uri.path();
    let query = parse_query(raw_path);
    let headers = request_headers(&headers);

    if method == "GET" && path == "/healthz" {
        return respond(200, &runtime.health());
    }
    if method == "GET" && path == "/metrics" {
        let Some(token) = bearer_token(&headers) else {
            return respond(
                401,
                &json!({"error":"UnauthorizedError","message":"authorization bearer token required"}),
            );
        };
        let auth = match crate::frontplane_backing::authenticate_bearer(&token) {
            Ok(auth) => auth,
            Err(err) => {
                return respond(
                    err.status,
                    &json!({"error": err.code, "message": err.message}),
                )
            }
        };
        if !auth_has_role(&auth, "admin") {
            return respond(
                403,
                &json!({"error":"ForbiddenError","message":"authorization rule provider_reader denied request"}),
            );
        }
        return respond(200, &runtime.metrics());
    }

    let Some((route, path_params)) = find_route(method, path) else {
        return respond(
            404,
            &json!({"error":"NotFoundError","message":"route not found"}),
        );
    };
    let client_ip = client_ip(&headers, remote_addr);
    if let Err(err) = runtime.check_rate_limit(route, &client_ip) {
        return respond(
            err.status,
            &json!({"error": err.code, "message": err.message}),
        );
    }
    if route.auth_required && bearer_token(&headers).is_none() {
        return respond(
            401,
            &json!({"error":"UnauthorizedError","message":"authorization bearer token required"}),
        );
    }

    let input = match parse_body_bytes(&body) {
        Ok(input) => input,
        Err(err) => {
            return respond(
                err.status,
                &json!({"error": err.code, "message": err.message}),
            )
        }
    };
    if let Err(err) = validate_request_input(route, &input, &query, &path_params) {
        return respond(
            err.status,
            &json!({"error": err.code, "message": err.message}),
        );
    }
    let auth = match bearer_token(&headers) {
        Some(token) => match crate::frontplane_backing::authenticate_bearer(&token) {
            Ok(auth) => auth,
            Err(err) => {
                return respond(
                    err.status,
                    &json!({"error": err.code, "message": err.message}),
                )
            }
        },
        None => json!({"authenticated": false, "authorization": "", "token": ""}),
    };
    match runtime
        .dispatch(route, &path_params, &query, input, auth)
        .await
    {
        Ok(response) => respond(response.status, &response.body),
        Err(err) => respond(
            err.status,
            &json!({"error": err.code, "message": err.message}),
        ),
    }
}

impl FrontplaneRuntime {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RuntimeState::default()),
            providers: ProviderClient::from_env(),
        }
    }

    fn check_rate_limit(&self, route: &Route, client_ip: &str) -> Result<(), ApiError> {
        let Some(limit) = rate_limit_for_operation(route.operation) else {
            return Ok(());
        };
        if limit.by != "ip" || limit.requests == 0 || limit.window_seconds == 0 {
            return Ok(());
        }
        let now = now_millis();
        let window_millis = u128::from(limit.window_seconds) * 1_000;
        let key = format!("{}|{}", route.operation, client_ip);
        let mut state = self.state.lock().unwrap();
        prune_rate_limit_buckets(&mut state.rate_limit_buckets, now);
        let limited = {
            let bucket = state
                .rate_limit_buckets
                .entry(key)
                .or_insert(RateLimitBucket {
                    window_start_millis: now,
                    requests: 0,
                });
            if now.saturating_sub(bucket.window_start_millis) >= window_millis {
                bucket.window_start_millis = now;
                bucket.requests = 0;
            }
            if bucket.requests >= limit.requests {
                true
            } else {
                bucket.requests += 1;
                false
            }
        };
        if limited {
            state.rate_limited_requests += 1;
            return Err(ApiError::rate_limited(format!(
                "rate limit exceeded for operation {} from client IP {}; limit is {} requests per {} seconds",
                route.operation, client_ip, limit.requests, limit.window_seconds
            )));
        }
        Ok(())
    }

    async fn dispatch(
        &self,
        route: &Route,
        path: &BTreeMap<String, String>,
        query: &BTreeMap<String, String>,
        input: Value,
        auth: Value,
    ) -> Result<FacadeResponse, ApiError> {
        let execution = self
            .execute_operation_flow(route.operation, path, query, input, auth)
            .await?;
        let mut state = self.state.lock().unwrap();
        let label = format!("{} {} {}", route.method, route.path, route.status);
        *state.request_counts.entry(label).or_insert(0) += 1;
        state.provider_calls += execution.result.provider_calls;
        Ok(FacadeResponse {
            status: route.status,
            body: envelope(route.operation, execution.output, execution.result),
        })
    }

    async fn execute_operation_flow(
        &self,
        operation: &str,
        path: &BTreeMap<String, String>,
        query: &BTreeMap<String, String>,
        input: Value,
        auth: Value,
    ) -> Result<FlowExecution, ApiError> {
        let flow = crate::OPERATION_FLOWS
            .iter()
            .find(|flow| flow.operation == operation)
            .ok_or_else(|| {
                ApiError::internal(format!("operation {operation} has no generated flow"))
            })?;
        let mut context = FlowContext {
            operation: operation.to_string(),
            input: request_input(input, path, query),
            path: path.clone(),
            query: query.clone(),
            auth,
            bindings: BTreeMap::new(),
        };
        let mut output_binding = None;
        let mut calls = 0_usize;
        let mut rest_calls = 0_usize;
        let mut provider_calls = 0_usize;

        for step in flow.steps {
            if step.raw.is_empty() {
                return Err(ApiError::internal(format!(
                    "operation {operation} has an empty flow step"
                )));
            }
            match step.kind {
                "input" => {}
                "output" => output_binding = Some(step.raw),
                "authz" => {
                    if !eval_authz(step.raw, &context)? {
                        return Err(ApiError::forbidden(format!(
                            "authorization rule {} denied request",
                            step.raw
                        )));
                    }
                }
                "Lcall" | "Dcall" | "Gcall" | "DGcall" | "LEcall" | "Ncall" | "Acall" => {
                    calls += 1;
                    let call = crate::CALLS
                        .iter()
                        .find(|call| call.name == step.target)
                        .ok_or_else(|| {
                            ApiError::internal(format!(
                                "operation {operation} calls undeclared function {}",
                                step.target
                            ))
                        })?;
                    if matches!(step.kind, "Ncall" | "Acall") && call.kind != "rest" {
                        return Err(ApiError::internal(format!(
                            "operation {operation} {} target {} is not a REST call",
                            step.kind, step.target
                        )));
                    }
                    if matches!(step.kind, "Lcall" | "Dcall" | "Gcall" | "DGcall" | "LEcall")
                        && call.kind == "rest"
                    {
                        return Err(ApiError::internal(format!(
                            "operation {operation} {} target {} is a REST call",
                            step.kind, step.target
                        )));
                    }
                    let value = if call.kind == "rest" {
                        rest_calls += 1;
                        let result = self
                            .providers
                            .call_flow_rest(call, &context, step.args, step.kind)
                            .await?;
                        provider_calls += 1;
                        let mut state = self.state.lock().unwrap();
                        *state
                            .provider_call_counts
                            .entry(call.name.to_string())
                            .or_insert(0) += 1;
                        result
                    } else {
                        warn_local_boundary(step.kind, step.target);
                        self.call_local(step.target, step.args, &context)?
                    };
                    if !step.binding.is_empty() {
                        context.bindings.insert(step.binding.to_string(), value);
                    }
                }
                "if" => {
                    let parts = parse_if_parts(step.raw)?;
                    if !eval_cel(parts[0], &context, 0)? {
                        return Err(reject_branch(parts[2]));
                    }
                }
                other => {
                    return Err(ApiError::internal(format!(
                        "unknown flow step kind {other}"
                    )));
                }
            }
        }

        let output = match output_binding {
            Some("none") | None => json!({}),
            Some(binding) => resolve_arg(binding, &context),
        };
        Ok(FlowExecution {
            result: FlowResult {
                steps: flow.steps.len(),
                calls,
                rest_calls,
                provider_calls,
            },
            output,
        })
    }

    fn call_local(
        &self,
        target: &str,
        args: &str,
        context: &FlowContext,
    ) -> Result<Value, ApiError> {
        let args = split_args(args);
        crate::frontplane_backing::invoke(target, &args, context)
    }

    fn health(&self) -> Value {
        json!({
            "status": "ok",
            "service": service_name(),
            "runtime": {
                "language": "rust",
                "facade": "rest",
                "route_count": crate::ROUTES.len(),
                "call_count": crate::CALLS.len(),
                "rest_call_count": crate::CALLS.iter().filter(|call| call.kind == "rest").count()
            }
        })
    }

    fn metrics(&self) -> Value {
        let state = self.state.lock().unwrap();
        let requests_total: usize = state.request_counts.values().sum();
        json!({
            "metrics": {
                "requests_total": requests_total,
                "requests": state.request_counts,
                "rate_limited_requests": state.rate_limited_requests,
                "rate_limits": crate::RATE_LIMITS.iter().map(|limit| {
                    json!({
                        "operation": limit.operation,
                        "by": limit.by,
                        "requests": limit.requests,
                        "window_seconds": limit.window_seconds
                    })
                }).collect::<Vec<_>>(),
                "provider_calls_by_name": state.provider_call_counts,
                "provider_calls": state.provider_calls
            }
        })
    }
}

fn warn_local_boundary(kind: &str, target: &str) {
    match kind {
        "Dcall" => eprintln!(
            "frontplane warning: Dcall {target} is declared to perform local disk I/O"
        ),
        "Gcall" => eprintln!(
            "frontplane warning: Gcall {target} is declared to access process/global state outside function arguments"
        ),
        "DGcall" => eprintln!(
            "frontplane warning: DGcall {target} is declared to perform local disk I/O and access process/global state outside function arguments"
        ),
        "LEcall" => eprintln!(
            "frontplane warning: LEcall {target} is declared to execute a configured local program"
        ),
        _ => {}
    }
}

impl ProviderClient {
    fn from_env() -> Self {
        let mut endpoints = default_provider_endpoints();
        if let Some(map) = env::var(crate::PROVIDER_ENDPOINTS_ENV)
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .and_then(|value| value.as_object().cloned())
        {
            for (name, value) in map {
                let endpoint = configured_endpoint(&name, &value);
                if let Some(existing) = endpoints.iter_mut().find(|existing| {
                    existing.provider == endpoint.provider && endpoint.fp_call.is_none()
                }) {
                    existing.url = endpoint.url;
                    existing.base_url = endpoint.base_url;
                    existing.host_header = endpoint.host_header;
                    existing.fp_call = endpoint.fp_call;
                } else {
                    endpoints.push(endpoint);
                }
            }
        }
        let connect_timeout = rest_timeout("CONNECT", 5_000);
        let read_timeout = rest_timeout("READ", 15_000);
        Self {
            endpoints,
            http: reqwest::Client::builder()
                .connect_timeout(connect_timeout)
                .read_timeout(read_timeout)
                .user_agent("frontplane-rust-facade/1.0")
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    async fn call_flow_rest(
        &self,
        declaration: &CallDeclaration,
        context: &FlowContext,
        args: &str,
        flow_call_kind: &str,
    ) -> Result<Value, ApiError> {
        if declaration.method.is_empty() || declaration.path.is_empty() {
            return Err(ApiError::internal(format!(
                "REST call {} is missing method or path",
                declaration.name
            )));
        }
        let payload = rest_payload(args, context);
        let endpoint = self.endpoint_for(declaration.name).ok_or_else(|| {
            ApiError::provider(format!(
                "REST call {} has no configured endpoint",
                declaration.name
            ))
        })?;
        if endpoint.url.is_none() && endpoint.base_url.is_none() {
            return Err(ApiError::provider(format!(
                "REST call {} has no configured endpoint",
                declaration.name
            )));
        }
        if declaration.name == "NATS.publish" && endpoint_uses_scheme(endpoint, "nats://") {
            return nats_publish(declaration, endpoint, context, payload.as_ref()).await;
        }
        let url =
            endpoint_url(endpoint, declaration, context, payload.as_ref()).ok_or_else(|| {
                ApiError::provider(format!(
                    "REST call {} cannot render required path variables for {}",
                    declaration.name, declaration.path
                ))
            })?;
        let body = http_json(
            &self.http,
            declaration,
            endpoint,
            &url,
            payload.as_ref(),
            flow_call_kind,
        )
        .await?;
        if crate::WRAP_PROVIDER_RESULTS {
            Ok(rest_result(
                declaration,
                "ready",
                true,
                "provider call succeeded",
                body,
            ))
        } else {
            Ok(body)
        }
    }

    fn endpoint_for(&self, call_name: &str) -> Option<&ProviderEndpoint> {
        let module = call_name
            .split_once('.')
            .map(|(module, _)| module)
            .unwrap_or(call_name);
        self.endpoints
            .iter()
            .find(|endpoint| {
                endpoint.provider == call_name || endpoint.fp_call.as_deref() == Some(call_name)
            })
            .or_else(|| {
                self.endpoints
                    .iter()
                    .find(|endpoint| endpoint.provider == module && endpoint.fp_call.is_none())
            })
    }

    fn provider_summary(&self) -> Value {
        let configured = self
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.url.is_some() || endpoint.base_url.is_some())
            .count();
        json!({
            "total": self.endpoints.len(),
            "configured": configured,
            "unconfigured": self.endpoints.len().saturating_sub(configured),
            "detail": "provider REST callouts fail closed unless endpoints are configured",
            "providers": self.endpoints.iter().map(|endpoint| {
                json!({
                    "provider": endpoint.provider,
                    "package": endpoint.package,
                    "purpose": endpoint.purpose,
                    "configured": endpoint.url.is_some() || endpoint.base_url.is_some()
                })
            }).collect::<Vec<_>>()
        })
    }
}

pub fn provider_health_from_values(values: &[Value]) -> Vec<Value> {
    let mut items = crate::PROVIDER_HEALTH_LIST
        .iter()
        .map(|provider| {
            json!({
                "provider": provider,
                "package": provider,
                "purpose": provider_purpose(provider),
                "state": "unconfigured",
                "configured": false,
                "detail": "no health result supplied by operation flow",
                "checked_at": now()
            })
        })
        .collect::<Vec<_>>();
    for (index, value) in values.iter().enumerate() {
        let provider = value
            .get("provider")
            .and_then(Value::as_str)
            .or_else(|| {
                value
                    .get("call")
                    .and_then(Value::as_str)
                    .and_then(|call| call.split_once('.').map(|(module, _)| module))
            })
            .or_else(|| crate::PROVIDER_HEALTH_LIST.get(index).copied());
        let Some(provider) = provider else {
            continue;
        };
        if let Some(item) = items
            .iter_mut()
            .find(|item| item.get("provider").and_then(Value::as_str) == Some(provider))
        {
            item["state"] = value
                .get("state")
                .cloned()
                .unwrap_or_else(|| json!("ready"));
            item["configured"] = value
                .get("configured")
                .cloned()
                .unwrap_or_else(|| json!(true));
            item["detail"] = value
                .get("detail")
                .cloned()
                .unwrap_or_else(|| json!("provider call succeeded"));
            item["checked_at"] = json!(now());
        }
    }
    items
}

fn eval_authz(rule_or_cel: &str, context: &FlowContext) -> Result<bool, ApiError> {
    eval_authz_depth(rule_or_cel, context, 0)
}

fn eval_authz_depth(
    rule_or_cel: &str,
    context: &FlowContext,
    depth: usize,
) -> Result<bool, ApiError> {
    if depth > 32 {
        return Err(ApiError::internal("authz rule recursion limit exceeded"));
    }
    let cel = crate::AUTHZ_RULES
        .iter()
        .find(|rule| rule.name == rule_or_cel)
        .map(|rule| rule.cel)
        .unwrap_or(rule_or_cel);
    eval_cel(cel, context, depth + 1)
}

fn eval_cel(expr: &str, context: &FlowContext, depth: usize) -> Result<bool, ApiError> {
    let expr = trim_outer_parens(expr.trim());
    if let Some(parts) = split_top_level_operator(expr, "||") {
        for part in parts {
            if eval_cel(part, context, depth)? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if let Some(parts) = split_top_level_operator(expr, "&&") {
        for part in parts {
            if !eval_cel(part, context, depth)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    eval_cel_atom(expr, context, depth)
}

fn eval_cel_atom(expr: &str, context: &FlowContext, depth: usize) -> Result<bool, ApiError> {
    let expr = trim_outer_parens(expr.trim());
    if expr == "true" {
        return Ok(true);
    }
    if expr == "false" {
        return Ok(false);
    }
    if let Some(rule) = crate::AUTHZ_RULES.iter().find(|rule| rule.name == expr) {
        return eval_authz_depth(rule.name, context, depth + 1);
    }
    if let Some(rest) = expr.strip_prefix('!') {
        return Ok(!eval_cel(rest, context, depth)?);
    }
    if let Some((left, right)) = split_top_level_once(expr, " in ") {
        let needle = cel_value(left.trim(), context);
        let haystack = cel_value(right.trim(), context);
        return Ok(match (needle, haystack) {
            (CelValue::String(needle), CelValue::List(values)) => {
                values.iter().any(|value| value == &needle)
            }
            _ => false,
        });
    }
    if let Some((left, right)) = split_top_level_once(expr, "!=") {
        return Ok(!cel_eq(
            cel_value(left.trim(), context),
            cel_value(right.trim(), context),
        ));
    }
    if let Some((left, right)) = split_top_level_once(expr, "==") {
        return Ok(cel_eq(
            cel_value(left.trim(), context),
            cel_value(right.trim(), context),
        ));
    }
    match cel_value(expr, context) {
        CelValue::Bool(value) => Ok(value),
        _ => Err(ApiError::internal(format!(
            "unsupported CEL authz expression `{expr}`"
        ))),
    }
}

pub enum CelValue {
    Bool(bool),
    String(String),
    List(Vec<String>),
    Null,
}

fn cel_eq(left: CelValue, right: CelValue) -> bool {
    match (left, right) {
        (CelValue::Bool(left), CelValue::Bool(right)) => left == right,
        (CelValue::String(left), CelValue::String(right)) => left == right,
        (CelValue::Null, CelValue::Null) => true,
        _ => false,
    }
}

fn cel_value(term: &str, context: &FlowContext) -> CelValue {
    let term = trim_outer_parens(term.trim());
    if term == "true" {
        return CelValue::Bool(true);
    }
    if term == "false" {
        return CelValue::Bool(false);
    }
    if let Some(value) = string_literal(term) {
        return CelValue::String(value);
    }
    if let Some((root, name)) = term.split_once('.') {
        match root {
            "path" => {
                return context
                    .path
                    .get(name)
                    .map(|value| CelValue::String(value.clone()))
                    .unwrap_or(CelValue::Null);
            }
            "query" => {
                return context
                    .query
                    .get(name)
                    .map(|value| CelValue::String(value.clone()))
                    .unwrap_or(CelValue::Null);
            }
            _ => {}
        }
    }
    value_path(term, context)
        .map(json_to_cel)
        .unwrap_or(CelValue::Null)
}

fn value_path<'a>(term: &str, context: &'a FlowContext) -> Option<&'a Value> {
    if term == "input" {
        return Some(&context.input);
    }
    let (root, rest) = term.split_once('.')?;
    let value = match root {
        "input" => &context.input,
        "auth" => &context.auth,
        "path" => return None,
        binding => context.bindings.get(binding)?,
    };
    nested_value_ref(value, rest)
}

fn nested_value_ref<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn json_to_cel(value: &Value) -> CelValue {
    if let Some(value) = value.as_bool() {
        return CelValue::Bool(value);
    }
    if let Some(value) = value.as_str() {
        return CelValue::String(value.to_string());
    }
    if let Some(values) = value.as_array() {
        return CelValue::List(
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
        );
    }
    CelValue::Null
}

fn parse_if_parts(raw: &str) -> Result<Vec<&str>, ApiError> {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(trimmed);
    let parts = split_top_level(inner, ',');
    if parts.len() != 3 {
        return Err(ApiError::internal(format!("invalid if step `{raw}`")));
    }
    Ok(parts)
}

fn reject_branch(branch: &str) -> ApiError {
    let branch = branch.trim();
    if !branch.starts_with("reject ") {
        return ApiError::internal(format!("unsupported if branch `{branch}`"));
    }
    let code = branch.trim_start_matches("reject ").trim();
    match code {
        "BadRequestError" => ApiError::bad_request("flow guard rejected request"),
        "UnauthorizedError" => ApiError::unauthorized("flow guard rejected request"),
        "ForbiddenError" => ApiError::forbidden("flow guard rejected request"),
        "ConflictError" => ApiError::conflict("flow guard rejected request"),
        "NotFoundError" => ApiError::not_found("flow guard rejected request"),
        _ => ApiError::internal(format!("unknown reject error {code}")),
    }
}

fn find_route(method: &str, path: &str) -> Option<(&'static Route, BTreeMap<String, String>)> {
    crate::ROUTES.iter().find_map(|route| {
        if route.method == method {
            match_template(route.path, path).map(|params| (route, params))
        } else {
            None
        }
    })
}

fn match_template(template: &str, path: &str) -> Option<BTreeMap<String, String>> {
    let expected = template.trim_matches('/').split('/').collect::<Vec<_>>();
    let actual = path.trim_matches('/').split('/').collect::<Vec<_>>();
    if expected.len() != actual.len() {
        return None;
    }
    let mut params = BTreeMap::new();
    for (left, right) in expected.iter().zip(actual.iter()) {
        if left.starts_with('{') && left.ends_with('}') && !right.is_empty() {
            params.insert(
                left.trim_matches(&['{', '}'][..]).to_string(),
                url_decode(right),
            );
        } else if left != right {
            return None;
        }
    }
    Some(params)
}

fn clean_path(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

fn parse_query(path: &str) -> BTreeMap<String, String> {
    path.split_once('?')
        .map(|(_, query)| {
            query
                .split('&')
                .filter_map(|part| {
                    let (key, value) = part.split_once('=').unwrap_or((part, ""));
                    if key.is_empty() {
                        None
                    } else {
                        Some((url_decode(key), url_decode(value)))
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn request_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            Some((
                name.as_str().to_ascii_lowercase(),
                value.to_str().ok()?.trim().to_string(),
            ))
        })
        .collect()
}

fn client_ip(headers: &BTreeMap<String, String>, remote_addr: SocketAddr) -> String {
    if trust_proxy_headers() {
        if let Some(ip) = forwarded_client_ip(headers) {
            return ip.to_string();
        }
    }
    remote_addr.ip().to_string()
}

fn trust_proxy_headers() -> bool {
    env_flag(&format!("{}_TRUST_PROXY_HEADERS", crate::ENV_PREFIX))
        || env_flag("FRONTPLANE_TRUST_PROXY_HEADERS")
}

fn forwarded_client_ip(headers: &BTreeMap<String, String>) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.split(',').next())
        .and_then(parse_header_ip)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| parse_header_ip(value))
        })
}

fn parse_header_ip(value: &str) -> Option<IpAddr> {
    value
        .trim()
        .trim_matches('"')
        .trim_start_matches("for=")
        .trim_matches('[')
        .trim_matches(']')
        .parse::<IpAddr>()
        .ok()
}

fn rate_limit_for_operation(operation: &str) -> Option<&'static RouteRateLimit> {
    crate::RATE_LIMITS
        .iter()
        .find(|limit| limit.operation == operation)
}

fn prune_rate_limit_buckets(buckets: &mut BTreeMap<String, RateLimitBucket>, now: u128) {
    if buckets.len() < 16_384 {
        return;
    }
    buckets.retain(|_, bucket| now.saturating_sub(bucket.window_start_millis) < 3_600_000);
}

fn bearer_token(headers: &BTreeMap<String, String>) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::to_string)
}

fn auth_has_role(auth: &Value, role: &str) -> bool {
    auth.get("roles")
        .and_then(Value::as_array)
        .map(|roles| roles.iter().any(|value| value.as_str() == Some(role)))
        .unwrap_or(false)
}

fn parse_body(body: &str) -> Value {
    if body.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(body).unwrap_or_else(|_| json!({}))
    }
}

fn parse_body_bytes(body: &[u8]) -> Result<Value, ApiError> {
    if body.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(body)
            .map_err(|_| ApiError::bad_request("request body must be valid JSON"))
    }
}

fn request_input(
    body: Value,
    path: &BTreeMap<String, String>,
    query: &BTreeMap<String, String>,
) -> Value {
    let mut object = body.as_object().cloned().unwrap_or_default();
    for (key, value) in query {
        object.insert(key.clone(), json!(value));
    }
    for (key, value) in path {
        object.insert(key.clone(), json!(value));
    }
    Value::Object(object)
}

fn validate_request_input(
    route: &Route,
    body: &Value,
    query: &BTreeMap<String, String>,
    path: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
    if let Some(object) = body.as_object() {
        for key in path.keys() {
            if object.contains_key(key) {
                return Err(ApiError::bad_request(format!(
                    "field {key} is path-owned and must not be supplied in the request body"
                )));
            }
        }
    }
    for key in query.keys() {
        if path.contains_key(key) {
            return Err(ApiError::bad_request(format!(
                "field {key} is path-owned and must not be supplied as a query parameter"
            )));
        }
    }

    let mut request = match body {
        Value::Object(object) => Value::Object(object.clone()),
        other if query.is_empty() && path.is_empty() => other.clone(),
        _ => {
            return Err(ApiError::bad_request(
                "path and query parameters require an object-shaped request input",
            ));
        }
    };
    if !query.is_empty() || !path.is_empty() {
        let object = request.as_object_mut().ok_or_else(|| {
            ApiError::bad_request("path and query parameters require an object-shaped request input")
        })?;
        for (key, value) in query {
            object.insert(key.clone(), json!(value));
        }
        for (key, value) in path {
            object.insert(key.clone(), json!(value));
        }
    }
    validate_shape(route.input, &request, "input")
}

fn validate_shape(shape: &str, value: &Value, location: &str) -> Result<(), ApiError> {
    let shape = shape.trim();
    if shape.is_empty() || shape == "none" {
        return validate_empty_object(value, location);
    }
    if let Some(inner) = shape
        .strip_prefix('[')
        .and_then(|tail| tail.strip_suffix(']'))
    {
        let array = value.as_array().ok_or_else(|| {
            ApiError::bad_request(format!("{location} must be an array matching {shape}"))
        })?;
        for (idx, item) in array.iter().enumerate() {
            validate_shape(inner, item, &format!("{location}[{idx}]"))?;
        }
        return Ok(());
    }
    if let Some(body) = shape
        .strip_prefix('{')
        .and_then(|tail| tail.strip_suffix('}'))
    {
        return validate_inline_object(body, value, location);
    }
    if let Some(kind) = builtin_shape_kind(shape) {
        return validate_builtin_shape(kind, value, location);
    }
    if let Some(declaration) = crate::STRUCTURES.iter().find(|decl| decl.name == shape) {
        return validate_declared_object(declaration.fields, value, location);
    }
    if shape.contains('<') && shape.ends_with('>') {
        return Ok(());
    }
    Err(ApiError::internal(format!(
        "input shape {shape} is not known to generated validation"
    )))
}

fn validate_empty_object(value: &Value, location: &str) -> Result<(), ApiError> {
    match value.as_object() {
        Some(object) if object.is_empty() => Ok(()),
        Some(_) => Err(ApiError::bad_request(format!(
            "{location} must not include fields"
        ))),
        None => Err(ApiError::bad_request(format!(
            "{location} must be an empty object"
        ))),
    }
}

fn validate_declared_object(
    fields: &[FieldDeclaration],
    value: &Value,
    location: &str,
) -> Result<(), ApiError> {
    let object = value.as_object().ok_or_else(|| {
        ApiError::bad_request(format!(
            "{location} must be an object matching its input shape"
        ))
    })?;
    for key in object.keys() {
        if !fields.iter().any(|field| field.name == key) {
            return Err(ApiError::bad_request(format!(
                "unknown field {location}.{key}"
            )));
        }
    }
    for field in fields {
        match object.get(field.name) {
            Some(field_value) if !field_value.is_null() => {
                validate_shape(
                    field.shape,
                    field_value,
                    &format!("{location}.{}", field.name),
                )?;
            }
            Some(_) if field.required => {
                return Err(ApiError::bad_request(format!(
                    "missing required field {location}.{}",
                    field.name
                )));
            }
            None if field.required => {
                return Err(ApiError::bad_request(format!(
                    "missing required field {location}.{}",
                    field.name
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_inline_object(body: &str, value: &Value, location: &str) -> Result<(), ApiError> {
    let object = value.as_object().ok_or_else(|| {
        ApiError::bad_request(format!(
            "{location} must be an object matching its input shape"
        ))
    })?;
    let fields = parse_inline_fields(body)?;
    for key in object.keys() {
        if !fields.iter().any(|(name, _)| name == key) {
            return Err(ApiError::bad_request(format!(
                "unknown field {location}.{key}"
            )));
        }
    }
    for (name, shape) in fields {
        if let Some(field_value) = object.get(name.as_str()).filter(|value| !value.is_null()) {
            validate_shape(&shape, field_value, &format!("{location}.{name}"))?;
        }
    }
    Ok(())
}

fn parse_inline_fields(body: &str) -> Result<Vec<(String, String)>, ApiError> {
    let mut fields = Vec::new();
    for part in split_top_level(body, ',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, shape) = split_top_level_once_char(part, ':').ok_or_else(|| {
            ApiError::internal(format!("invalid generated inline input field {part}"))
        })?;
        fields.push((name.trim().to_string(), shape.trim().to_string()));
    }
    Ok(fields)
}

fn split_top_level_once_char(input: &str, delimiter: char) -> Option<(&str, &str)> {
    let mut depth = 0_i32;
    let mut quoted = false;
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        match ch {
            '"' => quoted = true,
            '(' | '{' | '[' | '<' => depth += 1,
            ')' | '}' | ']' | '>' => depth -= 1,
            _ if ch == delimiter && depth == 0 => {
                return Some((&input[..idx], &input[idx + ch.len_utf8()..]))
            }
            _ => {}
        }
    }
    None
}

fn builtin_shape_kind(shape: &str) -> Option<&'static str> {
    match shape {
        "String" | "Secret" | "Timestamp" | "Url" => Some("string"),
        "Integer" => Some("integer"),
        "Boolean" => Some("boolean"),
        "Decimal" | "Float" | "Number" => Some("number"),
        "Document" => Some("document"),
        _ => None,
    }
}

fn validate_builtin_shape(kind: &str, value: &Value, location: &str) -> Result<(), ApiError> {
    let valid = match kind {
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "number" => value.is_number(),
        "document" => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!("{location} must be {kind}")))
    }
}

fn split_args(args: &str) -> Vec<String> {
    split_top_level(args, ',')
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn split_top_level(input: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut square = 0_i32;
    let mut paren = 0_i32;
    let mut curly = 0_i32;
    let mut quote = false;
    let mut prev = '\0';
    for (idx, ch) in input.char_indices() {
        match ch {
            '"' if prev != '\\' => quote = !quote,
            '[' if !quote => square += 1,
            ']' if !quote => square -= 1,
            '(' if !quote => paren += 1,
            ')' if !quote => paren -= 1,
            '{' if !quote => curly += 1,
            '}' if !quote => curly -= 1,
            _ => {}
        }
        if ch == delimiter && !quote && square == 0 && paren == 0 && curly == 0 {
            let part = input[start..idx].trim();
            if !part.is_empty() {
                parts.push(part);
            }
            start = idx + ch.len_utf8();
        }
        prev = ch;
    }
    let part = input[start..].trim();
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

fn split_top_level_operator<'a>(expr: &'a str, op: &str) -> Option<Vec<&'a str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    let mut quoted = false;
    let bytes = expr.as_bytes();
    let op_bytes = op.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        match bytes[idx] {
            b'"' => quoted = !quoted,
            b'(' if !quoted => depth += 1,
            b')' if !quoted => depth -= 1,
            _ => {}
        }
        if !quoted && depth == 0 && bytes[idx..].starts_with(op_bytes) {
            parts.push(expr[start..idx].trim());
            idx += op_bytes.len();
            start = idx;
            continue;
        }
        idx += 1;
    }
    if parts.is_empty() {
        None
    } else {
        parts.push(expr[start..].trim());
        Some(parts)
    }
}

fn split_top_level_once<'a>(expr: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    split_top_level_operator(expr, op).and_then(|parts| {
        if parts.len() == 2 {
            Some((parts[0], parts[1]))
        } else {
            None
        }
    })
}

fn trim_outer_parens(mut expr: &str) -> &str {
    loop {
        let trimmed = expr.trim();
        if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
            return trimmed;
        }
        let mut depth = 0_i32;
        let mut quoted = false;
        let mut encloses_all = true;
        for (idx, byte) in trimmed.as_bytes().iter().enumerate() {
            match byte {
                b'"' => quoted = !quoted,
                b'(' if !quoted => depth += 1,
                b')' if !quoted => {
                    depth -= 1;
                    if depth == 0 && idx + 1 != trimmed.len() {
                        encloses_all = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if encloses_all {
            expr = &trimmed[1..trimmed.len() - 1];
        } else {
            return trimmed;
        }
    }
}

pub fn arg_value(args: &[String], index: usize, context: &FlowContext) -> Value {
    args.get(index)
        .map(|arg| resolve_arg(arg, context))
        .unwrap_or(Value::Null)
}

pub fn resolve_arg(arg: &str, context: &FlowContext) -> Value {
    let arg = arg.trim();
    if arg.is_empty() || arg == "none" {
        return Value::Null;
    }
    if let Some(value) = string_literal(arg) {
        return Value::String(value);
    }
    if arg == "input" {
        return context.input.clone();
    }
    if arg == "auth" {
        return context.auth.clone();
    }
    if let Some(value) = context.bindings.get(arg) {
        return value.clone();
    }
    if let Some((head, tail)) = arg.split_once('.') {
        match head {
            "path" => {
                return context
                    .path
                    .get(tail)
                    .map(|value| json!(value))
                    .unwrap_or(Value::Null)
            }
            "query" => {
                return context
                    .query
                    .get(tail)
                    .map(|value| json!(value))
                    .unwrap_or(Value::Null)
            }
            "input" => return nested_value(&context.input, tail).unwrap_or(Value::Null),
            "auth" => return nested_value(&context.auth, tail).unwrap_or(Value::Null),
            binding => {
                if let Some(value) = context
                    .bindings
                    .get(binding)
                    .and_then(|value| nested_value(value, tail))
                {
                    return value;
                }
            }
        }
    }
    lookup_name(arg, context, None)
        .map(Value::String)
        .unwrap_or_else(|| Value::String(arg.to_string()))
}

fn string_literal(term: &str) -> Option<String> {
    term.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .map(|value| value.replace("\\\"", "\""))
}

pub fn lookup_name(name: &str, context: &FlowContext, payload: Option<&Value>) -> Option<String> {
    payload
        .and_then(|value| value.get("_frontplane_path"))
        .and_then(|value| value.get(name))
        .and_then(scalar_string)
        .or_else(|| {
            payload
                .and_then(|value| value.get("_frontplane_path_vars"))
                .and_then(|value| value.get(name))
                .and_then(scalar_string)
        })
        .or_else(|| {
            payload
                .and_then(|value| value.get(name))
                .and_then(scalar_string)
        })
        .or_else(|| context.input.get(name).and_then(scalar_string))
        .or_else(|| context.path.get(name).cloned())
        .or_else(|| context.query.get(name).cloned())
        .or_else(|| {
            context
                .bindings
                .values()
                .find_map(|value| value.get(name).and_then(scalar_string))
        })
}

pub fn nested_value(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current.clone())
}

fn rest_payload(args: &str, context: &FlowContext) -> Option<Value> {
    let args = split_args(args);
    if args.is_empty() || args.iter().all(|arg| arg == "none") {
        return None;
    }
    if args.len() == 1 {
        return Some(resolve_arg(&args[0], context));
    }
    Some(Value::Array(
        args.iter().map(|arg| resolve_arg(arg, context)).collect(),
    ))
}

fn endpoint_url(
    endpoint: &ProviderEndpoint,
    declaration: &CallDeclaration,
    context: &FlowContext,
    payload: Option<&Value>,
) -> Option<String> {
    if (endpoint.fp_call.as_deref() == Some(declaration.name)
        || endpoint.provider == declaration.name)
        && endpoint.base_url.is_none()
    {
        if let Some(url) = &endpoint.url {
            let path = url_path(url);
            if rest_path_matches(declaration.path, path) {
                return Some(url.clone());
            }
        }
    }
    let base = endpoint.base_url.as_ref().or(endpoint.url.as_ref())?;
    let path = render_rest_path(declaration.path, context, payload)?;
    Some(format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    ))
}

fn endpoint_uses_scheme(endpoint: &ProviderEndpoint, scheme: &str) -> bool {
    endpoint
        .base_url
        .as_ref()
        .or(endpoint.url.as_ref())
        .map(|target| target.starts_with(scheme))
        .unwrap_or(false)
}

async fn nats_publish(
    declaration: &CallDeclaration,
    endpoint: &ProviderEndpoint,
    context: &FlowContext,
    payload: Option<&Value>,
) -> Result<Value, ApiError> {
    let target = endpoint
        .base_url
        .as_ref()
        .or(endpoint.url.as_ref())
        .and_then(|value| value.strip_prefix("nats://"))
        .ok_or_else(|| ApiError::provider("NATS endpoint must use nats://"))?;
    let subject = path_variable("subject", context, payload)
        .or_else(|| literal_nats_subject(declaration.path))
        .ok_or_else(|| {
            ApiError::provider(format!(
                "REST call {} must provide NATS subject via payload or literal declaration path",
                declaration.name
            ))
        })?;
    let body = payload
        .map(Value::to_string)
        .unwrap_or_else(|| "{}".to_string());
    let connect_timeout = rest_timeout("CONNECT", 5_000);
    let read_timeout = rest_timeout("READ", 15_000);
    let write_timeout = rest_timeout("WRITE", 5_000);
    let mut stream = connect_with_timeout(target, connect_timeout, declaration.name).await?;
    let mut greeting = [0_u8; 512];
    let _ = timeout(read_timeout, stream.read(&mut greeting)).await;
    let mut connect_options = json!({"verbose": false, "pedantic": false});
    if !declaration.auth.is_empty() && declaration.auth != "none" {
        let token = auth_value(declaration.auth, payload).ok_or_else(|| {
            ApiError::provider(format!(
                "REST call {} requires auth material for {}",
                declaration.name, declaration.auth
            ))
        })?;
        reject_known_insecure_secret_value(&token, declaration.auth)?;
        connect_options["auth_token"] = json!(token);
    }
    let frame = format!(
        "CONNECT {}\r\nPUB {} {}\r\n{}\r\nPING\r\n",
        connect_options,
        subject,
        body.len(),
        body
    );
    timeout(write_timeout, stream.write_all(frame.as_bytes()))
        .await
        .map_err(|_| ApiError::provider(format!("NATS publish failed to write request within {}ms", write_timeout.as_millis())))?
        .map_err(|err| {
            eprintln!(
                "frontplane provider error: NATS publish transport failure for {}; internal error suppressed from facade client: {err}",
                declaration.name
            );
            ApiError::provider(format!(
                "REST call {} failed while publishing to internal service",
                declaration.name
            ))
        })?;
    let mut response_buf = [0_u8; 512];
    let response_len = timeout(read_timeout, stream.read(&mut response_buf))
        .await
        .map_err(|_| ApiError::provider(format!("NATS publish ack failed within {}ms", read_timeout.as_millis())))?
        .map_err(|err| {
            eprintln!(
                "frontplane provider error: NATS publish ack failure for {}; internal error suppressed from facade client: {err}",
                declaration.name
            );
            ApiError::provider(format!(
                "REST call {} failed while reading internal service ack",
                declaration.name
            ))
        })?;
    let response = String::from_utf8_lossy(&response_buf[..response_len]);
    if response.contains("-ERR") {
        eprintln!(
            "frontplane provider error: NATS publish for {} returned provider error; response body suppressed from facade client ({} bytes)",
            declaration.name,
            response.len()
        );
        return Err(ApiError::provider(format!(
            "REST call {} failed while publishing to internal service",
            declaration.name
        )));
    }
    if !response.contains("PONG") {
        return Err(ApiError::provider("NATS publish did not acknowledge PING"));
    }
    Ok(json!({
        "provider": declaration.name.split_once('.').map(|(module, _)| module).unwrap_or(declaration.name),
        "call": declaration.name,
        "state": "ready",
        "configured": true,
        "detail": "NATS publish succeeded",
        "subject": subject,
        "checked_at": now()
    }))
}

fn url_path(url: &str) -> &str {
    url.strip_prefix("http://")
        .and_then(|rest| rest.split_once('/').map(|(_, path)| path))
        .map(|path| {
            let path = path.split('?').next().unwrap_or(path);
            if path.is_empty() {
                "/"
            } else {
                path
            }
        })
        .unwrap_or("/")
}

fn render_rest_path(
    template: &str,
    context: &FlowContext,
    payload: Option<&Value>,
) -> Option<String> {
    let mut output = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let end = rest[start + 1..].find('}')? + start + 1;
        output.push_str(&rest[..start]);
        let name = &rest[start + 1..end];
        output.push_str(&url_encode(&path_variable(name, context, payload)?));
        rest = &rest[end + 1..];
    }
    output.push_str(rest);
    Some(output)
}

fn path_variable(name: &str, context: &FlowContext, payload: Option<&Value>) -> Option<String> {
    lookup_name(name, context, payload)
}

fn literal_nats_subject(path: &str) -> Option<String> {
    path.trim_matches('/')
        .strip_prefix("v1/pub/")
        .filter(|subject| !subject.contains('{') && !subject.is_empty())
        .map(str::to_string)
}

fn rest_result(
    declaration: &CallDeclaration,
    state: &str,
    configured: bool,
    detail: &str,
    body: Value,
) -> Value {
    json!({
        "provider": declaration.name.split_once('.').map(|(module, _)| module).unwrap_or(declaration.name),
        "call": declaration.name,
        "state": state,
        "configured": configured,
        "detail": detail,
        "response": body,
        "checked_at": now()
    })
}

fn url_authority(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

async fn http_json(
    client: &reqwest::Client,
    declaration: &CallDeclaration,
    endpoint: &ProviderEndpoint,
    url: &str,
    body: Option<&Value>,
    flow_call_kind: &str,
) -> Result<Value, ApiError> {
    let parsed_url = reqwest::Url::parse(url).map_err(|err| {
        ApiError::provider(format!(
            "REST call {} has invalid URL {url}: {err}",
            declaration.name
        ))
    })?;
    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        return Err(ApiError::provider(format!(
            "REST call {} uses unsupported URL scheme {}",
            declaration.name,
            parsed_url.scheme()
        )));
    }
    let authority = url_authority(&parsed_url).ok_or_else(|| {
        ApiError::provider(format!(
            "REST call {} URL {url} has no host",
            declaration.name
        ))
    })?;
    let mut request_path = parsed_url.path().to_string();
    if request_path.is_empty() {
        request_path.push('/');
    }
    if let Some(query) = parsed_url.query() {
        request_path.push('?');
        request_path.push_str(query);
    }
    if declaration.auth == "guacamole-token" {
        if let Some(token) = auth_value("guacamole-token", body) {
            let mut first = !request_path.contains('?');
            append_query_param(&mut request_path, &mut first, "token", &token);
        }
    }
    if let Some(query) = body.and_then(|value| value.get("_frontplane_query")) {
        append_query_params(&mut request_path, query);
    }
    if declaration.method == "GET" {
        if let Some(body) = body {
            append_query_params(&mut request_path, body);
        }
    }
    let actual_path = request_path
        .split('?')
        .next()
        .unwrap_or(request_path.as_str());
    if !rest_path_matches(declaration.path, actual_path) {
        return Err(ApiError::provider(format!(
            "configured URL path {actual_path} does not match FP REST declaration {} {}",
            declaration.method, declaration.path
        )));
    }
    let send_body = body.is_some() && declaration.method != "GET";
    let (payload, content_type) = if send_body {
        encode_request_body(body.expect("checked by send_body"))
    } else {
        (String::new(), "")
    };
    let host_header = endpoint
        .host_header
        .as_deref()
        .unwrap_or(authority.as_str());
    let request_url = format!("{}://{}{}", parsed_url.scheme(), authority, request_path);
    let method = reqwest::Method::from_bytes(declaration.method.as_bytes()).map_err(|err| {
        ApiError::provider(format!(
            "REST call {} has invalid method {}: {err}",
            declaration.name, declaration.method
        ))
    })?;
    let mut request = client.request(method, &request_url);
    if endpoint.host_header.is_some() {
        request = request.header(reqwest::header::HOST, host_header);
    }
    for (name, value) in auth_headers(declaration, &request_path, host_header, &payload, body)? {
        request = request.header(name, value);
    }
    if send_body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(payload.clone());
    }

    let connect_timeout = rest_timeout("CONNECT", 5_000);
    let read_timeout = rest_timeout("READ", 15_000);
    let write_timeout = rest_timeout("WRITE", 5_000);
    let send_timeout = connect_timeout + write_timeout + read_timeout;
    let response = timeout(send_timeout, request.send())
        .await
        .map_err(|_| {
            ApiError::provider(format!(
                "REST call {} failed to send request within {}ms",
                declaration.name,
                send_timeout.as_millis()
            ))
        })?
        .map_err(|err| {
            ApiError::provider(format!(
                "REST call {} failed to send request: {err}",
                declaration.name
            ))
        })?;
    let status = response.status().as_u16();
    let body_text = timeout(read_timeout, response.text())
        .await
        .map_err(|_| {
            ApiError::provider(format!(
                "REST call {} failed to read response within {}ms",
                declaration.name,
                read_timeout.as_millis()
            ))
        })?
        .map_err(|err| {
            ApiError::provider(format!(
                "REST call {} failed to read response within {}ms: {err}",
                declaration.name,
                read_timeout.as_millis()
            ))
        })?;
    let value = serde_json::from_str(&body_text).unwrap_or_else(|_| json!({}));
    if (200..300).contains(&status) {
        return Ok(value);
    }
    if flow_call_kind == "Acall" && status == 401 {
        log_provider_response_body_suppressed(declaration, status, &body_text);
        return Err(ApiError::unauthorized("auth provider returned HTTP 401"));
    }
    if flow_call_kind == "Acall" && status == 403 {
        log_provider_response_body_suppressed(declaration, status, &body_text);
        return Err(ApiError::forbidden("auth provider returned HTTP 403"));
    }
    if flow_call_kind == "Ncall" && matches!(status, 401 | 403) {
        eprintln!(
            "frontplane warning: Ncall {} returned HTTP {}; authn/authz provider checks should be modeled with Acall/authz",
            declaration.name,
            status
        );
    }
    log_provider_response_body_suppressed(declaration, status, &body_text);
    let provider_message = sanitized_provider_status_message(declaration, status);
    match status {
        400 => return Err(ApiError::bad_request(provider_message)),
        404 => return Err(ApiError::not_found(provider_message)),
        409 => return Err(ApiError::conflict(provider_message)),
        _ => {}
    }
    Err(ApiError::provider(provider_message))
}

fn sanitized_provider_status_message(declaration: &CallDeclaration, status: u16) -> String {
    format!(
        "REST call {} returned HTTP {}; provider response body suppressed",
        declaration.name, status
    )
}

fn log_provider_response_body_suppressed(
    declaration: &CallDeclaration,
    status: u16,
    body_text: &str,
) {
    if body_text.is_empty() {
        return;
    }
    eprintln!(
        "frontplane provider error: REST call {} returned HTTP {}; provider response body suppressed from facade client ({} bytes)",
        declaration.name,
        status,
        body_text.len()
    );
}

async fn connect_with_timeout(
    authority: &str,
    timeout_duration: Duration,
    call_name: &str,
) -> Result<TcpStream, ApiError> {
    timeout(timeout_duration, TcpStream::connect(authority))
        .await
        .map_err(|_| {
            ApiError::provider(format!(
                "REST call {call_name} failed to connect to {authority} within {}ms",
                timeout_duration.as_millis()
            ))
        })?
        .map_err(|err| {
            ApiError::provider(format!(
                "REST call {call_name} failed to connect to {authority} within {}ms: {err}",
                timeout_duration.as_millis()
            ))
        })
}

fn rest_timeout(kind: &str, default_ms: u64) -> Duration {
    let prefixed = format!("{}_REST_{}_TIMEOUT_MS", crate::ENV_PREFIX, kind);
    let generic = format!("FRONTPLANE_REST_{}_TIMEOUT_MS", kind);
    env::var(prefixed)
        .or_else(|_| env::var(generic))
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|millis| *millis > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(default_ms))
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn encode_request_body(value: &Value) -> (String, &'static str) {
    let Some(object) = value.as_object() else {
        return (value.to_string(), "application/json");
    };
    let content_type = object
        .get("_frontplane_content_type")
        .and_then(Value::as_str)
        .unwrap_or("application/json");
    if content_type == "application/x-www-form-urlencoded" {
        let form = object
            .get("_frontplane_form")
            .and_then(Value::as_object)
            .unwrap_or(object);
        let payload = form
            .iter()
            .filter(|(key, _)| !key.starts_with("_frontplane_"))
            .filter_map(|(key, value)| scalar_string(value).map(|value| (key, value)))
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(&value)))
            .collect::<Vec<_>>()
            .join("&");
        return (payload, "application/x-www-form-urlencoded");
    }
    let body = object.get("_frontplane_body").cloned().unwrap_or_else(|| {
        let mut cleaned = object.clone();
        cleaned.retain(|key, _| !key.starts_with("_frontplane_"));
        Value::Object(cleaned)
    });
    if content_type == "application/activity+json" {
        (body.to_string(), "application/activity+json")
    } else {
        (body.to_string(), "application/json")
    }
}

fn append_query_params(path: &mut String, value: &Value) {
    let Some(object) = value.as_object() else {
        return;
    };
    let mut first = !path.contains('?');
    for (key, value) in object {
        if key.starts_with("_frontplane_") {
            continue;
        }
        match value {
            Value::String(text) => append_query_param(path, &mut first, key, text),
            Value::Number(number) => append_query_param(path, &mut first, key, &number.to_string()),
            Value::Bool(flag) => {
                append_query_param(path, &mut first, key, if *flag { "true" } else { "false" })
            }
            Value::Array(items) => {
                for item in items {
                    if let Some(text) = scalar_string(item) {
                        append_query_param(path, &mut first, key, &text);
                    }
                }
            }
            _ => {}
        }
    }
}

fn append_query_param(path: &mut String, first: &mut bool, key: &str, value: &str) {
    if *first {
        path.push('?');
        *first = false;
    } else {
        path.push('&');
    }
    path.push_str(&url_encode(key));
    path.push('=');
    path.push_str(&url_encode(value));
}

fn auth_headers(
    declaration: &CallDeclaration,
    request_path: &str,
    host_header: &str,
    payload: &str,
    payload_value: Option<&Value>,
) -> Result<Vec<(&'static str, String)>, ApiError> {
    let auth = declaration.auth;
    if auth.is_empty() || auth == "none" {
        return Ok(Vec::new());
    }
    if auth == "s3-signature" {
        return s3_signature_headers(
            declaration,
            request_path,
            host_header,
            payload,
            payload_value,
        );
    }
    if auth == "http-signature" {
        return http_signature_headers(
            declaration,
            request_path,
            host_header,
            payload,
            payload_value,
        );
    }
    if auth == "guacamole-token" {
        return Ok(Vec::new());
    }
    let value = auth_value(auth, payload_value).ok_or_else(|| {
        ApiError::provider(format!(
            "REST call {} requires auth material for {auth}",
            declaration.name
        ))
    })?;
    reject_known_insecure_secret_value(&value, auth)?;
    if auth == "apisix-admin" {
        Ok(vec![("x-api-key", value)])
    } else if auth == "openbao-token" {
        Ok(vec![("x-vault-token", value)])
    } else {
        Ok(vec![(
            "authorization",
            normalize_authorization_value(&value),
        )])
    }
}

fn auth_value(auth: &str, payload: Option<&Value>) -> Option<String> {
    payload
        .and_then(|value| value_str(value, "_frontplane_auth_token"))
        .or_else(|| {
            crate::AUTH_ENV_VARS
                .iter()
                .find(|(name, _)| *name == auth)
                .and_then(|(_, envs)| envs.iter().find_map(|env_name| env::var(env_name).ok()))
        })
        .or_else(|| payload.and_then(|value| value_str(value, "token")))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn s3_signature_headers(
    declaration: &CallDeclaration,
    request_path: &str,
    host_header: &str,
    payload: &str,
    payload_value: Option<&Value>,
) -> Result<Vec<(&'static str, String)>, ApiError> {
    let provider = provider_name(declaration.name);
    let access_key = credential_value(provider, "ACCESS_KEY", payload_value, "access_key")
        .ok_or_else(|| {
            ApiError::provider(format!(
                "REST call {} requires S3 access key material",
                declaration.name
            ))
        })?;
    let secret_key = credential_value(provider, "SECRET_KEY", payload_value, "secret_key")
        .ok_or_else(|| {
            ApiError::provider(format!(
                "REST call {} requires S3 secret key material",
                declaration.name
            ))
        })?;
    reject_known_insecure_secret_value(&secret_key, "S3 secret key")?;
    let region = env::var(format!("{}_S3_REGION", crate::ENV_PREFIX))
        .or_else(|_| env::var("FRONTPLANE_S3_REGION"))
        .unwrap_or_else(|_| "us-east-1".to_string());
    let service = env::var(format!("{}_S3_SERVICE", crate::ENV_PREFIX))
        .or_else(|_| env::var("FRONTPLANE_S3_SERVICE"))
        .unwrap_or_else(|_| "s3".to_string());
    let (amz_date, date_stamp) = sigv4_timestamp();
    let payload_hash = sha256_hex(payload.as_bytes());
    let (canonical_uri, canonical_query) = canonical_path_and_query(request_path);
    let canonical_headers =
        format!("host:{host_header}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        declaration.method,
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signing_key = sigv4_signing_key(&secret_key, &date_stamp, &region, &service);
    let signature = hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );
    Ok(vec![
        ("x-amz-content-sha256", payload_hash),
        ("x-amz-date", amz_date),
        ("authorization", authorization),
    ])
}

fn http_signature_headers(
    declaration: &CallDeclaration,
    request_path: &str,
    host_header: &str,
    payload: &str,
    payload_value: Option<&Value>,
) -> Result<Vec<(&'static str, String)>, ApiError> {
    #[cfg(feature = "http_signature_rsa")]
    if let Some(headers) = rsa_http_signature_headers(
        declaration,
        request_path,
        host_header,
        payload,
        payload_value,
    ) {
        return Ok(headers);
    }

    let provider = provider_name(declaration.name);
    let key_id = credential_value(provider, "HTTP_SIGNATURE_KEY_ID", payload_value, "key_id")
        .unwrap_or_else(|| format!("frontplane-{provider}"));
    let secret = credential_value(provider, "HTTP_SIGNATURE_SECRET", payload_value, "secret")
        .or_else(|| auth_value("http-signature", payload_value))
        .ok_or_else(|| {
            ApiError::provider(format!(
                "REST call {} requires HTTP signature key material",
                declaration.name
            ))
        })?;
    reject_known_insecure_secret_value(&secret, "HTTP signature secret")?;
    let date = http_date();
    let digest = format!(
        "SHA-256={}",
        base64_standard(&sha256_bytes(payload.as_bytes()))
    );
    let signature_input = format!(
        "(request-target): {} {}\nhost: {}\ndate: {}\ndigest: {}",
        declaration.method.to_ascii_lowercase(),
        request_path,
        host_header,
        date,
        digest
    );
    let signature = base64_standard(&hmac_sha256(secret.as_bytes(), signature_input.as_bytes()));
    let header = format!(
        "keyId=\"{key_id}\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date digest\",signature=\"{signature}\""
    );
    Ok(vec![
        ("date", date),
        ("digest", digest),
        ("signature", header),
    ])
}

#[cfg(feature = "http_signature_rsa")]
fn rsa_http_signature_headers(
    declaration: &CallDeclaration,
    request_path: &str,
    host_header: &str,
    payload: &str,
    payload_value: Option<&Value>,
) -> Option<Vec<(&'static str, String)>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use rsa::pkcs1v15::SigningKey;
    use rsa::rand_core::OsRng;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::{BigUint, RsaPrivateKey};
    use sha2::Sha256;

    let provider = provider_name(declaration.name);
    let key_id = credential_value(provider, "HTTP_SIGNATURE_KEY_ID", payload_value, "key_id")
        .unwrap_or_else(|| format!("frontplane-{provider}"));
    let key_json = credential_value(
        provider,
        "HTTP_SIGNATURE_PRIVATE_KEY_JSON_B64",
        payload_value,
        "private_key_json_b64",
    )
    .and_then(|encoded| STANDARD.decode(encoded).ok())
    .and_then(|bytes| String::from_utf8(bytes).ok())
    .or_else(|| {
        credential_value(
            provider,
            "HTTP_SIGNATURE_PRIVATE_KEY_JSON",
            payload_value,
            "private_key_json",
        )
    })?;
    let key_value = serde_json::from_str::<Value>(&key_json).ok()?;
    let component = |name: &str| -> Option<BigUint> {
        let value = key_value.get(name)?;
        let text = value
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| value.to_string());
        BigUint::parse_bytes(text.trim_matches('"').as_bytes(), 10)
    };
    let n = component("N")?;
    let e = component("E")?;
    let d = component("D")?;
    let primes = key_value
        .get("Primes")?
        .as_array()?
        .iter()
        .filter_map(|value| {
            let text = value
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| value.to_string());
            BigUint::parse_bytes(text.trim_matches('"').as_bytes(), 10)
        })
        .collect::<Vec<_>>();
    if primes.len() < 2 {
        return None;
    }

    let private_key = RsaPrivateKey::from_components(n, e, d, primes).ok()?;
    let date = http_date();
    let digest = format!(
        "SHA-256={}",
        base64_standard(&sha256_bytes(payload.as_bytes()))
    );
    let signature_input = format!(
        "(request-target): {} {}\nhost: {}\ndate: {}\ndigest: {}",
        declaration.method.to_ascii_lowercase(),
        request_path,
        host_header,
        date,
        digest
    );
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(&mut OsRng, signature_input.as_bytes());
    let signature = base64_standard(&signature.to_vec());
    let header = format!(
        "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{signature}\""
    );
    Some(vec![
        ("date", date),
        ("digest", digest),
        ("signature", header),
    ])
}

fn credential_value(
    provider: &str,
    suffix: &str,
    payload: Option<&Value>,
    payload_field: &str,
) -> Option<String> {
    let provider_token = env_token_runtime(provider);
    [
        format!("{}_{}_{}", crate::ENV_PREFIX, provider_token, suffix),
        format!("{}_{}", crate::ENV_PREFIX, suffix),
        format!("FRONTPLANE_{}", suffix),
    ]
    .into_iter()
    .find_map(|name| env::var(name).ok())
    .or_else(|| payload.and_then(|value| value_str(value, payload_field)))
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

fn canonical_path_and_query(request_path: &str) -> (String, String) {
    let (path, query) = request_path.split_once('?').unwrap_or((request_path, ""));
    let canonical_query = if query.is_empty() {
        String::new()
    } else {
        let mut parts = query.split('&').collect::<Vec<_>>();
        parts.sort_unstable();
        parts.join("&")
    };
    (path.to_string(), canonical_query)
}

fn sigv4_signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut normalized_key = if key.len() > 64 {
        sha256_bytes(key).to_vec()
    } else {
        key.to_vec()
    };
    normalized_key.resize(64, 0);
    let mut outer = [0x5c_u8; 64];
    let mut inner = [0x36_u8; 64];
    for (index, byte) in normalized_key.iter().enumerate() {
        outer[index] ^= byte;
        inner[index] ^= byte;
    }
    let mut inner_data = Vec::with_capacity(64 + data.len());
    inner_data.extend_from_slice(&inner);
    inner_data.extend_from_slice(data);
    let inner_hash = sha256_bytes(&inner_data);
    let mut outer_data = Vec::with_capacity(96);
    outer_data.extend_from_slice(&outer);
    outer_data.extend_from_slice(&inner_hash);
    sha256_bytes(&outer_data).to_vec()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(sha256_bytes(bytes))
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for index in 0..16 {
            let offset = index * 4;
            w[index] = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0_u8; 32];
    for (index, word) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn base64_standard(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    let mut index = 0;
    while index < bytes.len() {
        let b0 = bytes[index];
        let b1 = bytes.get(index + 1).copied().unwrap_or(0);
        let b2 = bytes.get(index + 2).copied().unwrap_or(0);
        output.push(TABLE[(b0 >> 2) as usize] as char);
        output.push(TABLE[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if index + 1 < bytes.len() {
            output.push(TABLE[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if index + 2 < bytes.len() {
            output.push(TABLE[(b2 & 0b0011_1111) as usize] as char);
        } else {
            output.push('=');
        }
        index += 3;
    }
    output
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sigv4_timestamp() -> (String, String) {
    let seconds = now_u64();
    let (year, month, day, hour, minute, second, _) = utc_parts(seconds);
    (
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
        format!("{year:04}{month:02}{day:02}"),
    )
}

fn http_date() -> String {
    let seconds = now_u64();
    let (year, month, day, hour, minute, second, weekday) = utc_parts(seconds);
    let weekdays = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let months = [
        "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {day:02} {} {year:04} {hour:02}:{minute:02}:{second:02} GMT",
        weekdays[weekday as usize], months[month as usize],
    )
}

fn utc_parts(seconds: u64) -> (i32, u32, u32, u32, u32, u32, u32) {
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = (seconds_of_day / 3_600) as u32;
    let minute = ((seconds_of_day % 3_600) / 60) as u32;
    let second = (seconds_of_day % 60) as u32;
    let weekday = ((days + 4).rem_euclid(7)) as u32;
    (year, month, day, hour, minute, second, weekday)
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn provider_name(call_name: &str) -> &str {
    call_name
        .split_once('.')
        .map(|(provider, _)| provider)
        .unwrap_or(call_name)
}

fn env_token_runtime(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn normalize_authorization_value(value: &str) -> String {
    if value.starts_with("Bearer ") || value.starts_with("Basic ") || value.starts_with("Token ") {
        value.to_string()
    } else {
        format!("Bearer {value}")
    }
}

fn rest_path_matches(template: &str, path: &str) -> bool {
    match_template(template, path).is_some()
}

fn respond(status: u16, body: &Value) -> Response {
    let payload = body.to_string();
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(payload))
        .unwrap_or_else(|_| Response::new(Body::from("{}")))
}

async fn check_health(addr: &str) -> std::io::Result<()> {
    let declaration = CallDeclaration {
        name: "Frontplane.healthcheck",
        kind: "rest",
        method: "GET",
        path: "/healthz",
        auth: "none",
    };
    let endpoint = ProviderEndpoint {
        provider: "Frontplane".to_string(),
        package: "Frontplane".to_string(),
        purpose: "healthcheck".to_string(),
        url: None,
        base_url: Some(format!("http://{addr}")),
        host_header: None,
        fp_call: None,
    };
    let client = reqwest::Client::builder()
        .connect_timeout(rest_timeout("CONNECT", 5_000))
        .read_timeout(rest_timeout("READ", 15_000))
        .user_agent("frontplane-rust-facade/1.0")
        .build()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
    http_json(
        &client,
        &declaration,
        &endpoint,
        &format!("http://{addr}/healthz"),
        None,
        "Ncall",
    )
    .await
    .map(|_| ())
    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.message))
}

fn envelope(operation: &str, mut body: Value, flow: FlowResult) -> Value {
    if let Value::Object(ref mut object) = body {
        object.insert(
            "_frontplane".to_string(),
            json!({
                "operation": operation,
                "facade": service_name(),
                "facade_kind": "rest",
                "runtime_language": "rust",
                "flow_steps": flow.steps,
                "call_count": flow.calls,
                "rest_call_count": flow.rest_calls,
                "provider_call_count": flow.provider_calls
            }),
        );
    }
    body
}

pub fn page(items: Vec<Value>) -> Value {
    json!({"items": items, "next_cursor": Value::Null})
}

pub fn provider_response(value: &Value) -> &Value {
    value.get("response").unwrap_or(value)
}

pub fn provider_items(value: &Value) -> Vec<Value> {
    let response = provider_response(value);
    response
        .get("items")
        .or_else(|| response.get("hits").and_then(|hits| hits.get("hits")))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| item.get("_source").cloned().unwrap_or_else(|| item.clone()))
                .collect()
        })
        .or_else(|| response.as_array().cloned())
        .unwrap_or_default()
}

pub fn first_string(input: &Value, fields: &[&str]) -> Option<String> {
    for field in fields {
        if let Some(value) = input.get(*field).and_then(scalar_string) {
            return Some(value);
        }
    }
    None
}

pub fn value_str(input: &Value, key: &str) -> Option<String> {
    input.get(key).and_then(Value::as_str).map(str::to_string)
}

pub fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub fn string_array_field(input: &Value, field: &str) -> Vec<String> {
    input.get(field).map(string_array).unwrap_or_default()
}

pub fn string_array(input: &Value) -> Vec<String> {
    input
        .as_array()
        .map(|values| values.iter().filter_map(scalar_string).collect())
        .unwrap_or_default()
}

pub fn inferred_resource_type(resource: &Value) -> String {
    if resource.get("access_request_id").is_some() || resource.get("purpose").is_some() {
        "access_request".to_string()
    } else if resource.get("console_session_id").is_some() || resource.get("console_url").is_some()
    {
        "console_session".to_string()
    } else if resource.get("lease_id").is_some() || resource.get("lease_duration").is_some() {
        "credential_lease".to_string()
    } else if resource.get("session_id").is_some() || resource.get("expires_at").is_some() {
        "session".to_string()
    } else if resource.get("evidence_id").is_some() || resource.get("evidence_uri").is_some() {
        "evidence".to_string()
    } else if resource.get("target_id").is_some() || resource.get("hostname").is_some() {
        "target".to_string()
    } else {
        "production_access_resource".to_string()
    }
}

fn url_decode(value: &str) -> String {
    let mut out = String::new();
    let mut bytes = value.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => out.push(' '),
            b'%' => {
                let hi = bytes.next();
                let lo = bytes.next();
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    let hex = [hi, lo];
                    if let Ok(hex) = std::str::from_utf8(&hex) {
                        if let Ok(decoded) = u8::from_str_radix(hex, 16) {
                            out.push(decoded as char);
                            continue;
                        }
                    }
                }
                out.push('%');
            }
            _ => out.push(byte as char),
        }
    }
    out
}

fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub fn now() -> String {
    format!("{}", now_u64())
}

pub fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

pub fn now_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn provider_purpose(provider: &str) -> &'static str {
    crate::PROVIDER_PURPOSES
        .iter()
        .find_map(|(name, purpose)| (*name == provider).then_some(*purpose))
        .unwrap_or("provider")
}

fn default_provider_endpoints() -> Vec<ProviderEndpoint> {
    crate::DEFAULT_PROVIDER_LIST
        .iter()
        .map(|provider| ProviderEndpoint {
            provider: (*provider).to_string(),
            package: (*provider).to_string(),
            purpose: provider_purpose(provider).to_string(),
            url: None,
            base_url: None,
            host_header: None,
            fp_call: None,
        })
        .collect()
}
fn configured_endpoint(name: &str, value: &Value) -> ProviderEndpoint {
    let module = name
        .split_once('.')
        .map(|(module, _)| module)
        .unwrap_or(name);
    let provider = if name.contains('.') {
        name.to_string()
    } else {
        value
            .get("provider")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string()
    };
    ProviderEndpoint {
        provider,
        package: module.to_string(),
        purpose: provider_purpose(module).to_string(),
        url: value.get("url").and_then(Value::as_str).map(str::to_string),
        base_url: value
            .get("base_url")
            .or_else(|| value.get("baseUrl"))
            .and_then(Value::as_str)
            .map(str::to_string),
        host_header: value
            .get("host_header")
            .or_else(|| value.get("hostHeader"))
            .and_then(Value::as_str)
            .map(str::to_string),
        fp_call: value
            .get("fp_call")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| name.contains('.').then(|| name.to_string())),
    }
}

impl ApiError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, "BadRequestError", message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(401, "UnauthorizedError", message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(403, "ForbiddenError", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, "NotFoundError", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, "ConflictError", message)
    }

    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(429, "RateLimitError", message)
    }

    pub fn provider(message: impl Into<String>) -> Self {
        Self::new(502, "ProviderError", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "ProviderError", message)
    }
}

#[cfg(feature = "frontplane_security")]
#[derive(Clone)]
pub struct FrontplaneTokenToolkit {
    issuer: String,
    audience: String,
    ttl_seconds: u64,
    active_signing_kid: String,
    keys: BTreeMap<String, FrontplaneTokenKey>,
    revoked_jtis: BTreeSet<String>,
}

#[cfg(feature = "frontplane_security")]
#[derive(Clone)]
struct FrontplaneTokenKey {
    alg: String,
    status: String,
    secret: Vec<u8>,
}

#[cfg(feature = "frontplane_security")]
impl FrontplaneTokenToolkit {
    pub fn from_env(
        env_prefix: &str,
        default_issuer: &str,
        default_audience: &str,
    ) -> Result<Self, ApiError> {
        if let Some(registry) = registry_json_from_env(env_prefix, "TOKEN")? {
            let mut toolkit =
                Self::from_registry_value(&registry, default_issuer, default_audience)?;
            toolkit
                .revoked_jtis
                .extend(token_revocation_set_from_env(env_prefix)?);
            return Ok(toolkit);
        }
        let secret = read_named_secret_from_env_or_file(env_prefix, "TOKEN_SECRET")?;
        let kid = env_string(env_prefix, "TOKEN_ACTIVE_KID")
            .or_else(|| env::var("FRONTPLANE_TOKEN_ACTIVE_KID").ok())
            .unwrap_or_else(|| "tok".to_string());
        let issuer = env_string(env_prefix, "TOKEN_ISSUER")
            .or_else(|| env::var("FRONTPLANE_TOKEN_ISSUER").ok())
            .unwrap_or_else(|| default_issuer.to_string());
        let audience = env_string(env_prefix, "TOKEN_AUDIENCE")
            .or_else(|| env::var("FRONTPLANE_TOKEN_AUDIENCE").ok())
            .unwrap_or_else(|| default_audience.to_string());
        let ttl_seconds = env_string(env_prefix, "TOKEN_TTL_SECONDS")
            .or_else(|| env::var("FRONTPLANE_TOKEN_TTL_SECONDS").ok())
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(3600);
        let mut keys = BTreeMap::new();
        keys.insert(
            kid.clone(),
            FrontplaneTokenKey {
                alg: "HS256".to_string(),
                status: "active".to_string(),
                secret,
            },
        );
        Ok(Self {
            issuer,
            audience,
            ttl_seconds,
            active_signing_kid: kid,
            keys,
            revoked_jtis: token_revocation_set_from_env(env_prefix)?,
        })
    }

    pub fn from_registry_value(
        value: &Value,
        default_issuer: &str,
        default_audience: &str,
    ) -> Result<Self, ApiError> {
        let token_config = value
            .get("token_keys")
            .or_else(|| value.get("tokens"))
            .unwrap_or(value);
        let issuer =
            value_string(token_config, "issuer").unwrap_or_else(|| default_issuer.to_string());
        let audience =
            value_string(token_config, "audience").unwrap_or_else(|| default_audience.to_string());
        let ttl_seconds = token_config
            .get("ttl_seconds")
            .or_else(|| token_config.get("ttlSeconds"))
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .unwrap_or(3600);
        let active_signing_kid = value_string(token_config, "active_signing_kid")
            .or_else(|| value_string(token_config, "activeSigningKid"))
            .ok_or_else(|| ApiError::internal("token registry missing active_signing_kid"))?;
        let keys_value = token_config
            .get("keys")
            .and_then(Value::as_object)
            .ok_or_else(|| ApiError::internal("token registry missing keys"))?;
        let mut keys = BTreeMap::new();
        for (kid, key_value) in keys_value {
            let alg = value_string(key_value, "alg").unwrap_or_else(|| "HS256".to_string());
            if alg != "HS256" {
                return Err(ApiError::internal(format!(
                    "token key {kid} uses unsupported algorithm {alg}"
                )));
            }
            let status =
                value_string(key_value, "status").unwrap_or_else(|| "verify_only".to_string());
            if !matches!(status.as_str(), "active" | "verify_only") {
                return Err(ApiError::internal(format!(
                    "token key {kid} has unsupported status {status}"
                )));
            }
            let secret = secret_bytes_from_value(key_value, true, "token signing key")?;
            if secret.len() < 32 {
                return Err(ApiError::internal(format!(
                    "token key {kid} must be at least 32 bytes"
                )));
            }
            keys.insert(
                kid.clone(),
                FrontplaneTokenKey {
                    alg,
                    status,
                    secret,
                },
            );
        }
        let active_key = keys.get(&active_signing_kid).ok_or_else(|| {
            ApiError::internal("token registry active_signing_kid is not in keys")
        })?;
        if active_key.status != "active" {
            return Err(ApiError::internal(
                "token registry active signing key must have active status",
            ));
        }
        Ok(Self {
            issuer,
            audience,
            ttl_seconds,
            active_signing_kid,
            keys,
            revoked_jtis: revoked_jtis_from_value(token_config)?,
        })
    }

    pub fn issue(&self, principal: &Value) -> Result<Value, ApiError> {
        let handle = required_string_field(principal, "handle", "authenticated principal")?;
        let subject_id = required_string_field(principal, "subject_id", "authenticated principal")?;
        let account_id = required_string_field(principal, "account_id", "authenticated principal")?;
        let roles = string_array_field(principal, "roles");
        if roles.is_empty() {
            return Err(ApiError::unauthorized(
                "authenticated principal has no roles",
            ));
        }
        let key = self
            .keys
            .get(&self.active_signing_kid)
            .ok_or_else(|| ApiError::internal("token active signing key missing"))?;
        if key.status != "active" {
            return Err(ApiError::internal("token active signing key is not active"));
        }
        let issued_at = now_u64();
        let expires_at = issued_at.saturating_add(self.ttl_seconds);
        let token_id = secure_random_b64url(16)?;
        let header = json!({
            "alg": key.alg,
            "typ": "JWT",
            "kid": self.active_signing_kid
        });
        let payload = json!({
            "iss": self.issuer,
            "aud": self.audience,
            "sub": subject_id,
            "handle": handle,
            "account_id": account_id,
            "roles": roles,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": expires_at,
            "jti": token_id
        });
        let token = sign_frontplane_token(&header, &payload, &key.secret)?;
        Ok(json!({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": self.ttl_seconds,
            "handle": handle,
            "subject_id": subject_id,
            "account_id": account_id,
            "roles": roles
        }))
    }

    pub fn verify(&self, token: &str) -> Result<Value, ApiError> {
        let parts = token.split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(ApiError::unauthorized("invalid bearer token"));
        }
        let header = decode_token_json(parts[0])?;
        let payload = decode_token_json(parts[1])?;
        let alg = value_string(&header, "alg")
            .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))?;
        if alg != "HS256" {
            return Err(ApiError::unauthorized("invalid bearer token"));
        }
        let kid = value_string(&header, "kid")
            .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))?;
        let key = self
            .keys
            .get(&kid)
            .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))?;
        if !matches!(key.status.as_str(), "active" | "verify_only") {
            return Err(ApiError::unauthorized("invalid bearer token"));
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let expected = hmac_sha256(&key.secret, signing_input.as_bytes());
        let presented =
            b64url_decode(parts[2]).map_err(|_| ApiError::unauthorized("invalid bearer token"))?;
        if !frontplane_constant_time_eq(&expected, &presented) {
            return Err(ApiError::unauthorized("invalid bearer token"));
        }
        self.validate_claims(token, &payload)
    }

    pub fn rotate_registry_value(
        value: &Value,
        new_kid: &str,
        new_secret: &[u8],
    ) -> Result<Value, ApiError> {
        if new_kid.is_empty() {
            return Err(ApiError::internal("new token key id must not be empty"));
        }
        if new_secret.len() < 32 {
            return Err(ApiError::internal(
                "new token signing key must be at least 32 bytes",
            ));
        }
        let mut rotated = value.clone();
        let use_token_keys = rotated.get("token_keys").is_some();
        let use_tokens = rotated.get("tokens").is_some();
        let token_config = if use_token_keys {
            rotated.get_mut("token_keys").expect("checked")
        } else if use_tokens {
            rotated.get_mut("tokens").expect("checked")
        } else {
            &mut rotated
        };
        let object = token_config
            .as_object_mut()
            .ok_or_else(|| ApiError::internal("token registry must be an object"))?;
        let old_kid = object
            .get("active_signing_kid")
            .or_else(|| object.get("activeSigningKid"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let keys = object
            .entry("keys".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| ApiError::internal("token registry keys must be an object"))?;
        if !old_kid.is_empty() {
            if let Some(old_key) = keys.get_mut(&old_kid).and_then(Value::as_object_mut) {
                old_key.insert("status".to_string(), json!("verify_only"));
            }
        }
        keys.insert(
            new_kid.to_string(),
            json!({
                "alg": "HS256",
                "status": "active",
                "secret_b64": b64url_encode(new_secret)
            }),
        );
        object.insert("active_signing_kid".to_string(), json!(new_kid));
        Ok(rotated)
    }

    fn validate_claims(&self, token: &str, payload: &Value) -> Result<Value, ApiError> {
        if value_string(payload, "iss").as_deref() != Some(self.issuer.as_str()) {
            return Err(ApiError::unauthorized("invalid bearer token issuer"));
        }
        if !audience_matches(payload.get("aud"), &self.audience) {
            return Err(ApiError::unauthorized("invalid bearer token audience"));
        }
        let now = now_u64();
        let expires_at = payload
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or_else(|| ApiError::unauthorized("invalid bearer token claims"))?;
        if expires_at <= now {
            return Err(ApiError::unauthorized("expired bearer token"));
        }
        let not_before = payload.get("nbf").and_then(Value::as_u64).unwrap_or(0);
        if not_before > now.saturating_add(60) {
            return Err(ApiError::unauthorized("bearer token not yet valid"));
        }
        let issued_at = payload.get("iat").and_then(Value::as_u64).unwrap_or(0);
        if issued_at == 0 || issued_at > now.saturating_add(60) {
            return Err(ApiError::unauthorized("invalid bearer token claims"));
        }
        let subject_id = required_string_field(payload, "sub", "bearer token")?;
        let handle = required_string_field(payload, "handle", "bearer token")?;
        let account_id = required_string_field(payload, "account_id", "bearer token")?;
        let roles = string_array_field(payload, "roles");
        if roles.is_empty() {
            return Err(ApiError::unauthorized("invalid bearer token claims"));
        }
        let token_id = required_string_field(payload, "jti", "bearer token")?;
        if self.revoked_jtis.contains(&token_id) {
            return Err(ApiError::unauthorized("revoked bearer token"));
        }
        Ok(json!({
            "authenticated": true,
            "authorization": format!("Bearer {token}"),
            "token": token,
            "handle": handle,
            "subject_id": subject_id,
            "account_id": account_id,
            "roles": roles,
            "expires_at": expires_at,
            "issuer": self.issuer,
            "audience": self.audience,
            "token_id": token_id
        }))
    }
}

#[cfg(feature = "frontplane_security")]
fn sign_frontplane_token(
    header: &Value,
    payload: &Value,
    secret: &[u8],
) -> Result<String, ApiError> {
    let header = b64url_encode(header.to_string().as_bytes());
    let payload = b64url_encode(payload.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature = b64url_encode(&hmac_sha256(secret, signing_input.as_bytes()));
    Ok(format!("{signing_input}.{signature}"))
}

#[cfg(feature = "frontplane_security")]
fn decode_token_json(value: &str) -> Result<Value, ApiError> {
    let bytes = b64url_decode(value).map_err(|_| ApiError::unauthorized("invalid bearer token"))?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|_| ApiError::unauthorized("invalid bearer token"))
}

#[cfg(feature = "frontplane_security")]
fn audience_matches(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

#[cfg(all(feature = "frontplane_security", feature = "sealed_ids"))]
#[derive(Clone)]
pub struct FrontplaneSealedIdToolkit {
    active: BTreeMap<String, String>,
    profiles: BTreeMap<String, FrontplaneSealedIdProfile>,
}

#[cfg(all(feature = "frontplane_security", feature = "sealed_ids"))]
#[derive(Clone)]
struct FrontplaneSealedIdProfile {
    kind: String,
    code: String,
    key_id: String,
    status: String,
    cipher: String,
    mode: String,
    key: Vec<u8>,
}

#[cfg(all(feature = "frontplane_security", feature = "sealed_ids"))]
impl FrontplaneSealedIdToolkit {
    pub fn from_env_with_defaults(
        env_prefix: &str,
        default_profiles: &[(&str, &str, &str)],
    ) -> Result<Self, ApiError> {
        if let Some(registry) = registry_json_from_env(env_prefix, "ID")? {
            return Self::from_registry_value_with_secret_sources(&registry, true);
        }
        let root_key = read_named_secret_from_env_or_file(env_prefix, "ID_SEALING_KEY")?;
        if root_key.len() < 32 {
            return Err(ApiError::internal(
                "ID_SEALING_KEY must be at least 32 bytes",
            ));
        }
        let mut active = BTreeMap::new();
        let mut profiles = BTreeMap::new();
        for (kind, code, key_id) in default_profiles {
            active.insert((*kind).to_string(), (*code).to_string());
            profiles.insert(
                (*code).to_string(),
                FrontplaneSealedIdProfile {
                    kind: (*kind).to_string(),
                    code: (*code).to_string(),
                    key_id: (*key_id).to_string(),
                    status: "active".to_string(),
                    cipher: "AES-256-GCM-SIV".to_string(),
                    mode: "deterministic".to_string(),
                    key: root_key.clone(),
                },
            );
        }
        Ok(Self { active, profiles })
    }

    pub fn from_registry_value(value: &Value) -> Result<Self, ApiError> {
        Self::from_registry_value_with_secret_sources(value, false)
    }

    fn from_registry_value_with_secret_sources(
        value: &Value,
        allow_secret_sources: bool,
    ) -> Result<Self, ApiError> {
        let registry = value
            .get("sealed_ids")
            .or_else(|| value.get("sealedIds"))
            .unwrap_or(value);
        let active_value = registry
            .get("active")
            .and_then(Value::as_object)
            .ok_or_else(|| ApiError::internal("sealed id registry missing active map"))?;
        let mut active = BTreeMap::new();
        for (kind, code) in active_value {
            let code = code.as_str().ok_or_else(|| {
                ApiError::internal("sealed id active profile code must be a string")
            })?;
            validate_sealed_id_kind(kind)?;
            validate_sealed_id_code(code)?;
            active.insert(kind.clone(), code.to_string());
        }
        let keys = registry.get("keys").and_then(Value::as_object);
        let profiles_value = registry
            .get("profiles")
            .and_then(Value::as_object)
            .ok_or_else(|| ApiError::internal("sealed id registry missing profiles"))?;
        let mut profiles = BTreeMap::new();
        for (code, profile_value) in profiles_value {
            validate_sealed_id_code(code)?;
            let kind = value_string(profile_value, "kind")
                .or_else(|| value_string(profile_value, "entity"))
                .ok_or_else(|| {
                    ApiError::internal(format!("sealed id profile {code} missing kind"))
                })?;
            validate_sealed_id_kind(&kind)?;
            let key_id = value_string(profile_value, "key_id")
                .or_else(|| value_string(profile_value, "keyId"))
                .unwrap_or_else(|| code.clone());
            let key_source = if has_inline_secret(profile_value) {
                profile_value
            } else {
                keys.and_then(|keys| keys.get(&key_id)).ok_or_else(|| {
                    ApiError::internal(format!("sealed id profile {code} missing key material"))
                })?
            };
            let key = secret_bytes_from_value(key_source, allow_secret_sources, "sealed id key")?;
            if key.len() < 32 {
                return Err(ApiError::internal(format!(
                    "sealed id profile {code} key must be at least 32 bytes"
                )));
            }
            let status =
                value_string(profile_value, "status").unwrap_or_else(|| "read_only".to_string());
            if !matches!(
                status.as_str(),
                "active" | "read_only" | "verify_only" | "retired" | "revoked"
            ) {
                return Err(ApiError::internal(format!(
                    "sealed id profile {code} has unsupported status {status}"
                )));
            }
            let cipher = value_string(profile_value, "cipher")
                .unwrap_or_else(|| "AES-256-GCM-SIV".to_string());
            if cipher != "AES-256-GCM-SIV" {
                return Err(ApiError::internal(format!(
                    "sealed id profile {code} uses unsupported cipher {cipher}"
                )));
            }
            let mode =
                value_string(profile_value, "mode").unwrap_or_else(|| "deterministic".to_string());
            if mode != "deterministic" {
                return Err(ApiError::internal(format!(
                    "sealed id profile {code} uses unsupported mode {mode}"
                )));
            }
            profiles.insert(
                code.clone(),
                FrontplaneSealedIdProfile {
                    kind,
                    code: code.clone(),
                    key_id,
                    status,
                    cipher,
                    mode,
                    key,
                },
            );
        }
        for (kind, code) in &active {
            let profile = profiles.get(code).ok_or_else(|| {
                ApiError::internal(format!("active sealed id profile {code} missing"))
            })?;
            if profile.kind != *kind {
                return Err(ApiError::internal(format!(
                    "active sealed id profile {code} has kind {}, expected {kind}",
                    profile.kind
                )));
            }
            if profile.status != "active" {
                return Err(ApiError::internal(format!(
                    "active sealed id profile {code} must have active status"
                )));
            }
        }
        Ok(Self { active, profiles })
    }

    pub fn to_registry_value(&self) -> Value {
        let active = self
            .active
            .iter()
            .map(|(kind, code)| (kind.clone(), Value::String(code.clone())))
            .collect::<serde_json::Map<_, _>>();
        let profiles = self
            .profiles
            .iter()
            .map(|(code, profile)| {
                (
                    code.clone(),
                    json!({
                        "kind": profile.kind,
                        "code": profile.code,
                        "key_id": profile.key_id,
                        "status": profile.status,
                        "cipher": profile.cipher,
                        "mode": profile.mode,
                        "key_b64": b64url_encode(&profile.key)
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        json!({
            "registry_version": 1,
            "active": active,
            "profiles": profiles
        })
    }

    pub fn seal(&self, kind: &str, native_id: &str) -> Result<String, ApiError> {
        if native_id.is_empty() {
            return Ok(String::new());
        }
        validate_sealed_id_kind(kind)?;
        let code = self.active.get(kind).ok_or_else(|| {
            ApiError::internal(format!("sealed id registry has no active {kind} profile"))
        })?;
        let profile = self
            .profiles
            .get(code)
            .ok_or_else(|| ApiError::internal(format!("sealed id profile {code} missing")))?;
        if profile.status != "active" {
            return Err(ApiError::internal(format!(
                "sealed id profile {code} is not active for sealing"
            )));
        }
        FrontplaneSealedIdCodec::new(kind, code, &profile.key)?.seal(native_id)
    }

    pub fn open(&self, kind: &str, public_id: &str) -> Result<String, ApiError> {
        if public_id.is_empty() {
            return Ok(String::new());
        }
        validate_sealed_id_kind(kind)?;
        let (id_kind, code) = parse_sealed_id_prefix(public_id)?;
        if id_kind != kind {
            return Err(ApiError::bad_request(format!("invalid sealed {kind} id")));
        }
        let profile = self.profiles.get(code).ok_or_else(|| {
            ApiError::bad_request(format!("unsupported sealed {kind} id version"))
        })?;
        if profile.kind != kind {
            return Err(ApiError::bad_request(format!("invalid sealed {kind} id")));
        }
        if matches!(profile.status.as_str(), "retired" | "revoked") {
            return Err(ApiError::bad_request(format!(
                "unsupported sealed {kind} id version"
            )));
        }
        FrontplaneSealedIdCodec::new(kind, code, &profile.key)?.open(public_id)
    }

    pub fn rotate_registry_value(
        value: &Value,
        kind: &str,
        new_code: &str,
        new_key_id: &str,
        new_key: &[u8],
    ) -> Result<Value, ApiError> {
        validate_sealed_id_kind(kind)?;
        validate_sealed_id_code(new_code)?;
        if new_key_id.is_empty() {
            return Err(ApiError::internal("new sealed id key id must not be empty"));
        }
        if new_key.len() < 32 {
            return Err(ApiError::internal(
                "new sealed id key must be at least 32 bytes",
            ));
        }
        let mut rotated = value.clone();
        let use_sealed_ids = rotated.get("sealed_ids").is_some();
        let use_sealed_ids_camel = rotated.get("sealedIds").is_some();
        let registry = if use_sealed_ids {
            rotated.get_mut("sealed_ids").expect("checked")
        } else if use_sealed_ids_camel {
            rotated.get_mut("sealedIds").expect("checked")
        } else {
            &mut rotated
        };
        let object = registry
            .as_object_mut()
            .ok_or_else(|| ApiError::internal("sealed id registry must be an object"))?;
        let old_code = object
            .entry("active".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| ApiError::internal("sealed id active map must be an object"))?
            .insert(kind.to_string(), json!(new_code))
            .and_then(|value| value.as_str().map(str::to_string));
        let profiles = object
            .entry("profiles".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| ApiError::internal("sealed id profiles must be an object"))?;
        if let Some(old_code) = old_code {
            if let Some(old_profile) = profiles.get_mut(&old_code).and_then(Value::as_object_mut) {
                old_profile.insert("status".to_string(), json!("read_only"));
            }
        }
        profiles.insert(
            new_code.to_string(),
            json!({
                "kind": kind,
                "code": new_code,
                "key_id": new_key_id,
                "status": "active",
                "cipher": "AES-256-GCM-SIV",
                "mode": "deterministic",
                "key_b64": b64url_encode(new_key)
            }),
        );
        Ok(rotated)
    }
}

#[cfg(feature = "frontplane_security")]
fn registry_json_from_env(env_prefix: &str, kind: &str) -> Result<Option<Value>, ApiError> {
    for name in [
        prefixed_env_name(env_prefix, &format!("{kind}_REGISTRY_JSON")),
        format!("FRONTPLANE_{kind}_REGISTRY_JSON"),
    ] {
        if let Ok(value) = env::var(&name) {
            let value = value.trim();
            if !value.is_empty() {
                return serde_json::from_str(value)
                    .map(Some)
                    .map_err(|err| ApiError::internal(format!("{name} is not valid JSON: {err}")));
            }
        }
    }
    for name in [
        prefixed_env_name(env_prefix, &format!("{kind}_REGISTRY_FILE")),
        format!("FRONTPLANE_{kind}_REGISTRY_FILE"),
    ] {
        if let Ok(path) = env::var(&name) {
            let path = path.trim();
            if !path.is_empty() {
                let body = fs::read_to_string(path)
                    .map_err(|err| ApiError::internal(format!("failed to read {name}: {err}")))?;
                return serde_json::from_str(&body).map(Some).map_err(|err| {
                    ApiError::internal(format!("{name} did not contain valid JSON: {err}"))
                });
            }
        }
    }
    Ok(None)
}

#[cfg(feature = "frontplane_security")]
fn token_revocation_set_from_env(env_prefix: &str) -> Result<BTreeSet<String>, ApiError> {
    for name in [
        prefixed_env_name(env_prefix, "TOKEN_REVOKED_JTIS_JSON"),
        "FRONTPLANE_TOKEN_REVOKED_JTIS_JSON".to_string(),
    ] {
        if let Ok(value) = env::var(&name) {
            let value = value.trim();
            if !value.is_empty() {
                let parsed = serde_json::from_str::<Value>(value).map_err(|err| {
                    ApiError::internal(format!("{name} is not valid JSON: {err}"))
                })?;
                return revoked_jtis_from_value(&parsed);
            }
        }
    }
    for name in [
        prefixed_env_name(env_prefix, "TOKEN_REVOKED_JTIS_FILE"),
        "FRONTPLANE_TOKEN_REVOKED_JTIS_FILE".to_string(),
    ] {
        if let Ok(path) = env::var(&name) {
            let path = path.trim();
            if !path.is_empty() {
                let body = fs::read_to_string(path)
                    .map_err(|err| ApiError::internal(format!("failed to read {name}: {err}")))?;
                let parsed = serde_json::from_str::<Value>(&body).map_err(|err| {
                    ApiError::internal(format!("{name} did not contain valid JSON: {err}"))
                })?;
                return revoked_jtis_from_value(&parsed);
            }
        }
    }
    Ok(BTreeSet::new())
}

#[cfg(feature = "frontplane_security")]
fn revoked_jtis_from_value(value: &Value) -> Result<BTreeSet<String>, ApiError> {
    let revoked = value
        .get("revoked_jtis")
        .or_else(|| value.get("revokedJtis"))
        .unwrap_or(value);
    let Some(array) = revoked.as_array() else {
        if revoked.is_object() && revoked.get("keys").is_some() {
            return Ok(BTreeSet::new());
        }
        return Err(ApiError::internal("token revoked_jtis must be an array"));
    };
    let mut out = BTreeSet::new();
    for value in array {
        let Some(jti) = value.as_str() else {
            return Err(ApiError::internal(
                "token revoked_jtis entries must be strings",
            ));
        };
        if !jti.trim().is_empty() {
            out.insert(jti.trim().to_string());
        }
    }
    Ok(out)
}

#[cfg(feature = "frontplane_security")]
fn read_named_secret_from_env_or_file(env_prefix: &str, suffix: &str) -> Result<Vec<u8>, ApiError> {
    for name in [
        prefixed_env_name(env_prefix, suffix),
        format!("FRONTPLANE_{suffix}"),
    ] {
        if let Ok(value) = env::var(&name) {
            let value = value.trim();
            if !value.is_empty() {
                let bytes = secret_bytes_from_string(value)?;
                if bytes.len() >= 32 {
                    return Ok(bytes);
                }
                return Err(ApiError::internal(format!(
                    "{name} must be at least 32 bytes"
                )));
            }
        }
    }
    for name in [
        prefixed_env_name(env_prefix, &format!("{suffix}_FILE")),
        format!("FRONTPLANE_{suffix}_FILE"),
    ] {
        if let Ok(path) = env::var(&name) {
            let path = path.trim();
            if !path.is_empty() {
                let value = fs::read_to_string(path)
                    .map_err(|err| ApiError::internal(format!("failed to read {name}: {err}")))?;
                let bytes = secret_bytes_from_string(value.trim())?;
                if bytes.len() >= 32 {
                    return Ok(bytes);
                }
                return Err(ApiError::internal(format!(
                    "{name} contents must be at least 32 bytes"
                )));
            }
        }
    }
    Err(ApiError::internal(format!(
        "{} or {}_FILE is required",
        prefixed_env_name(env_prefix, suffix),
        prefixed_env_name(env_prefix, suffix)
    )))
}

#[cfg(feature = "frontplane_security")]
fn secret_bytes_from_value(
    value: &Value,
    allow_secret_sources: bool,
    label: &str,
) -> Result<Vec<u8>, ApiError> {
    if let Some(secret) = value_string(value, "secret").or_else(|| value_string(value, "key")) {
        return secret_bytes_from_string(secret.trim());
    }
    if let Some(secret) =
        value_string(value, "secret_b64").or_else(|| value_string(value, "key_b64"))
    {
        return decode_secret_b64(secret.trim())
            .map_err(|_| ApiError::internal(format!("invalid base64 {label}")));
    }
    if !allow_secret_sources
        && (value.get("secret_env").is_some()
            || value.get("key_env").is_some()
            || value.get("secret_file").is_some()
            || value.get("key_file").is_some())
    {
        return Err(ApiError::internal(format!(
            "{label} registry value must contain resolved key material, not env/file references"
        )));
    }
    if allow_secret_sources {
        if let Some(name) =
            value_string(value, "secret_env").or_else(|| value_string(value, "key_env"))
        {
            let secret = env::var(&name).map_err(|err| {
                ApiError::internal(format!("failed to read {label} env {name}: {err}"))
            })?;
            return secret_bytes_from_string(secret.trim());
        }
        if let Some(path) =
            value_string(value, "secret_file").or_else(|| value_string(value, "key_file"))
        {
            let secret = fs::read_to_string(&path).map_err(|err| {
                ApiError::internal(format!("failed to read {label} file {path}: {err}"))
            })?;
            return secret_bytes_from_string(secret.trim());
        }
    }
    Err(ApiError::internal(format!("{label} missing key material")))
}

#[cfg(feature = "frontplane_security")]
fn secret_bytes_from_string(value: &str) -> Result<Vec<u8>, ApiError> {
    let value = value.trim();
    reject_known_insecure_secret_value(value, "secret")?;
    if let Some(encoded) = value.strip_prefix("base64url:") {
        return b64url_decode(encoded).map_err(|_| ApiError::internal("invalid base64url secret"));
    }
    if let Some(encoded) = value.strip_prefix("base64:") {
        return b64standard_decode(encoded)
            .map_err(|_| ApiError::internal("invalid base64 secret"));
    }
    Ok(value.as_bytes().to_vec())
}

fn reject_known_insecure_secret_value(value: &str, label: &str) -> Result<(), ApiError> {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    let known = matches!(
        lower.as_str(),
        "frontplane-rest-callout"
            | "minioadmin"
            | "admin"
            | "password"
            | "changeme"
            | "change-me"
    );
    if known {
        return Err(ApiError::internal(format!(
            "{label} uses a known insecure development secret"
        )));
    }
    Ok(())
}

#[cfg(feature = "frontplane_security")]
fn decode_secret_b64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    b64url_decode(value).or_else(|_| b64standard_decode(value))
}

#[cfg(feature = "frontplane_security")]
fn env_string(env_prefix: &str, suffix: &str) -> Option<String> {
    env::var(prefixed_env_name(env_prefix, suffix))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(feature = "frontplane_security")]
fn prefixed_env_name(env_prefix: &str, suffix: &str) -> String {
    let prefix = env_prefix.trim_end_matches('_');
    if prefix.is_empty() {
        suffix.to_string()
    } else {
        format!("{prefix}_{suffix}")
    }
}

#[cfg(feature = "frontplane_security")]
fn value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(feature = "frontplane_security")]
fn required_string_field(value: &Value, key: &str, label: &str) -> Result<String, ApiError> {
    value_string(value, key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthorized(format!("{label} missing {key}")))
}

#[cfg(feature = "frontplane_security")]
fn secure_random_b64url(len: usize) -> Result<String, ApiError> {
    let mut bytes = vec![0_u8; len];
    getrandom::getrandom(&mut bytes)
        .map_err(|err| ApiError::internal(format!("secure random unavailable: {err}")))?;
    Ok(b64url_encode(&bytes))
}

#[cfg(feature = "frontplane_security")]
pub fn frontplane_secure_random_b64url(len: usize) -> Result<String, ApiError> {
    secure_random_b64url(len)
}

#[cfg(feature = "frontplane_security")]
pub fn frontplane_sha256_hex(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

#[cfg(feature = "frontplane_security")]
pub fn frontplane_hmac_sha256_b64url(secret: &str, value: &str) -> Result<String, ApiError> {
    reject_known_insecure_secret_value(secret, "HMAC secret")?;
    Ok(b64url_encode(&hmac_sha256(
        secret.as_bytes(),
        value.as_bytes(),
    )))
}

#[cfg(feature = "frontplane_security")]
pub fn frontplane_verify_hmac_sha256_b64url(
    secret: &str,
    value: &str,
    signature: &str,
) -> Result<bool, ApiError> {
    let expected = frontplane_hmac_sha256_b64url(secret, value)?;
    Ok(frontplane_constant_time_eq(
        expected.as_bytes(),
        signature.trim().as_bytes(),
    ))
}

#[cfg(feature = "frontplane_security")]
fn b64url_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(feature = "frontplane_security")]
fn b64url_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(value)
}

#[cfg(feature = "frontplane_security")]
fn b64standard_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(value)
}

#[cfg(feature = "frontplane_security")]
fn frontplane_constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(all(feature = "frontplane_security", feature = "sealed_ids"))]
fn has_inline_secret(value: &Value) -> bool {
    value.get("secret").is_some()
        || value.get("key").is_some()
        || value.get("secret_b64").is_some()
        || value.get("key_b64").is_some()
        || value.get("secret_env").is_some()
        || value.get("key_env").is_some()
        || value.get("secret_file").is_some()
        || value.get("key_file").is_some()
}

#[cfg(all(feature = "frontplane_security", feature = "sealed_ids"))]
fn validate_sealed_id_kind(kind: &str) -> Result<(), ApiError> {
    if kind.is_empty()
        || kind.contains('_')
        || !kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(ApiError::internal(
            "sealed id kind must be a non-empty lowercase token",
        ));
    }
    Ok(())
}

#[cfg(all(feature = "frontplane_security", feature = "sealed_ids"))]
fn validate_sealed_id_code(code: &str) -> Result<(), ApiError> {
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return Err(ApiError::internal(
            "sealed id profile code must be three lowercase letters",
        ));
    }
    Ok(())
}

#[cfg(all(feature = "frontplane_security", feature = "sealed_ids"))]
fn parse_sealed_id_prefix(public_id: &str) -> Result<(&str, &str), ApiError> {
    let mut parts = public_id.splitn(3, '_');
    let kind = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    let payload = parts.next().unwrap_or_default();
    if payload.is_empty()
        || validate_sealed_id_kind(kind).is_err()
        || validate_sealed_id_code(code).is_err()
    {
        return Err(ApiError::bad_request("invalid sealed id"));
    }
    Ok((kind, code))
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;

    #[test]
    fn configured_ip_rate_limit_rejects_after_threshold() {
        let Some(limit) = crate::RATE_LIMITS.first() else {
            return;
        };
        let route = crate::ROUTES
            .iter()
            .find(|route| route.operation == limit.operation)
            .expect("rate limit must reference a generated route");
        let runtime = FrontplaneRuntime::new();
        for _ in 0..limit.requests {
            runtime
                .check_rate_limit(route, "203.0.113.10")
                .expect("request should be within rate limit");
        }
        let err = runtime
            .check_rate_limit(route, "203.0.113.10")
            .expect_err("request should exceed rate limit");
        assert_eq!(err.status, 429);
        runtime
            .check_rate_limit(route, "203.0.113.11")
            .expect("rate limiting should be keyed by client IP");
    }
}

#[cfg(feature = "sealed_ids")]
static FRONTPLANE_SEALED_ID_CACHE: OnceLock<Mutex<FrontplaneSealedIdCache>> = OnceLock::new();

#[cfg(feature = "sealed_ids")]
#[derive(Default)]
struct FrontplaneSealedIdCache {
    native_to_public: BTreeMap<String, String>,
    public_to_native: BTreeMap<String, String>,
}

#[cfg(feature = "sealed_ids")]
pub struct FrontplaneSealedIdCodec {
    kind: String,
    code: String,
    prefix: String,
    key: Vec<u8>,
    key_fingerprint: String,
    max_cache_entries: usize,
}

#[cfg(feature = "sealed_ids")]
impl FrontplaneSealedIdCodec {
    pub fn new(kind: &str, code: &str, root_key: &[u8]) -> Result<Self, ApiError> {
        if kind.is_empty() || kind.contains('_') {
            return Err(ApiError::internal(
                "sealed id kind must be a non-empty token",
            ));
        }
        if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_lowercase()) {
            return Err(ApiError::internal(
                "sealed id code must be three lowercase letters",
            ));
        }
        if root_key.len() < 32 {
            return Err(ApiError::internal(
                "sealed id key must be at least 32 bytes",
            ));
        }
        let derivation = format!("frontplane-sealed-id-key:v1:{kind}:{code}:");
        let key = hmac_sha256(root_key, derivation.as_bytes());
        let key_hash = sha256_bytes(&key);
        Ok(Self {
            kind: kind.to_string(),
            code: code.to_string(),
            prefix: format!("{kind}_{code}_"),
            key,
            key_fingerprint: hex(&key_hash[..8]),
            max_cache_entries: 16_384,
        })
    }

    pub fn with_max_cache_entries(mut self, max_cache_entries: usize) -> Self {
        self.max_cache_entries = max_cache_entries.max(1);
        self
    }

    pub fn seal(&self, native_id: &str) -> Result<String, ApiError> {
        if native_id.is_empty() {
            return Ok(String::new());
        }
        if native_id.starts_with(&self.prefix) {
            return Ok(native_id.to_string());
        }
        if let Some(cached) = self.cached_public(native_id) {
            return Ok(cached);
        }

        use aes_gcm_siv::aead::{Aead, NewAead};
        use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let cipher = Aes256GcmSiv::new(Key::from_slice(&self.key));
        let nonce_bytes = self.deterministic_nonce(native_id);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), native_id.as_bytes())
            .map_err(|_| ApiError::internal("sealed id encryption failed"))?;
        let mut payload = Vec::with_capacity(1 + nonce_bytes.len() + ciphertext.len());
        payload.push(1);
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);
        let public_id = format!("{}{}", self.prefix, URL_SAFE_NO_PAD.encode(payload));
        self.cache_pair(native_id, &public_id);
        Ok(public_id)
    }

    pub fn open(&self, public_id: &str) -> Result<String, ApiError> {
        if public_id.is_empty() {
            return Ok(String::new());
        }
        if !public_id.starts_with(&self.prefix) {
            if public_id.starts_with(&format!("{}_", self.kind)) {
                return Err(ApiError::bad_request(format!(
                    "unsupported {} id version",
                    self.kind
                )));
            }
            return Err(ApiError::bad_request(format!(
                "invalid sealed {} id",
                self.kind
            )));
        }
        if let Some(cached) = self.cached_native(public_id) {
            return Ok(cached);
        }

        use aes_gcm_siv::aead::{Aead, NewAead};
        use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let payload = URL_SAFE_NO_PAD
            .decode(&public_id[self.prefix.len()..])
            .map_err(|_| ApiError::bad_request(format!("invalid sealed {} id", self.kind)))?;
        if payload.len() <= 29 {
            return Err(ApiError::bad_request(format!(
                "invalid sealed {} id",
                self.kind
            )));
        }
        if payload[0] != 1 {
            return Err(ApiError::bad_request(format!(
                "unsupported sealed {} id version",
                self.kind
            )));
        }
        let nonce = &payload[1..13];
        let ciphertext = &payload[13..];
        let cipher = Aes256GcmSiv::new(Key::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| ApiError::bad_request(format!("invalid sealed {} id", self.kind)))?;
        let native_id = String::from_utf8(plaintext)
            .map_err(|_| ApiError::bad_request(format!("invalid sealed {} id", self.kind)))?;
        self.cache_pair(&native_id, public_id);
        Ok(native_id)
    }

    fn deterministic_nonce(&self, native_id: &str) -> [u8; 12] {
        let mut input =
            format!("frontplane-sealed-id-nonce:v1:{}:{}:", self.kind, self.code).into_bytes();
        input.extend_from_slice(native_id.as_bytes());
        let digest = hmac_sha256(&self.key, &input);
        let mut nonce = [0_u8; 12];
        nonce.copy_from_slice(&digest[..12]);
        nonce
    }

    fn cached_public(&self, native_id: &str) -> Option<String> {
        sealed_id_cache().lock().ok().and_then(|cache| {
            cache
                .native_to_public
                .get(&self.native_cache_key(native_id))
                .cloned()
        })
    }

    fn cached_native(&self, public_id: &str) -> Option<String> {
        sealed_id_cache().lock().ok().and_then(|cache| {
            cache
                .public_to_native
                .get(&self.public_cache_key(public_id))
                .cloned()
        })
    }

    fn cache_pair(&self, native_id: &str, public_id: &str) {
        if let Ok(mut cache) = sealed_id_cache().lock() {
            if cache.native_to_public.len() >= self.max_cache_entries
                || cache.public_to_native.len() >= self.max_cache_entries
            {
                cache.native_to_public.clear();
                cache.public_to_native.clear();
            }
            cache
                .native_to_public
                .insert(self.native_cache_key(native_id), public_id.to_string());
            cache
                .public_to_native
                .insert(self.public_cache_key(public_id), native_id.to_string());
        }
    }

    fn native_cache_key(&self, native_id: &str) -> String {
        format!(
            "{}:{}:{}:native:{}",
            self.kind, self.code, self.key_fingerprint, native_id
        )
    }

    fn public_cache_key(&self, public_id: &str) -> String {
        format!(
            "{}:{}:{}:public:{}",
            self.kind, self.code, self.key_fingerprint, public_id
        )
    }
}

#[cfg(feature = "sealed_ids")]
fn sealed_id_cache() -> &'static Mutex<FrontplaneSealedIdCache> {
    FRONTPLANE_SEALED_ID_CACHE.get_or_init(|| Mutex::new(FrontplaneSealedIdCache::default()))
}

#[cfg(all(test, feature = "sealed_ids"))]
mod sealed_id_tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [7_u8; 32]
    }

    #[test]
    fn sealed_ids_reject_raw_native_ids() {
        let codec = FrontplaneSealedIdCodec::new("acct", "nva", &test_key()).unwrap();

        let err = codec.open("gotosocial-native-account-id").unwrap_err();

        assert_eq!(err.status, 400);
        assert_eq!(err.code, "BadRequestError");
    }

    #[test]
    fn sealed_ids_round_trip_expected_prefix() {
        let codec = FrontplaneSealedIdCodec::new("acct", "nva", &test_key()).unwrap();

        let public_id = codec.seal("gotosocial-native-account-id").unwrap();

        assert!(public_id.starts_with("acct_nva_"));
        assert_eq!(
            codec.open(&public_id).unwrap(),
            "gotosocial-native-account-id"
        );
    }
}

#[cfg(all(test, feature = "frontplane_security", feature = "sealed_ids"))]
mod frontplane_security_toolkit_tests {
    use super::*;

    fn principal() -> Value {
        json!({
            "handle": "alice",
            "subject_id": "user-alice",
            "account_id": "acct_nva_test",
            "roles": ["user"]
        })
    }

    fn token_registry(active_kid: &str, old_status: &str) -> Value {
        json!({
            "issuer": "OssDecentralizedMicroblog",
            "audience": "OssDecentralizedMicroblog",
            "ttl_seconds": 3600,
            "active_signing_kid": active_kid,
            "keys": {
                "old": {
                    "alg": "HS256",
                    "status": old_status,
                    "secret": "old-token-signing-secret-0123456789abcdef"
                },
                "new": {
                    "alg": "HS256",
                    "status": "active",
                    "secret": "new-token-signing-secret-0123456789abcdef"
                }
            }
        })
    }

    #[test]
    fn token_toolkit_rotates_kid_and_keeps_verify_only_keys() {
        let old_registry = json!({
            "issuer": "OssDecentralizedMicroblog",
            "audience": "OssDecentralizedMicroblog",
            "ttl_seconds": 3600,
            "active_signing_kid": "old",
            "keys": {
                "old": {
                    "alg": "HS256",
                    "status": "active",
                    "secret": "old-token-signing-secret-0123456789abcdef"
                }
            }
        });
        let old_toolkit = FrontplaneTokenToolkit::from_registry_value(
            &old_registry,
            "OssDecentralizedMicroblog",
            "OssDecentralizedMicroblog",
        )
        .unwrap();
        let old_token = old_toolkit.issue(&principal()).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();

        let rotated_registry = FrontplaneTokenToolkit::rotate_registry_value(
            &old_registry,
            "new",
            b"new-token-signing-secret-0123456789abcdef",
        )
        .unwrap();
        let rotated_toolkit = FrontplaneTokenToolkit::from_registry_value(
            &rotated_registry,
            "OssDecentralizedMicroblog",
            "OssDecentralizedMicroblog",
        )
        .unwrap();
        let verified = rotated_toolkit.verify(&old_token).unwrap();
        assert_eq!(verified["handle"], "alice");

        let new_token = rotated_toolkit.issue(&principal()).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let new_header = decode_token_json(new_token.split('.').next().unwrap()).unwrap();
        assert_eq!(new_header["kid"], "new");
    }

    #[test]
    fn token_toolkit_enforces_audience() {
        let toolkit = FrontplaneTokenToolkit::from_registry_value(
            &token_registry("new", "verify_only"),
            "OssDecentralizedMicroblog",
            "OssDecentralizedMicroblog",
        )
        .unwrap();
        let token = toolkit.issue(&principal()).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let wrong_audience = FrontplaneTokenToolkit::from_registry_value(
            &json!({
                "issuer": "OssDecentralizedMicroblog",
                "audience": "OtherFacade",
                "ttl_seconds": 3600,
                "active_signing_kid": "new",
                "keys": {
                    "new": {
                        "alg": "HS256",
                        "status": "active",
                        "secret": "new-token-signing-secret-0123456789abcdef"
                    }
                }
            }),
            "OssDecentralizedMicroblog",
            "OtherFacade",
        )
        .unwrap();

        let err = wrong_audience.verify(&token).unwrap_err();
        assert_eq!(err.status, 401);
    }

    #[test]
    fn token_toolkit_rejects_revoked_jtis() {
        let toolkit = FrontplaneTokenToolkit::from_registry_value(
            &token_registry("new", "verify_only"),
            "OssDecentralizedMicroblog",
            "OssDecentralizedMicroblog",
        )
        .unwrap();
        let token = toolkit.issue(&principal()).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let token_id = toolkit.verify(&token).unwrap()["token_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut registry = token_registry("new", "verify_only");
        registry["revoked_jtis"] = json!([token_id]);
        let revoked_toolkit = FrontplaneTokenToolkit::from_registry_value(
            &registry,
            "OssDecentralizedMicroblog",
            "OssDecentralizedMicroblog",
        )
        .unwrap();

        let err = revoked_toolkit.verify(&token).unwrap_err();
        assert_eq!(err.status, 401);
    }

    #[test]
    fn sealed_id_registry_rotates_profile_codes() {
        let old_key = b"old-sealed-id-key-0123456789abcdef";
        let new_key = b"new-sealed-id-key-0123456789abcdef";
        let old_public = FrontplaneSealedIdCodec::new("acct", "nva", old_key)
            .unwrap()
            .seal("native-account-1")
            .unwrap();
        let registry = json!({
            "registry_version": 1,
            "active": { "acct": "nva" },
            "profiles": {
                "nva": {
                    "kind": "acct",
                    "key_id": "idseal-old",
                    "status": "active",
                    "cipher": "AES-256-GCM-SIV",
                    "mode": "deterministic",
                    "key_b64": b64url_encode(old_key)
                }
            }
        });
        let rotated_registry = FrontplaneSealedIdToolkit::rotate_registry_value(
            &registry,
            "acct",
            "xqj",
            "idseal-new",
            new_key,
        )
        .unwrap();
        let toolkit = FrontplaneSealedIdToolkit::from_registry_value(&rotated_registry).unwrap();

        assert_eq!(
            toolkit.open("acct", &old_public).unwrap(),
            "native-account-1"
        );
        let new_public = toolkit.seal("acct", "native-account-1").unwrap();
        assert!(new_public.starts_with("acct_xqj_"));
        assert_eq!(
            toolkit.open("acct", &new_public).unwrap(),
            "native-account-1"
        );
    }

    #[test]
    fn sealed_id_registry_rejects_revoked_profiles() {
        let old_key = b"old-sealed-id-key-0123456789abcdef";
        let old_public = FrontplaneSealedIdCodec::new("acct", "nva", old_key)
            .unwrap()
            .seal("native-account-1")
            .unwrap();
        let registry = json!({
            "registry_version": 1,
            "active": { "acct": "xqj" },
            "profiles": {
                "nva": {
                    "kind": "acct",
                    "key_id": "idseal-old",
                    "status": "revoked",
                    "cipher": "AES-256-GCM-SIV",
                    "mode": "deterministic",
                    "key_b64": b64url_encode(old_key)
                },
                "xqj": {
                    "kind": "acct",
                    "key_id": "idseal-new",
                    "status": "active",
                    "cipher": "AES-256-GCM-SIV",
                    "mode": "deterministic",
                    "key_b64": b64url_encode(b"new-sealed-id-key-0123456789abcdef")
                }
            }
        });
        let toolkit = FrontplaneSealedIdToolkit::from_registry_value(&registry).unwrap();

        let err = toolkit.open("acct", &old_public).unwrap_err();
        assert_eq!(err.status, 400);
    }
}
