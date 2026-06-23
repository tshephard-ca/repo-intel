use crate::frontplane_runtime::{ApiError, FlowContext};
use serde_json::Value;

#[path = "backing/repointel_runtime.rs"]
mod repointel_runtime;

pub fn authenticate_bearer(token: &str) -> Result<Value, ApiError> {
    repointel_runtime::authenticate_bearer(token)
}

pub fn invoke(
    target: &str,
    args: &[String],
    context: &FlowContext,
) -> Result<Value, ApiError> {
    match target.split_once('.').map(|(module, _)| module).unwrap_or(target) {
        "RepointelRuntime" => repointel_runtime::invoke(target, args, context),
        other => Err(ApiError::internal(format!("local call module {other} is not installed in generated Rust backing"))),
    }
}
