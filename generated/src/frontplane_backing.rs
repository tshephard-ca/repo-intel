use crate::frontplane_runtime::{ApiError, FlowContext};
use serde_json::Value;

#[path = "backing/metadata_collection_runtime.rs"]
mod metadata_collection_runtime;

pub fn authenticate_bearer(token: &str) -> Result<Value, ApiError> {
    metadata_collection_runtime::authenticate_bearer(token)
}

pub fn invoke(target: &str, args: &[String], context: &FlowContext) -> Result<Value, ApiError> {
    match target
        .split_once('.')
        .map(|(module, _)| module)
        .unwrap_or(target)
    {
        "MetadataCollectionRuntime" => metadata_collection_runtime::invoke(target, args, context),
        other => Err(ApiError::internal(format!(
            "local call module {other} is not installed in generated Rust backing"
        ))),
    }
}
