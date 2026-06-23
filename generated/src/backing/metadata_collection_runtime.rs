use crate::frontplane_runtime::{resolve_arg, ApiError, FlowContext};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
struct CollectionMeta {
    collection: &'static str,
    singular: &'static str,
    key: &'static str,
    prefix: &'static str,
}

const COLLECTIONS: &[CollectionMeta] = &[
    CollectionMeta {
        collection: "downstream-services",
        singular: "downstream_service",
        key: "downstream_service_id",
        prefix: "downstream-service",
    },
    CollectionMeta {
        collection: "profiles",
        singular: "profile",
        key: "profile_id",
        prefix: "profile",
    },
    CollectionMeta {
        collection: "scenarios",
        singular: "scenario",
        key: "scenario_id",
        prefix: "scenario",
    },
    CollectionMeta {
        collection: "dictionaries",
        singular: "dictionary",
        key: "dictionary_id",
        prefix: "dictionary",
    },
    CollectionMeta {
        collection: "extractor-bundles",
        singular: "bundle",
        key: "bundle_id",
        prefix: "bundle",
    },
    CollectionMeta {
        collection: "extractor-rules",
        singular: "rule",
        key: "rule_id",
        prefix: "rule",
    },
    CollectionMeta {
        collection: "runs",
        singular: "run",
        key: "collection_run_id",
        prefix: "run",
    },
    CollectionMeta {
        collection: "evidence-hits",
        singular: "evidence_hit",
        key: "evidence_hit_id",
        prefix: "evidence-hit",
    },
    CollectionMeta {
        collection: "coverage-reports",
        singular: "coverage_report",
        key: "coverage_report_id",
        prefix: "coverage-report",
    },
    CollectionMeta {
        collection: "keyword-configs",
        singular: "keyword_config",
        key: "keyword_config_id",
        prefix: "keyword-config",
    },
    CollectionMeta {
        collection: "szz-runs",
        singular: "szz_run",
        key: "szz_run_id",
        prefix: "szz-run",
    },
    CollectionMeta {
        collection: "downstream-calls",
        singular: "downstream_call",
        key: "downstream_call_id",
        prefix: "downstream-call",
    },
];

const PROFILE_ID: &str = "profile_vuln_intel_priority_v1";
const BUNDLE_ID: &str = "bundle_vuln_intel_core_extractors";
const REVIEW_RISK_SCORE_BUCKET_ID: &str = "review_risk_weighted_average";
const KEYWORD_SCORE_CAP: i64 = 160;
const GENERATED_NCALL_STATUS_UNAVAILABLE: &str =
    "generated Ncall completed before backing step; provider status/duration unavailable";
static COLLECTION_IO_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn authenticate_bearer(token: &str) -> Result<Value, ApiError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(ApiError::unauthorized("empty bearer token"));
    }
    if looks_like_legacy_role_token(token) {
        return Err(ApiError::unauthorized(
            "role-name bearer tokens are not accepted; configure an explicit token registry",
        ));
    }
    let registry = auth_token_registry()?;
    let principal = registry_principal_for_token(&registry, token)?;
    let roles = registry_roles(&principal)?;
    let subject_id = first_non_empty(&[
        value_text(&principal, "subject_id"),
        value_text(&principal, "subjectId"),
        value_text(&principal, "sub"),
    ]);
    if subject_id.is_empty() {
        return Err(ApiError::unauthorized(
            "token registry principal is missing subject_id",
        ));
    }
    let handle = first_non_empty(&[
        value_text(&principal, "handle"),
        value_text(&principal, "name"),
        subject_id.clone(),
    ]);
    let account_id = first_non_empty(&[
        value_text(&principal, "account_id"),
        value_text(&principal, "accountId"),
        subject_id.clone(),
    ]);
    Ok(json!({
        "authenticated": true,
        "authorization": format!("Bearer {token}"),
        "token": token,
        "subject_id": subject_id,
        "handle": handle,
        "account_id": account_id,
        "roles": roles
    }))
}

pub fn invoke(target: &str, args: &[String], context: &FlowContext) -> Result<Value, ApiError> {
    match target {
        "MetadataCollectionRuntime.validate_extractor_rule" => {
            Ok(validate_extractor_rule(args, context))
        }
        "MetadataCollectionRuntime.validate_extractor_rule_patch" => {
            Ok(validate_extractor_rule_patch(args, context))
        }
        "MetadataCollectionRuntime.validate_collection_run_request" => {
            Ok(validate_collection_run_request(args, context))
        }
        "MetadataCollectionRuntime.validate_relationship_bulk_upsert_request" => {
            Ok(validate_relationship_bulk_upsert_request(args, context))
        }
        "MetadataCollectionRuntime.test_rule" => test_rule(args, context),
        "MetadataCollectionRuntime.get_console_config" => get_console_config(),
        target if target.starts_with("MetadataCollectionRuntime.") => {
            handle_persistence_target(target, args, context)
        }
        other => Err(ApiError::internal(format!(
            "call {other} is not implemented by MetadataCollectionRuntime backing"
        ))),
    }
}

fn validate_extractor_rule(args: &[String], context: &FlowContext) -> Value {
    validate_rule_value(&arg_value(args, 0, context), false)
}

fn validate_extractor_rule_patch(args: &[String], context: &FlowContext) -> Value {
    validate_rule_value(&arg_value(args, 0, context), true)
}

fn validate_collection_run_request(args: &[String], context: &FlowContext) -> Value {
    let input = arg_value(args, 0, context);
    if text_field(&input, "profile_id").is_empty() {
        return invalid_result("missing_profile_id", "profile_id is required", json!({}));
    }
    let mode = text_field(&input, "mode");
    if !mode.is_empty()
        && !matches!(
            mode.as_str(),
            "full" | "incremental" | "backfill" | "refresh"
        )
    {
        return invalid_result(
            "invalid_mode",
            "mode must be full, incremental, backfill, or refresh",
            json!({ "mode": mode }),
        );
    }
    valid_result()
}

fn validate_relationship_bulk_upsert_request(args: &[String], context: &FlowContext) -> Value {
    let input = arg_value(args, 0, context);
    let Some(relationships) = input.get("relationships").and_then(Value::as_array) else {
        return invalid_result(
            "missing_relationships",
            "relationships must be supplied as an array",
            json!({}),
        );
    };
    for (index, relationship) in relationships.iter().enumerate() {
        let validation = validate_relationship_value(relationship);
        if validation.get("valid").and_then(Value::as_bool) != Some(true) {
            let mut result = validation;
            if let Some(details) = result.get_mut("details").and_then(Value::as_object_mut) {
                details.insert("index".to_string(), json!(index));
            }
            return result;
        }
    }
    valid_result()
}

fn validate_rule_value(input: &Value, patch: bool) -> Value {
    if !patch && text_field(input, "bundle_id").is_empty() {
        return invalid_result("missing_bundle_id", "bundle_id is required", json!({}));
    }
    if !patch && text_field(input, "slug").is_empty() {
        return invalid_result("missing_slug", "slug is required", json!({}));
    }
    let rule_type = text_field(input, "type");
    if !rule_type.is_empty()
        && !matches!(
            rule_type.as_str(),
            "field_map"
                | "regex"
                | "regex_set"
                | "json_path"
                | "yaml_path"
                | "parser"
                | "dictionary"
                | "relationship_rule"
                | "heuristic"
        )
    {
        return invalid_result(
            "invalid_rule_type",
            "rule type is not supported",
            json!({ "type": rule_type }),
        );
    }
    for field in ["outputs_relationships", "proposed_relationships"] {
        if let Some(items) = input.get(field).and_then(Value::as_array) {
            for (index, item) in items.iter().enumerate() {
                if let Some(endpoint) = item.get("from") {
                    if !valid_endpoint_type(&text_field(endpoint, "type")) {
                        return invalid_result(
                            "invalid_relationship_endpoint",
                            "relationship endpoints must be metadata, art, or author",
                            json!({ "field": field, "index": index, "endpoint": "from" }),
                        );
                    }
                }
                if let Some(endpoint) = item.get("to") {
                    if !valid_endpoint_type(&text_field(endpoint, "type")) {
                        return invalid_result(
                            "invalid_relationship_endpoint",
                            "relationship endpoints must be metadata, art, or author",
                            json!({ "field": field, "index": index, "endpoint": "to" }),
                        );
                    }
                }
            }
        }
    }
    valid_result()
}

fn validate_relationship_value(input: &Value) -> Value {
    let from_type = text_field(input, "from_type");
    let from_id = text_field(input, "from_id");
    let to_type = text_field(input, "to_type");
    let to_id = text_field(input, "to_id");
    let relation = text_field(input, "relation");
    if !valid_endpoint_type(&from_type) {
        return invalid_result(
            "invalid_from_type",
            "from_type must be one of metadata, art, or author",
            json!({ "from_type": from_type }),
        );
    }
    if !valid_endpoint_type(&to_type) {
        return invalid_result(
            "invalid_to_type",
            "to_type must be one of metadata, art, or author",
            json!({ "to_type": to_type }),
        );
    }
    if from_id.is_empty() || to_id.is_empty() {
        return invalid_result(
            "missing_endpoint_id",
            "from_id and to_id are required",
            json!({ "from_id": from_id, "to_id": to_id }),
        );
    }
    if !relation_allowed(&from_type, &to_type, &relation) {
        return invalid_result(
            "invalid_relation",
            "relation is not allowed for the relationship endpoint pair",
            json!({ "from_type": from_type, "to_type": to_type, "relation": relation }),
        );
    }
    valid_result()
}

fn valid_endpoint_type(endpoint_type: &str) -> bool {
    matches!(endpoint_type, "metadata" | "art" | "author")
}

fn relation_allowed(from_type: &str, to_type: &str, relation: &str) -> bool {
    match (from_type, to_type) {
        ("art", "author") => relation == "authored_by",
        ("author", "art") => false,
        ("metadata", "art") | ("art", "metadata") => matches!(
            relation,
            "describes"
                | "classifies"
                | "tags"
                | "mentions"
                | "references"
                | "extracted_from"
                | "evidenced_by"
                | "derived_from"
                | "assigned_to"
                | "related_to"
        ),
        ("metadata", "author") | ("author", "metadata") => matches!(
            relation,
            "describes"
                | "classifies"
                | "tags"
                | "about_author"
                | "assigned_to"
                | "same_as"
                | "related_to"
        ),
        ("metadata", "metadata") => matches!(
            relation,
            "same_as" | "derived_from" | "normalized_from" | "contains" | "related_to"
        ),
        _ => false,
    }
}

fn valid_result() -> Value {
    json!({ "valid": true, "code": "", "message": "", "details": {} })
}

fn invalid_result(code: &str, message: &str, details: Value) -> Value {
    json!({ "valid": false, "code": code, "message": message, "details": details })
}

fn handle_persistence_target(
    target: &str,
    args: &[String],
    context: &FlowContext,
) -> Result<Value, ApiError> {
    let _storage_guard = collection_io_guard()?;
    ensure_seeded()?;
    let op = target.rsplit('.').next().unwrap_or(target);
    let input = arg_value(args, 0, context);
    match op {
        "seed_vuln_intel_priority_profile" => seed_vuln_intel_priority_profile(&input),
        "prepare_repointel_health" => prepare_repointel_health(&input),
        "record_downstream_service_connection_test" => {
            record_downstream_service_connection_test(&input, &arg_value(args, 1, context))
        }
        "prepare_repointel_search_sources" => prepare_repointel_search(&input, "sources"),
        "prepare_repointel_search_raw_records" => prepare_repointel_search(&input, "raw-records"),
        "prepare_repointel_search_arts" => prepare_repointel_search(&input, "arts"),
        "prepare_repointel_search_authors" => prepare_repointel_search(&input, "authors"),
        "plan_run" => plan_run(
            &input,
            &arg_value(args, 1, context),
            &arg_value(args, 2, context),
            &arg_value(args, 3, context),
            &arg_value(args, 4, context),
        ),
        "create_run" => create_run(
            &input,
            &arg_value(args, 1, context),
            &arg_value(args, 2, context),
            &arg_value(args, 3, context),
            &arg_value(args, 4, context),
        ),
        "prepare_metadata_bulk_upsert" => prepare_metadata_bulk_upsert(&input),
        "prepare_relationship_bulk_upsert" => {
            prepare_relationship_bulk_upsert(&input, &arg_value(args, 1, context))
        }
        "finish_commit" => finish_commit(
            &input,
            &arg_value(args, 1, context),
            &arg_value(args, 2, context),
        ),
        "prepare_evidence_hit_raw_record" => prepare_evidence_hit_fetch(&input, "raw_record_id"),
        "prepare_evidence_hit_art" => prepare_evidence_hit_fetch(&input, "art_id"),
        "record_evidence_hit_downstream_read" => {
            record_evidence_hit_downstream_read(&input, &arg_value(args, 1, context))
        }
        "bulk_review_evidence_hits" => bulk_review_evidence_hits(&input),
        "accept_evidence_hit" => disposition_update(&input, "accepted", ""),
        "reject_evidence_hit" => {
            disposition_update(&input, "rejected", &text_field(&input, "reason"))
        }
        "cancel_run" => status_update("runs", "collection_run_id", &input, "canceled"),
        "pause_run" => status_update("runs", "collection_run_id", &input, "paused"),
        "resume_run" => status_update("runs", "collection_run_id", &input, "queued"),
        "retry_run" => status_update("runs", "collection_run_id", &input, "queued"),
        "enable_bundle" => bool_update("extractor-bundles", "bundle_id", &input, "enabled", true),
        "disable_bundle" => bool_update("extractor-bundles", "bundle_id", &input, "enabled", false),
        "enable_rule" => bool_update("extractor-rules", "rule_id", &input, "enabled", true),
        "disable_rule" => bool_update("extractor-rules", "rule_id", &input, "enabled", false),
        "get_profile_scenarios" => member_page("scenarios", "profile_id", "profile_id", &input),
        "get_profile_bundles" => {
            member_page("extractor-bundles", "profile_id", "profile_id", &input)
        }
        "get_scenario_rules" => {
            member_page("extractor-rules", "scenario_id", "scenario_id", &input)
        }
        "get_bundle_rules" => member_page("extractor-rules", "bundle_id", "bundle_id", &input),
        "get_run_evidence_hits" => member_page(
            "evidence-hits",
            "collection_run_id",
            "collection_run_id",
            &input,
        ),
        "get_run_downstream_calls" => member_page(
            "downstream-calls",
            "collection_run_id",
            "collection_run_id",
            &input,
        ),
        "create_coverage_report" => create_coverage_report(&input),
        "get_latest_coverage_report" => get_latest_coverage_report(&input),
        "list_scores" => list_scores(&input),
        "get_score" => get_score(&input),
        "compute_score" => compute_score(&input),
        "list_score_buckets" => list_score_buckets(&input),
        "get_score_bucket" => get_score_bucket(&input),
        "compute_score_bucket" => compute_score_bucket(&input),
        "list_keyword_configs" => list_keyword_configs(&input),
        "get_keyword_config" => get_keyword_config(&input),
        "resolve_keyword_config" => resolve_keyword_config(&input),
        "save_keyword_config" => save_keyword_config(&input),
        "adjust_keyword_config" => adjust_keyword_config(&input),
        "prepare_szz_batch_analysis" => prepare_szz_analysis(&input, "batch"),
        "prepare_szz_review_analysis" => prepare_szz_analysis(&input, "review"),
        "store_szz_analysis_result" => {
            store_szz_analysis_result(&input, &arg_value(args, 1, context))
        }
        other if other.starts_with("list_") => {
            let meta = collection_for_op(other.trim_start_matches("list_"))?;
            list_records(meta.collection, &input)
        }
        other if other.starts_with("search_") => {
            let meta = collection_for_op(other.trim_start_matches("search_"))?;
            search_records(meta.collection, &input)
        }
        other if other.starts_with("create_") => {
            let meta = collection_for_op(other.trim_start_matches("create_"))?;
            create_record(meta.collection, &input)
        }
        other if other.starts_with("get_") => {
            let meta = collection_for_op(other.trim_start_matches("get_"))?;
            get_record_by_input(meta.collection, meta.key, &input)
        }
        other if other.starts_with("update_") => {
            let meta = collection_for_op(other.trim_start_matches("update_"))?;
            update_record(meta.collection, meta.key, &input)
        }
        other if other.starts_with("delete_") => {
            let meta = collection_for_op(other.trim_start_matches("delete_"))?;
            delete_record(meta.collection, meta.key, &input)
        }
        other => Err(ApiError::internal(format!(
            "metadata collection operation {other} is not implemented"
        ))),
    }
}

fn test_rule(args: &[String], context: &FlowContext) -> Result<Value, ApiError> {
    ensure_seeded()?;
    let input = arg_value(args, 0, context);
    let rule_id = text_field(&input, "rule_id");
    let rule = get_record("extractor-rules", &rule_id)?;
    let mut record = Map::new();
    record.insert(
        "repository_id".to_string(),
        json!(text_field(&input, "repository_id")),
    );
    record.insert(
        "source_id".to_string(),
        json!(text_field(&input, "source_id")),
    );
    record.insert(
        "raw_record_id".to_string(),
        json!(text_field(&input, "sample_raw_record_id")),
    );
    record.insert(
        "art_id".to_string(),
        json!(text_field(&input, "sample_art_id")),
    );
    record.insert("source_kind".to_string(), json!("art"));
    record.insert(
        "body".to_string(),
        input.get("sample_body").cloned().unwrap_or(Value::Null),
    );
    record.insert(
        "payload".to_string(),
        input.get("sample_payload").cloned().unwrap_or(Value::Null),
    );
    let hits = extract_hits_for_item(
        &Value::Object(record),
        &[rule.clone()],
        None,
        text_field(&rule, "scenario_id"),
        BUNDLE_ID.to_string(),
        false,
        number_field(&rule, "min_confidence", 0.8),
        number_field(&rule, "review_required_below_confidence", 0.8),
    );
    Ok(json!({
        "ok": true,
        "rule_id": rule_id,
        "rule_version": text_field(&rule, "version"),
        "evidence_hits": hits,
        "proposed_metadata_count": hits.iter().map(|hit| hit.get("proposed_metadata").and_then(Value::as_array).map(Vec::len).unwrap_or(0)).sum::<usize>(),
        "proposed_relationships_count": hits.iter().map(|hit| hit.get("proposed_relationships").and_then(Value::as_array).map(Vec::len).unwrap_or(0)).sum::<usize>(),
        "logs": ["rule test executed locally"],
        "details": { "rule_slug": text_field(&rule, "slug") }
    }))
}

fn prepare_repointel_search(input: &Value, collection: &str) -> Result<Value, ApiError> {
    let selector = input.get("selector").unwrap_or(input);
    let mut filters = object_from(selector.get("filters").unwrap_or(&Value::Null));
    copy_filter(selector, &mut filters, "repository_id");
    copy_filter(selector, &mut filters, "source_id");
    match collection {
        "sources" => {
            copy_array_filter(selector, &mut filters, "source_ids", "id");
            copy_array_filter(selector, &mut filters, "source_types", "type");
            copy_array_filter(selector, &mut filters, "providers", "provider");
        }
        "raw-records" => {
            copy_array_filter(selector, &mut filters, "raw_record_ids", "id");
            copy_array_filter(selector, &mut filters, "raw_record_types", "record_type");
        }
        "arts" => {
            copy_array_filter(selector, &mut filters, "art_ids", "id");
            copy_array_filter(selector, &mut filters, "art_types", "type");
        }
        "authors" => {
            copy_array_filter(selector, &mut filters, "author_ids", "id");
        }
        _ => {}
    }
    Ok(json!({
        "query": text_field(selector, "query"),
        "filters": filters,
        "cursor": text_field(selector, "cursor"),
        "limit": number_field(selector, "limit", 1000.0) as i64,
        "_frontplane_auth_token": downstream_token()
    }))
}

fn copy_filter(source: &Value, target: &mut Map<String, Value>, field: &str) {
    if let Some(value) = source.get(field).filter(|value| !is_empty_value(value)) {
        target.insert(field.to_string(), value.clone());
    }
}

fn copy_array_filter(source: &Value, target: &mut Map<String, Value>, from: &str, to: &str) {
    if let Some(values) = source.get(from).and_then(Value::as_array) {
        if values.len() == 1 {
            target.insert(to.to_string(), values[0].clone());
        }
    }
}

fn prepare_repointel_health(input: &Value) -> Result<Value, ApiError> {
    let downstream_service_id = text_field(input, "downstream_service_id");
    let service_config = get_record("downstream-services", &downstream_service_id)?;
    if !is_repointel_downstream_service(&service_config) {
        return Err(ApiError::bad_request(
            "test-connection is wired to the declared RepointelFacade.health provider edge; configure other providers through generated provider endpoint settings",
        ));
    }
    Ok(json!({}))
}

fn is_repointel_downstream_service(service_config: &Value) -> bool {
    [
        value_text(service_config, "kind"),
        value_text(service_config, "name"),
        value_text(service_config, "id"),
    ]
    .iter()
    .any(|value| value.to_ascii_lowercase().contains("repointel"))
}

fn record_downstream_service_connection_test(
    input: &Value,
    downstream_health: &Value,
) -> Result<Value, ApiError> {
    let downstream_service_id = text_field(input, "downstream_service_id");
    let service_config = get_record("downstream-services", &downstream_service_id)?;
    let service = downstream_health
        .get("service")
        .and_then(Value::as_str)
        .unwrap_or("RepointelFacade")
        .to_string();
    trace_downstream(
        "",
        "",
        &downstream_service_id,
        "RepointelFacade.health",
        "GET",
        "/healthz",
        200,
        "",
    )?;
    Ok(json!({
        "ok": true,
        "downstream_service_id": downstream_service_id,
        "service": service,
        "status_code": 200,
        "latency_ms": 0,
        "message": "generated RepointelFacade.health provider call succeeded",
        "details": {
            "health": downstream_health,
            "configured_service": {
                "id": value_text(&service_config, "id"),
                "name": value_text(&service_config, "name"),
                "kind": value_text(&service_config, "kind"),
                "base_url": value_text(&service_config, "base_url")
            },
            "routing": "provider routing is controlled by METADATACOLLECTIONFACADE_PROVIDER_ENDPOINTS_JSON and generated Frontplane provider config"
        }
    }))
}

fn plan_run(
    input: &Value,
    sources_page: &Value,
    raw_records_page: &Value,
    arts_page: &Value,
    authors_page: &Value,
) -> Result<Value, ApiError> {
    let profile_id = text_field(input, "profile_id");
    let scenarios = selected_records(
        "scenarios",
        input,
        "scenario_ids",
        "profile_id",
        &profile_id,
    )?;
    let bundles = selected_records(
        "extractor-bundles",
        input,
        "bundle_ids",
        "profile_id",
        &profile_id,
    )?;
    let rules = selected_rules(input, &profile_id)?;
    let raw_count = page_items(raw_records_page).len();
    let art_count = page_items(arts_page).len();
    let mut gaps = Vec::new();
    if rules.is_empty() {
        gaps.push(json!("rules_disabled"));
    }
    if raw_count == 0 && art_count == 0 {
        gaps.push(json!("insufficient_art_body_text"));
    }
    Ok(json!({
        "id": format!("plan-{}", stable_hash(&format!("{}|{}", profile_id, now_timestamp()))),
        "profile_id": profile_id,
        "selector": input.get("selector").cloned().unwrap_or(Value::Null),
        "repositories_count": if text_field(input.get("selector").unwrap_or(input), "repository_id").is_empty() { 0 } else { 1 },
        "sources_count": page_items(sources_page).len(),
        "raw_records_count": raw_count,
        "arts_count": art_count,
        "authors_count": page_items(authors_page).len(),
        "scenarios_count": scenarios.len(),
        "bundles_count": bundles.len(),
        "rules_count": rules.len(),
        "estimated_work_units": ((raw_count + art_count) * rules.len()) as i64,
        "can_run": !rules.is_empty() && (raw_count + art_count) > 0,
        "warnings": [],
        "gaps": gaps,
        "created_at": now_timestamp()
    }))
}

fn create_run(
    input: &Value,
    sources_page: &Value,
    raw_records_page: &Value,
    arts_page: &Value,
    authors_page: &Value,
) -> Result<Value, ApiError> {
    let profile_id = text_field(input, "profile_id");
    let rules = selected_rules(input, &profile_id)?;
    let auto_commit = bool_field(input, "auto_commit", false);
    let min_confidence = number_field(input, "min_confidence", 0.85);
    let review_below = number_field(input, "review_below_confidence", min_confidence);
    let mut run = object_from(input);
    run.insert("status".to_string(), json!("completed"));
    run.insert("started_at".to_string(), json!(now_timestamp()));
    run.insert("finished_at".to_string(), json!(now_timestamp()));
    run.insert("duration_ms".to_string(), json!(0));
    run.insert(
        "sources_scanned_count".to_string(),
        json!(page_items(sources_page).len()),
    );
    run.insert(
        "raw_records_scanned_count".to_string(),
        json!(page_items(raw_records_page).len()),
    );
    run.insert(
        "arts_scanned_count".to_string(),
        json!(page_items(arts_page).len()),
    );
    run.insert(
        "authors_scanned_count".to_string(),
        json!(page_items(authors_page).len()),
    );
    run.insert(
        "repository_id".to_string(),
        input
            .get("selector")
            .map(|selector| text_field(selector, "repository_id"))
            .unwrap_or_default()
            .into(),
    );
    let run_value = create_record("runs", &Value::Object(run))?;
    let run_id = value_text(&run_value, "id");
    let mut hits = Vec::new();
    for raw in page_items(raw_records_page) {
        hits.extend(extract_hits_for_item(
            &normalize_raw_input(&raw),
            &rules,
            Some(run_id.clone()),
            String::new(),
            BUNDLE_ID.to_string(),
            auto_commit,
            min_confidence,
            review_below,
        ));
    }
    for art in page_items(arts_page) {
        hits.extend(extract_hits_for_item(
            &normalize_art_input(&art),
            &rules,
            Some(run_id.clone()),
            String::new(),
            BUNDLE_ID.to_string(),
            auto_commit,
            min_confidence,
            review_below,
        ));
    }
    let mut accepted = 0;
    let mut review = 0;
    let mut hit_count = 0;
    let mut metadata_count = 0;
    let mut relationship_count = 0;
    for hit in hits {
        hit_count += 1;
        if value_text(&hit, "disposition") == "accepted" {
            accepted += 1;
        }
        if value_text(&hit, "disposition") == "needs_review" {
            review += 1;
        }
        metadata_count += hit
            .get("proposed_metadata")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        relationship_count += hit
            .get("proposed_relationships")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        upsert_evidence_hit(&hit)?;
    }
    let mut patch = Map::new();
    patch.insert("collection_run_id".to_string(), json!(run_id));
    patch.insert("evidence_hits_count".to_string(), json!(hit_count));
    patch.insert("accepted_hits_count".to_string(), json!(accepted));
    patch.insert("review_hits_count".to_string(), json!(review));
    patch.insert("rejected_hits_count".to_string(), json!(0));
    patch.insert("metadata_proposed_count".to_string(), json!(metadata_count));
    patch.insert(
        "relationships_proposed_count".to_string(),
        json!(relationship_count),
    );
    patch.insert("downstream_calls_count".to_string(), json!(4));
    trace_downstream(
        &run_id,
        "",
        "",
        "RepointelFacade.search_sources",
        "POST",
        "/sources:search",
        0,
        GENERATED_NCALL_STATUS_UNAVAILABLE,
    )?;
    trace_downstream(
        &run_id,
        "",
        "",
        "RepointelFacade.search_raw_records",
        "POST",
        "/raw-records:search",
        0,
        GENERATED_NCALL_STATUS_UNAVAILABLE,
    )?;
    trace_downstream(
        &run_id,
        "",
        "",
        "RepointelFacade.search_arts",
        "POST",
        "/arts:search",
        0,
        GENERATED_NCALL_STATUS_UNAVAILABLE,
    )?;
    trace_downstream(
        &run_id,
        "",
        "",
        "RepointelFacade.search_authors",
        "POST",
        "/authors:search",
        0,
        GENERATED_NCALL_STATUS_UNAVAILABLE,
    )?;
    update_record("runs", "collection_run_id", &Value::Object(patch))
}

fn normalize_raw_input(raw: &Value) -> Value {
    let mut object = object_from(raw);
    object.insert("source_kind".to_string(), json!("raw_record"));
    if !object.contains_key("raw_record_id") {
        object.insert("raw_record_id".to_string(), json!(value_text(raw, "id")));
    }
    Value::Object(object)
}

fn normalize_art_input(art: &Value) -> Value {
    let mut object = object_from(art);
    object.insert("source_kind".to_string(), json!("art"));
    if !object.contains_key("art_id") {
        object.insert("art_id".to_string(), json!(value_text(art, "id")));
    }
    Value::Object(object)
}

fn extract_hits_for_item(
    item: &Value,
    rules: &[Value],
    run_id: Option<String>,
    scenario_id_hint: String,
    bundle_id_hint: String,
    auto_commit: bool,
    min_confidence: f64,
    review_below: f64,
) -> Vec<Value> {
    let text = extraction_text(item);
    if text.trim().is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for rule in rules
        .iter()
        .filter(|rule| bool_field(rule, "enabled", true))
    {
        let rule_slug = text_field(rule, "slug");
        let scenario_id = first_non_empty(&[
            text_field(rule, "scenario_id"),
            scenario_id_hint.clone(),
            scenario_for_rule(&rule_slug),
        ]);
        let bundle_id = first_non_empty(&[text_field(rule, "bundle_id"), bundle_id_hint.clone()]);
        let matches = match_rule(&rule_slug, rule, &text);
        for m in matches {
            let confidence = number_field(rule, "default_confidence", m.confidence);
            let disposition = if auto_commit && confidence >= min_confidence {
                "accepted"
            } else if confidence < review_below || scenario_requires_review(&scenario_id) {
                "needs_review"
            } else {
                "proposed"
            };
            let value = m.value.clone();
            let namespace = m.namespace.clone();
            let key = m.key.clone();
            let value_type = m.value_type.clone();
            let value_hash = stable_hash(&value.to_string());
            let hit_hash = stable_hash(&format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                value_text(item, "repository_id"),
                value_text(item, "source_id"),
                value_text(item, "raw_record_id"),
                value_text(item, "art_id"),
                text_field(rule, "id"),
                text_field(rule, "version"),
                m.field_path,
                m.start,
                m.end,
                namespace,
                value_hash
            ));
            let metadata_ref = format!("metadata_{}", stable_hash(&hit_hash));
            let metadata = json!({
                "local_ref": metadata_ref,
                "repository_id": value_text(item, "repository_id"),
                "source_id": value_text(item, "source_id"),
                "ingestion_job_id": value_text(item, "ingestion_job_id"),
                "raw_record_id": value_text(item, "raw_record_id"),
                "subject_type": if value_text(item, "art_id").is_empty() { "raw_record" } else { "art" },
                "subject_id": first_non_empty(&[value_text(item, "art_id"), value_text(item, "raw_record_id")]),
                "namespace": namespace,
                "key": key,
                "value": value,
                "value_type": value_type,
                "dedupe_key": hit_hash,
                "role": if m.canonical { "canonical_node" } else { "extracted_fact" }
            });
            let mut relationships = Vec::new();
            if !value_text(item, "art_id").is_empty() {
                relationships.push(json!({
                    "local_ref": format!("rel_{}", stable_hash(&(hit_hash.clone() + "|mentions"))),
                    "repository_id": value_text(item, "repository_id"),
                    "source_id": value_text(item, "source_id"),
                    "ingestion_job_id": value_text(item, "ingestion_job_id"),
                    "raw_record_id": value_text(item, "raw_record_id"),
                    "from": { "type": "art", "id": value_text(item, "art_id") },
                    "relation": "mentions",
                    "to": { "type": "metadata", "metadata_local_ref": metadata_ref },
                    "confidence": confidence,
                    "evidence_art_id": value_text(item, "art_id"),
                    "origin": format!("metadata-collection:{}:{}", rule_slug, text_field(rule, "version")),
                    "dedupe_key": hit_hash
                }));
            }
            if !value_text(item, "author_id").is_empty() && !value_text(item, "art_id").is_empty() {
                relationships.push(json!({
                    "local_ref": format!("rel_{}", stable_hash(&(hit_hash.clone() + "|authored_by"))),
                    "repository_id": value_text(item, "repository_id"),
                    "source_id": value_text(item, "source_id"),
                    "ingestion_job_id": value_text(item, "ingestion_job_id"),
                    "raw_record_id": value_text(item, "raw_record_id"),
                    "from": { "type": "art", "id": value_text(item, "art_id") },
                    "relation": "authored_by",
                    "to": { "type": "author", "id": value_text(item, "author_id") },
                    "confidence": 1.0,
                    "evidence_art_id": value_text(item, "art_id"),
                    "origin": "metadata-collection:author-link",
                    "dedupe_key": hit_hash
                }));
            }
            hits.push(json!({
                "id": format!("evidence-hit-{hit_hash}"),
                "collection_run_id": run_id.clone().unwrap_or_default(),
                "profile_id": PROFILE_ID,
                "scenario_id": scenario_id,
                "bundle_id": bundle_id,
                "rule_id": text_field(rule, "id"),
                "rule_version": text_field(rule, "version"),
                "repository_id": value_text(item, "repository_id"),
                "source_id": value_text(item, "source_id"),
                "ingestion_job_id": value_text(item, "ingestion_job_id"),
                "raw_record_id": value_text(item, "raw_record_id"),
                "art_id": value_text(item, "art_id"),
                "author_id": value_text(item, "author_id"),
                "source_kind": text_field(item, "source_kind"),
                "source_field_path": m.field_path,
                "evidence_span_start": m.start,
                "evidence_span_end": m.end,
                "matched_text_hash": stable_hash(&m.matched_text),
                "matched_text_preview": preview(&m.matched_text, 180),
                "namespace": namespace,
                "key": key,
                "value": m.value,
                "value_type": m.value_type,
                "canonical_value": m.canonical_value,
                "value_hash": value_hash,
                "confidence": confidence,
                "disposition": disposition,
                "disposition_reason": "",
                "origin": format!("metadata-collection:{}", rule_slug),
                "hit_hash": hit_hash,
                "proposed_metadata": [metadata],
                "proposed_relationships": relationships,
                "committed_metadata_ids": [],
                "committed_relationship_ids": [],
                "created_at": now_timestamp(),
                "updated_at": now_timestamp()
            }));
        }
    }
    hits
}

#[derive(Clone)]
struct MatchOut {
    namespace: String,
    key: String,
    value: Value,
    value_type: String,
    canonical_value: Value,
    field_path: String,
    start: usize,
    end: usize,
    matched_text: String,
    confidence: f64,
    canonical: bool,
}

fn match_rule(rule_slug: &str, rule: &Value, text: &str) -> Vec<MatchOut> {
    let lower = text.to_lowercase();
    let mut matches = Vec::new();
    if rule_slug.contains("cve") {
        for (start, value) in scan_cve(text) {
            matches.push(match_out(
                "security.identifier",
                "cve",
                json!(value.to_uppercase()),
                "body",
                start,
                start + value.len(),
                0.98,
                true,
                text_slice(text, start, start + value.len()).as_str(),
            ));
        }
    } else if rule_slug.contains("ghsa") {
        for (start, value) in scan_ghsa(text) {
            matches.push(match_out(
                "security.identifier",
                "ghsa",
                json!(value.to_uppercase()),
                "body",
                start,
                start + value.len(),
                0.98,
                true,
                text_slice(text, start, start + value.len()).as_str(),
            ));
        }
    } else if rule_slug.contains("security_fix") || rule_slug.contains("suspected_security_fix") {
        for term in [
            "security fix",
            "vulnerability",
            "authorization bypass",
            "authentication bypass",
            "privilege escalation",
            "credential exposure",
            "secret leak",
        ] {
            if let Some(start) = lower.find(term) {
                matches.push(match_out(
                    "security.signal",
                    "suspected_security_fix",
                    json!({ "term": term }),
                    "body",
                    start,
                    start + term.len(),
                    0.88,
                    false,
                    text_slice(text, start, start + term.len()).as_str(),
                ));
            }
        }
    } else if rule_slug.contains("review_security_concern") {
        for term in [
            "security concern",
            "unsafe",
            "bypass",
            "permission",
            "credential",
            "token exposure",
        ] {
            if let Some(start) = lower.find(term) {
                matches.push(match_out(
                    "security.review",
                    "concern",
                    json!({ "term": term }),
                    "body",
                    start,
                    start + term.len(),
                    0.75,
                    false,
                    text_slice(text, start, start + term.len()).as_str(),
                ));
            }
        }
    } else if rule_slug.contains("fix_issue_reference") {
        for verb in ["fixes #", "closes #", "resolves #"] {
            if let Some(start) = lower.find(verb) {
                let number = lower[start + verb.len()..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect::<String>();
                if !number.is_empty() {
                    matches.push(match_out(
                        "issue.reference",
                        "local_id",
                        json!({ "id": number, "verb": verb.trim() }),
                        "body",
                        start,
                        start + verb.len() + number.len(),
                        0.93,
                        true,
                        text_slice(text, start, start + verb.len() + number.len()).as_str(),
                    ));
                }
            }
        }
    } else if rule_slug.contains("revert") || rule_slug.contains("cherry") {
        if let Some(start) = lower.find("revert") {
            matches.push(match_out(
                "git.commit",
                "revert_or_cherry_pick",
                json!({ "kind": "revert" }),
                "body",
                start,
                start + 6,
                0.9,
                false,
                text_slice(text, start, start + 6).as_str(),
            ));
        }
        if let Some(start) = lower.find("cherry picked from commit") {
            matches.push(match_out(
                "git.commit",
                "revert_or_cherry_pick",
                json!({ "kind": "cherry_pick" }),
                "body",
                start,
                start + 25,
                0.92,
                false,
                text_slice(text, start, start + 25).as_str(),
            ));
        }
    } else if rule_slug.contains("workflow") {
        for term in [
            "pull_request_target",
            "permissions: write-all",
            "contents: write",
        ] {
            if let Some(start) = lower.find(term) {
                matches.push(match_out(
                    "workflow.permission",
                    "risk",
                    json!({ "term": term }),
                    "body",
                    start,
                    start + term.len(),
                    0.9,
                    false,
                    text_slice(text, start, start + term.len()).as_str(),
                ));
            }
        }
    } else if rule_slug.contains("dependency") {
        for term in [
            "package-lock.json",
            "requirements.txt",
            "pom.xml",
            "go.mod",
            "cargo.lock",
        ] {
            if let Some(start) = lower.find(term) {
                matches.push(match_out(
                    "dependency.manifest",
                    "path",
                    json!(term),
                    "body",
                    start,
                    start + term.len(),
                    0.86,
                    true,
                    text_slice(text, start, start + term.len()).as_str(),
                ));
            }
        }
    } else if rule_slug.contains("component") || rule_slug.contains("path") {
        for term in [
            "auth",
            "policy",
            "token",
            "credential",
            "session",
            "permission",
        ] {
            if let Some(start) = lower.find(term) {
                matches.push(match_out(
                    "code.component",
                    "name",
                    json!(term),
                    "body",
                    start,
                    start + term.len(),
                    0.86,
                    true,
                    text_slice(text, start, start + term.len()).as_str(),
                ));
            }
        }
    } else if let Some(pattern) = rule.get("pattern").and_then(Value::as_str) {
        if !pattern.is_empty() {
            if let Some(start) = lower.find(&pattern.to_lowercase()) {
                matches.push(match_out(
                    "extraction.regex",
                    "match",
                    json!(pattern),
                    "body",
                    start,
                    start + pattern.len(),
                    number_field(rule, "default_confidence", 0.8),
                    false,
                    text_slice(text, start, start + pattern.len()).as_str(),
                ));
            }
        }
    }
    matches
}

fn match_out(
    namespace: &str,
    key: &str,
    value: Value,
    field_path: &str,
    start: usize,
    end: usize,
    confidence: f64,
    canonical: bool,
    matched_text: &str,
) -> MatchOut {
    MatchOut {
        namespace: namespace.to_string(),
        key: key.to_string(),
        value_type: match value {
            Value::String(_) => "string",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            Value::Null => "null",
        }
        .to_string(),
        canonical_value: value.clone(),
        matched_text: matched_text.to_string(),
        value,
        field_path: field_path.to_string(),
        start,
        end,
        confidence,
        canonical,
    }
}

fn text_slice(text: &str, start: usize, end: usize) -> String {
    text.get(start..end).unwrap_or_default().to_string()
}

fn scan_cve(text: &str) -> Vec<(usize, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for start in 0..bytes.len().saturating_sub(8) {
        if !text[start..].to_uppercase().starts_with("CVE-") {
            continue;
        }
        let tail = &text[start + 4..];
        let mut parts = tail.splitn(3, '-');
        let Some(year) = parts.next() else { continue };
        let Some(seq_rest) = parts.next() else {
            continue;
        };
        if year.len() == 4 && year.chars().all(|ch| ch.is_ascii_digit()) {
            let seq = seq_rest
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>();
            if seq.len() >= 4 {
                out.push((start, format!("CVE-{year}-{seq}")));
            }
        }
    }
    out
}

fn scan_ghsa(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let upper = text.to_uppercase();
    let chars = upper.as_bytes();
    for start in 0..chars.len().saturating_sub(19) {
        if !upper[start..].starts_with("GHSA-") {
            continue;
        }
        let candidate = &upper[start..(start + 19).min(upper.len())];
        if candidate.len() == 19
            && candidate.chars().enumerate().all(|(idx, ch)| {
                matches!(idx, 4 | 9 | 14) && ch == '-'
                    || (!matches!(idx, 4 | 9 | 14) && ch.is_ascii_alphanumeric())
            })
        {
            out.push((start, candidate.to_string()));
        }
    }
    out
}

fn extraction_text(item: &Value) -> String {
    let mut parts = Vec::new();
    for field in ["body", "message", "title", "description", "summary"] {
        if let Some(text) = item.get(field).and_then(Value::as_str) {
            parts.push(text.to_string());
        }
    }
    if let Some(payload) = item.get("payload") {
        collect_text(payload, &mut parts);
    }
    if parts.is_empty() {
        parts.push(item.to_string());
    }
    parts.join("\n")
}

fn collect_text(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_text(item, out);
            }
        }
        Value::Object(object) => {
            for value in object.values() {
                collect_text(value, out);
            }
        }
        _ => {}
    }
}

fn prepare_metadata_bulk_upsert(input: &Value) -> Result<Value, ApiError> {
    let hits = committable_hits(input)?;
    let mut items = Vec::new();
    for hit in &hits {
        for proposal in hit
            .get("proposed_metadata")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            items.push(json!({
                "repository_id": value_text(&proposal, "repository_id"),
                "source_id": value_text(&proposal, "source_id"),
                "ingestion_job_id": value_text(&proposal, "ingestion_job_id"),
                "raw_record_id": value_text(&proposal, "raw_record_id"),
                "subject_type": value_text(&proposal, "subject_type"),
                "subject_id": value_text(&proposal, "subject_id"),
                "namespace": value_text(&proposal, "namespace"),
                "key": value_text(&proposal, "key"),
                "value": proposal.get("value").cloned().unwrap_or(Value::Null),
                "value_type": value_text(&proposal, "value_type")
            }));
        }
    }
    Ok(json!({
        "items": if bool_field(input, "dry_run", false) { Vec::<Value>::new() } else { items },
        "_frontplane_auth_token": downstream_token()
    }))
}

fn prepare_relationship_bulk_upsert(
    input: &Value,
    metadata_page: &Value,
) -> Result<Value, ApiError> {
    let hits = committable_hits(input)?;
    let metadata_map = metadata_local_ref_map(&hits, metadata_page);
    let mut relationships = Vec::new();
    for hit in &hits {
        for proposal in hit
            .get("proposed_relationships")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let from =
                resolve_endpoint(proposal.get("from").unwrap_or(&Value::Null), &metadata_map);
            let to = resolve_endpoint(proposal.get("to").unwrap_or(&Value::Null), &metadata_map);
            if let (Some((from_type, from_id)), Some((to_type, to_id))) = (from, to) {
                relationships.push(json!({
                    "repository_id": value_text(&proposal, "repository_id"),
                    "source_id": value_text(&proposal, "source_id"),
                    "ingestion_job_id": value_text(&proposal, "ingestion_job_id"),
                    "raw_record_id": value_text(&proposal, "raw_record_id"),
                    "from_type": from_type,
                    "from_id": from_id,
                    "to_type": to_type,
                    "to_id": to_id,
                    "relation": value_text(&proposal, "relation"),
                    "direction": value_text(&proposal, "direction"),
                    "confidence": number_field(&proposal, "confidence", 0.0),
                    "evidence_art_id": value_text(&proposal, "evidence_art_id"),
                    "evidence_metadata_id": metadata_map.get(&value_text(&proposal, "evidence_metadata_local_ref")).cloned().unwrap_or_default(),
                    "origin": value_text(&proposal, "origin")
                }));
            }
        }
    }
    Ok(json!({
        "relationships": if bool_field(input, "dry_run", false) { Vec::<Value>::new() } else { relationships },
        "_frontplane_auth_token": downstream_token()
    }))
}

fn metadata_local_ref_map(hits: &[Value], metadata_page: &Value) -> BTreeMap<String, String> {
    let mut local_refs = Vec::new();
    for hit in hits {
        for proposal in hit
            .get("proposed_metadata")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            local_refs.push(value_text(&proposal, "local_ref"));
        }
    }
    let mut map = BTreeMap::new();
    for (idx, item) in page_items(metadata_page).into_iter().enumerate() {
        if let Some(local_ref) = local_refs.get(idx) {
            map.insert(local_ref.clone(), value_text(&item, "id"));
        }
    }
    map
}

fn resolve_endpoint(
    endpoint: &Value,
    metadata_map: &BTreeMap<String, String>,
) -> Option<(String, String)> {
    let endpoint_type = text_field(endpoint, "type");
    if !valid_endpoint_type(&endpoint_type) {
        return None;
    }
    let id = first_non_empty(&[
        text_field(endpoint, "id"),
        metadata_map
            .get(&text_field(endpoint, "metadata_local_ref"))
            .cloned()
            .unwrap_or_default(),
    ]);
    if id.is_empty() {
        None
    } else {
        Some((endpoint_type, id))
    }
}

fn finish_commit(
    input: &Value,
    metadata_page: &Value,
    relationship_page: &Value,
) -> Result<Value, ApiError> {
    let hits = committable_hits(input)?;
    let metadata_ids = page_items(metadata_page)
        .into_iter()
        .map(|item| value_text(&item, "id"))
        .filter(|id| !id.is_empty())
        .collect::<Vec<_>>();
    let relationship_ids = page_items(relationship_page)
        .into_iter()
        .map(|item| value_text(&item, "id"))
        .filter(|id| !id.is_empty())
        .collect::<Vec<_>>();
    let mut committed = 0;
    for hit in &hits {
        let mut patch = Map::new();
        patch.insert("evidence_hit_id".to_string(), json!(value_text(hit, "id")));
        patch.insert("disposition".to_string(), json!("committed"));
        patch.insert("committed_metadata_ids".to_string(), json!(metadata_ids));
        patch.insert(
            "committed_relationship_ids".to_string(),
            json!(relationship_ids),
        );
        update_record("evidence-hits", "evidence_hit_id", &Value::Object(patch))?;
        committed += 1;
    }
    if let Some(run_id) = first_run_id(input, &hits) {
        let mut patch = Map::new();
        patch.insert("collection_run_id".to_string(), json!(run_id.clone()));
        patch.insert(
            "metadata_upserted_count".to_string(),
            json!(metadata_ids.len()),
        );
        patch.insert(
            "relationships_upserted_count".to_string(),
            json!(relationship_ids.len()),
        );
        update_record("runs", "collection_run_id", &Value::Object(patch))?;
        trace_downstream(
            &run_id,
            "",
            "",
            "RepointelFacade.bulk_upsert_metadata",
            "POST",
            "/metadata:bulk-upsert",
            0,
            GENERATED_NCALL_STATUS_UNAVAILABLE,
        )?;
        trace_downstream(
            &run_id,
            "",
            "",
            "RepointelFacade.bulk_upsert_relationships",
            "POST",
            "/relationships:bulk-upsert",
            0,
            GENERATED_NCALL_STATUS_UNAVAILABLE,
        )?;
    }
    Ok(json!({
        "ok": true,
        "collection_run_id": first_run_id(input, &hits).unwrap_or_default(),
        "evidence_hits_committed_count": committed,
        "metadata_upserted_count": metadata_ids.len(),
        "relationships_upserted_count": relationship_ids.len(),
        "skipped_count": 0,
        "failed_count": 0,
        "downstream_calls": [],
        "errors": [],
        "details": { "metadata_ids": metadata_ids, "relationship_ids": relationship_ids }
    }))
}

fn first_run_id(input: &Value, hits: &[Value]) -> Option<String> {
    let direct = text_field(input, "collection_run_id");
    if !direct.is_empty() {
        return Some(direct);
    }
    hits.first()
        .map(|hit| value_text(hit, "collection_run_id"))
        .filter(|id| !id.is_empty())
}

fn committable_hits(input: &Value) -> Result<Vec<Value>, ApiError> {
    let mut hits = read_collection("evidence-hits")?;
    let ids = string_set(input.get("evidence_hit_ids"));
    let run_id = text_field(input, "collection_run_id");
    let disposition_filter = text_field(input, "disposition_filter");
    let min_confidence = number_field(input, "min_confidence", 0.0);
    hits.retain(|hit| {
        (ids.is_empty() || ids.contains(&value_text(hit, "id")))
            && (run_id.is_empty() || value_text(hit, "collection_run_id") == run_id)
            && (disposition_filter.is_empty()
                || value_text(hit, "disposition") == disposition_filter
                || (disposition_filter == "proposed"
                    && matches!(
                        value_text(hit, "disposition").as_str(),
                        "proposed" | "accepted"
                    )))
            && number_field(hit, "confidence", 0.0) >= min_confidence
            && value_text(hit, "disposition") != "committed"
    });
    Ok(hits)
}

fn prepare_evidence_hit_fetch(input: &Value, field: &str) -> Result<Value, ApiError> {
    let hit = get_record_by_input("evidence-hits", "evidence_hit_id", input)?;
    let id = value_text(&hit, field);
    if id.is_empty() {
        return Err(ApiError::not_found(format!("evidence hit has no {field}")));
    }
    Ok(json!({
        field: id,
        "_frontplane_auth_token": downstream_token()
    }))
}

fn record_evidence_hit_downstream_read(input: &Value, response: &Value) -> Result<Value, ApiError> {
    let hit = get_record_by_input("evidence-hits", "evidence_hit_id", input)?;
    trace_downstream(
        &value_text(&hit, "collection_run_id"),
        &value_text(&hit, "id"),
        "",
        "RepointelFacade.get_record",
        "GET",
        "/raw-records|/arts",
        0,
        GENERATED_NCALL_STATUS_UNAVAILABLE,
    )?;
    Ok(response.clone())
}

fn bulk_review_evidence_hits(input: &Value) -> Result<Value, ApiError> {
    let ids = string_set(input.get("evidence_hit_ids"));
    let run_id = text_field(input, "collection_run_id");
    let disposition = text_field(input, "disposition");
    let mut reviewed = 0;
    let mut skipped = 0;
    let hits = read_collection("evidence-hits")?;
    for hit in hits {
        let matches = (ids.is_empty() || ids.contains(&value_text(&hit, "id")))
            && (run_id.is_empty() || value_text(&hit, "collection_run_id") == run_id);
        if matches {
            let mut patch = Map::new();
            patch.insert("evidence_hit_id".to_string(), json!(value_text(&hit, "id")));
            patch.insert("disposition".to_string(), json!(disposition));
            patch.insert(
                "disposition_reason".to_string(),
                input
                    .get("disposition_reason")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            patch.insert(
                "reviewer_note".to_string(),
                input.get("reviewer_note").cloned().unwrap_or(Value::Null),
            );
            patch.insert("reviewed_at".to_string(), json!(now_timestamp()));
            update_record("evidence-hits", "evidence_hit_id", &Value::Object(patch))?;
            reviewed += 1;
        } else {
            skipped += 1;
        }
    }
    Ok(json!({
        "ok": true,
        "reviewed_count": reviewed,
        "skipped_count": skipped,
        "errors": [],
        "details": {}
    }))
}

fn disposition_update(input: &Value, disposition: &str, reason: &str) -> Result<Value, ApiError> {
    let mut patch = object_from(input);
    patch.insert("disposition".to_string(), json!(disposition));
    if !reason.is_empty() {
        patch.insert("disposition_reason".to_string(), json!(reason));
    }
    patch.insert("reviewed_at".to_string(), json!(now_timestamp()));
    update_record("evidence-hits", "evidence_hit_id", &Value::Object(patch))
}

fn create_coverage_report(input: &Value) -> Result<Value, ApiError> {
    let profile_id = text_field(input, "profile_id");
    let scenarios = selected_records(
        "scenarios",
        input,
        "scenario_ids",
        "profile_id",
        &profile_id,
    )?;
    let hits = read_collection("evidence-hits")?;
    let mut scenario_rows = Vec::new();
    for scenario in scenarios {
        let scenario_id = value_text(&scenario, "id");
        let scenario_hits = hits
            .iter()
            .filter(|hit| value_text(hit, "scenario_id") == scenario_id)
            .count();
        let rules = selected_records(
            "extractor-rules",
            &json!({ "scenario_ids": [scenario_id.clone()] }),
            "scenario_ids",
            "scenario_id",
            &scenario_id,
        )?;
        scenario_rows.push(json!({
            "scenario_id": scenario_id,
            "scenario_slug": value_text(&scenario, "slug"),
            "priority": number_field(&scenario, "priority", 0.0) as i64,
            "feasible": !rules.is_empty(),
            "sources_available": true,
            "rules_enabled": !rules.is_empty(),
            "raw_records_available_count": 0,
            "arts_available_count": 0,
            "evidence_hits_count": scenario_hits,
            "committed_metadata_count": hits.iter().filter(|hit| value_text(hit, "scenario_id") == value_text(&scenario, "id") && value_text(hit, "disposition") == "committed").count(),
            "committed_relationships_count": 0,
            "gaps": if rules.is_empty() { vec![json!("rules_disabled")] } else { Vec::new() }
        }));
    }
    create_record(
        "coverage-reports",
        &json!({
            "profile_id": profile_id,
            "repository_id": input.get("selector").map(|selector| text_field(selector, "repository_id")).unwrap_or_default(),
            "source_ids": input.get("selector").and_then(|selector| selector.get("source_ids")).cloned().unwrap_or_else(|| json!([])),
            "scenarios": scenario_rows,
            "gaps": [],
            "generated_at": now_timestamp()
        }),
    )
}

fn get_latest_coverage_report(input: &Value) -> Result<Value, ApiError> {
    let profile_id = text_field(input, "profile_id");
    let mut reports = read_collection("coverage-reports")?;
    reports
        .retain(|report| profile_id.is_empty() || value_text(report, "profile_id") == profile_id);
    reports.sort_by_key(record_sort_key);
    reports
        .pop()
        .ok_or_else(|| ApiError::not_found("coverage report was not found"))
}

fn list_scores(input: &Value) -> Result<Value, ApiError> {
    let mut records = review_risk_score_definitions();
    records.retain(|record| record_matches_filter(record, input));
    Ok(page(records, input))
}

fn get_score(input: &Value) -> Result<Value, ApiError> {
    let score_id = id_from_input(input, "score_id")?;
    review_risk_score_definitions()
        .into_iter()
        .find(|record| value_text(record, "id") == score_id)
        .ok_or_else(|| ApiError::not_found(format!("score {score_id} was not found")))
}

fn compute_score(input: &Value) -> Result<Value, ApiError> {
    let score_id = id_from_input(input, "score_id")?;
    let definition = get_score(&json!({ "score_id": score_id.clone() }))?;
    let raw_score = score_input_value(input).ok_or_else(|| {
        ApiError::bad_request("score compute requires a numeric score or value.score")
    })?;
    let score = round_decimal(clamp_score_value(raw_score), 4);
    let confidence = round_decimal(clamp01_value(number_field(input, "confidence", 1.0)), 4);
    Ok(json!({
        "score_id": score_id,
        "subject_id": text_field(input, "subject_id"),
        "score": score,
        "confidence": confidence,
        "normalized": true,
        "details": {
            "direction": value_text(&definition, "direction"),
            "range": definition.get("range").cloned().unwrap_or_else(|| json!({ "min": 0, "max": 100 })),
            "input_value": input.get("value").cloned().unwrap_or(Value::Null),
            "version": value_text(&definition, "version")
        }
    }))
}

fn list_score_buckets(input: &Value) -> Result<Value, ApiError> {
    let mut records = review_risk_score_bucket_definitions();
    records.retain(|record| record_matches_filter(record, input));
    Ok(page(records, input))
}

fn get_score_bucket(input: &Value) -> Result<Value, ApiError> {
    let score_bucket_id = id_from_input(input, "score_bucket_id")?;
    review_risk_score_bucket_definitions()
        .into_iter()
        .find(|record| value_text(record, "id") == score_bucket_id)
        .ok_or_else(|| ApiError::not_found(format!("score bucket {score_bucket_id} was not found")))
}

fn compute_score_bucket(input: &Value) -> Result<Value, ApiError> {
    let score_bucket_id = id_from_input(input, "score_bucket_id")?;
    let bucket = get_score_bucket(&json!({ "score_bucket_id": score_bucket_id.clone() }))?;
    let input_items = input
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let missing_policy = input
        .get("params")
        .and_then(|params| params.get("missing_policy"))
        .and_then(Value::as_str)
        .unwrap_or("omit_missing");
    let mut results = Vec::new();
    let mut missing_score_ids = Vec::new();
    let mut weighted_sum = 0.0;
    let mut denominator = 0.0;
    for bucket_item in bucket
        .get("scores")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let score_id = value_text(&bucket_item, "score_id");
        let default_weight = number_field(&bucket_item, "weight", 1.0);
        let Some(input_item) = input_items
            .iter()
            .find(|item| value_text(item, "score_id") == score_id)
        else {
            missing_score_ids.push(score_id.clone());
            if missing_policy == "score_zero" {
                let effective_weight = default_weight.max(0.0);
                denominator += effective_weight;
                results.push(json!({
                    "score_id": score_id,
                    "subject_id": text_field(input, "subject_id"),
                    "score": 0.0,
                    "confidence": 1.0,
                    "normalized": true,
                    "details": {
                        "weight": default_weight,
                        "effective_weight": effective_weight,
                        "weighted_value": 0.0,
                        "missing": true
                    }
                }));
            }
            continue;
        };
        if score_input_value(input_item).is_none() {
            missing_score_ids.push(score_id.clone());
            continue;
        }
        let mut score_input = object_from(input_item);
        score_input.insert("score_id".to_string(), json!(score_id.clone()));
        score_input
            .entry("subject_id".to_string())
            .or_insert_with(|| json!(text_field(input, "subject_id")));
        let mut result = compute_score(&Value::Object(score_input.clone()))?;
        let item_weight = if input_item.get("weight").is_some() {
            number_field(input_item, "weight", default_weight)
        } else {
            default_weight
        }
        .max(0.0);
        let confidence = number_field(&result, "confidence", 1.0);
        let effective_weight = item_weight * confidence;
        let score = number_field(&result, "score", 0.0);
        let weighted_value = score * effective_weight;
        weighted_sum += weighted_value;
        denominator += effective_weight;
        if let Some(details) = result.get_mut("details").and_then(Value::as_object_mut) {
            details.insert("weight".to_string(), json!(item_weight));
            details.insert(
                "effective_weight".to_string(),
                json!(round_decimal(effective_weight, 4)),
            );
            details.insert(
                "weighted_value".to_string(),
                json!(round_decimal(weighted_value, 4)),
            );
        }
        results.push(result);
    }
    let score = if denominator > 0.0 {
        weighted_sum / denominator
    } else {
        0.0
    };
    Ok(json!({
        "score_bucket_id": score_bucket_id,
        "subject_id": text_field(input, "subject_id"),
        "score": round_decimal(score, 4),
        "aggregation": value_text(&bucket, "aggregation"),
        "items": results,
        "missing_score_ids": missing_score_ids,
        "denominator": round_decimal(denominator, 4),
        "details": {
            "weighted_sum": round_decimal(weighted_sum, 4),
            "missing_policy": missing_policy,
            "version": value_text(&bucket, "version")
        }
    }))
}

fn list_keyword_configs(input: &Value) -> Result<Value, ApiError> {
    let mut records = read_collection("keyword-configs")?
        .into_iter()
        .map(|record| {
            let repository_id = value_text(&record, "repository_id");
            materialize_keyword_config(&repository_id, Some(&record))
        })
        .collect::<Vec<_>>();
    records.sort_by_key(record_sort_key);
    records.retain(|record| record_matches_filter(record, input));
    Ok(page(records, input))
}

fn get_keyword_config(input: &Value) -> Result<Value, ApiError> {
    let keyword_config_id = id_from_input(input, "keyword_config_id")?;
    let record = get_record("keyword-configs", &keyword_config_id)?;
    let repository_id = value_text(&record, "repository_id");
    Ok(materialize_keyword_config(&repository_id, Some(&record)))
}

fn resolve_keyword_config(input: &Value) -> Result<Value, ApiError> {
    let repository_id = normalized_repository_id(input);
    keyword_config_for_repository(&repository_id)
}

fn save_keyword_config(input: &Value) -> Result<Value, ApiError> {
    let repository_id = normalized_repository_id(input);
    let rules = normalize_keyword_rules_from_value(input.get("rules").unwrap_or(&Value::Null));
    if rules.is_empty() {
        return Err(ApiError::bad_request("rules must be a non-empty array"));
    }
    upsert_keyword_config(&repository_id, rules)
}

fn adjust_keyword_config(input: &Value) -> Result<Value, ApiError> {
    let repository_id = normalized_repository_id(input);
    let keyword_id = id_from_input(input, "keyword_id")?;
    let delta = integer_field(input, "delta", 0);
    let config = keyword_config_for_repository(&repository_id)?;
    let mut rules = config
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut found = false;
    for rule in &mut rules {
        if value_text(rule, "id") != keyword_id {
            continue;
        }
        found = true;
        let next_weight = (integer_field(rule, "weight", 0) + delta).clamp(0, 100);
        if let Some(object) = rule.as_object_mut() {
            object.insert("weight".to_string(), json!(next_weight));
        }
    }
    if !found {
        return Err(ApiError::not_found(format!(
            "keyword rule {keyword_id} was not found"
        )));
    }
    upsert_keyword_config(&repository_id, normalize_keyword_rules_vec(rules))
}

fn keyword_config_for_repository(repository_id: &str) -> Result<Value, ApiError> {
    let config_id = keyword_config_id(repository_id);
    let stored = read_collection("keyword-configs")?
        .into_iter()
        .find(|record| {
            value_text(record, "id") == config_id
                || value_text(record, "keyword_config_id") == config_id
        });
    Ok(materialize_keyword_config(repository_id, stored.as_ref()))
}

fn upsert_keyword_config(repository_id: &str, rules: Vec<Value>) -> Result<Value, ApiError> {
    let config_id = keyword_config_id(repository_id);
    let record = upsert_record(
        "keyword-configs",
        &json!({
            "id": config_id,
            "keyword_config_id": config_id,
            "repository_id": repository_id,
            "keyword_score_cap": KEYWORD_SCORE_CAP,
            "rules": rules,
            "updated_at": now_timestamp()
        }),
    )?;
    Ok(materialize_keyword_config(repository_id, Some(&record)))
}

fn materialize_keyword_config(repository_id: &str, stored: Option<&Value>) -> Value {
    let stored_repository_id = stored
        .map(|record| value_text(record, "repository_id"))
        .unwrap_or_default();
    let repository_id = if repository_id.is_empty() {
        stored_repository_id
    } else {
        repository_id.to_string()
    };
    let config_id = stored
        .map(|record| {
            first_non_empty(&[
                value_text(record, "id"),
                value_text(record, "keyword_config_id"),
            ])
        })
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| keyword_config_id(&repository_id));
    let stored_rules = stored
        .and_then(|record| record.get("rules"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({
        "id": config_id,
        "keyword_config_id": config_id,
        "repository_id": repository_id,
        "keyword_score_cap": KEYWORD_SCORE_CAP,
        "rules": merge_keyword_rules(&stored_rules),
        "updated_at": stored
            .map(|record| value_text(record, "updated_at"))
            .filter(|updated_at| !updated_at.is_empty())
            .unwrap_or_else(now_timestamp)
    })
}

fn merge_keyword_rules(stored_rules: &[Value]) -> Vec<Value> {
    let mut by_id = BTreeMap::new();
    for rule in default_keyword_rules() {
        by_id.insert(value_text(&rule, "id"), rule);
    }
    for stored in stored_rules {
        let Some(normalized) = normalize_keyword_rule(stored) else {
            continue;
        };
        let id = value_text(&normalized, "id");
        if let Some(existing) = by_id.get(&id) {
            let mut merged = object_from(existing);
            for (key, value) in object_from(&normalized) {
                merged.insert(key, value);
            }
            by_id.insert(id, Value::Object(merged));
        } else {
            by_id.insert(id, normalized);
        }
    }
    let mut rules = by_id.into_iter().map(|(_, rule)| rule).collect::<Vec<_>>();
    sort_keyword_rules(&mut rules);
    rules
}

fn normalize_keyword_rules_from_value(value: &Value) -> Vec<Value> {
    normalize_keyword_rules_vec(value.as_array().cloned().unwrap_or_default())
}

fn normalize_keyword_rules_vec(rules: Vec<Value>) -> Vec<Value> {
    let mut normalized = rules
        .iter()
        .filter_map(normalize_keyword_rule)
        .collect::<Vec<_>>();
    sort_keyword_rules(&mut normalized);
    normalized
}

fn normalize_keyword_rule(rule: &Value) -> Option<Value> {
    let id = text_field(rule, "id").trim().to_string();
    let pattern = text_field(rule, "pattern").trim().to_string();
    if id.is_empty() || pattern.is_empty() {
        return None;
    }
    let label = text_field(rule, "label").trim().to_string();
    let color = text_field(rule, "color");
    Some(json!({
        "id": id,
        "label": if label.is_empty() { text_field(rule, "id") } else { label },
        "pattern": pattern,
        "color": if valid_hex_color(&color) { color } else { "#245da8".to_string() },
        "weight": integer_field(rule, "weight", 0).clamp(0, 100),
        "order": integer_field(rule, "order", 0),
        "enabled": bool_field(rule, "enabled", true)
    }))
}

fn sort_keyword_rules(rules: &mut [Value]) {
    rules.sort_by(|left, right| {
        integer_field(left, "order", 0)
            .cmp(&integer_field(right, "order", 0))
            .then_with(|| value_text(left, "label").cmp(&value_text(right, "label")))
    });
}

fn default_keyword_rules() -> Vec<Value> {
    vec![
        keyword_rule(
            "vulnerability_terms",
            "Vulnerability terms",
            "(vulnerab|exploit|cve|security)",
            "#b42318",
            8,
            10,
        ),
        keyword_rule(
            "auth_access",
            "Auth / access",
            "(auth|authentication|authorization|permission|privilege|capability|trust)",
            "#7a2e0e",
            6,
            20,
        ),
        keyword_rule(
            "secrets_crypto",
            "Secrets / crypto",
            "(credential|secret|password|token|apikey|api key|certificate|cert|tls|ssl|crypto|encrypt|decrypt|signature|signed)",
            "#a56315",
            6,
            30,
        ),
        keyword_rule(
            "unsafe_parsing",
            "Parsing / validation",
            "(pickle|unmarshal|deserialize|deseriali[sz]ation|sanitize|validation|validate|bounds?|overflow|traversal|injection|xss|csrf)",
            "#245da8",
            6,
            40,
        ),
        keyword_rule(
            "race_conflict",
            "Race / conflict",
            "(race|collision|conflict|concurrent|atomic|lock)",
            "#6d3fb0",
            4,
            50,
        ),
        keyword_rule(
            "data_exposure",
            "Data exposure",
            "(leak|expos|private|sensitive)",
            "#087443",
            6,
            60,
        ),
    ]
}

fn keyword_rule(
    id: &str,
    label: &str,
    pattern: &str,
    color: &str,
    weight: i64,
    order: i64,
) -> Value {
    json!({
        "id": id,
        "label": label,
        "pattern": pattern,
        "color": color,
        "weight": weight,
        "order": order,
        "enabled": true
    })
}

fn keyword_config_id(repository_id: &str) -> String {
    format!(
        "review-risk-keywords-{}",
        sanitize_keyword_config_key(repository_id)
    )
}

fn sanitize_keyword_config_key(value: &str) -> String {
    let key = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if key.is_empty() {
        "global".to_string()
    } else {
        key
    }
}

fn normalized_repository_id(input: &Value) -> String {
    text_field(input, "repository_id").trim().to_string()
}

fn valid_hex_color(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(u8::is_ascii_hexdigit)
}

fn get_console_config() -> Result<Value, ApiError> {
    Ok(json!({
        "repointelBase": env::var("REPOINTEL_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:18101".to_string()),
        "metadataCollectionBase": env::var("METADATA_COLLECTION_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:18102".to_string()),
        "analyticsAvailable": env::var("REPOINTEL_DATABASE_URL").map(|value| !value.trim().is_empty()).unwrap_or(false),
        "repointelProxy": "/api/repointel",
        "metadataCollectionProxy": "/api/metadata"
    }))
}

fn review_risk_score_definitions() -> Vec<Value> {
    vec![
        score_definition(
            "security_keyword_score",
            "Security Keyword Score",
            "Security keyword and security.signal metadata score for a review.",
            "security",
            1.4,
            &["review_message.body", "metadata.security.signal"],
        ),
        score_definition(
            "security_sensitivity_score",
            "Security Sensitivity Score",
            "ONNX-backed security.sensitivity contribution for review text.",
            "security",
            1.0,
            &["metadata.security.sensitivity.score"],
        ),
        score_definition(
            "security_file_surface_score",
            "Security File Surface Score",
            "Touched security-sensitive, attack-surface, dependency, or workflow file surface score.",
            "security",
            1.2,
            &["metadata.code.file_role", "metadata.code.file.path"],
        ),
        score_definition(
            "author_competence_score",
            "Author Competence Score",
            "Risk score derived from author line survival, rework, and historical review quality.",
            "author_competence",
            1.3,
            &["metadata.git.line_survival.summary", "review_history.owner"],
        ),
        score_definition(
            "reviewer_survival_score",
            "Reviewer Survival Score",
            "Risk score derived from current approval survival and reviewer history survival.",
            "reviewer_competence",
            1.1,
            &["metadata.review.approval_line_survival"],
        ),
        score_definition(
            "implementation_concern_score",
            "Implementation Concern Score",
            "Strong concern, repeated concern, file-specific concern, and concern-after-approval score.",
            "implementation_risk",
            1.5,
            &["metadata.review.concern", "metadata.review.implementation_risk"],
        ),
        score_definition(
            "review_friction_score",
            "Review Friction Score",
            "Unresolved comments, negative votes, contradictory votes, and comment-volume score.",
            "review_friction",
            1.0,
            &["gerrit_change.unresolved_comments", "metadata.review.approval.vote", "review_message.count"],
        ),
        score_definition(
            "review_churn_score",
            "Review Churn Score",
            "Patch-set, touched-file, reviewer-count, and concern-span score.",
            "review_churn",
            0.8,
            &["gerrit_change.patch_sets", "gerrit_change.files", "review_message.reviewer_count"],
        ),
        score_definition(
            "changed_lines_score",
            "Changed Lines Score",
            "Risk score from total lines of code changed by the review.",
            "change_size",
            0.9,
            &["gerrit_change.insertions", "gerrit_change.deletions", "gerrit_change.changed_lines"],
        ),
        score_definition(
            "staleness_score",
            "Staleness Score",
            "Open-review age score after the configured freshness window.",
            "staleness",
            0.3,
            &["gerrit_change.created_at", "gerrit_change.status"],
        ),
    ]
}

fn score_definition(
    id: &str,
    name: &str,
    description: &str,
    bucket: &str,
    default_weight: f64,
    inputs: &[&str],
) -> Value {
    json!({
        "id": id,
        "slug": id,
        "name": name,
        "description": description,
        "subject_type": "review",
        "value_type": "risk_score",
        "direction": "higher_is_risk",
        "range": { "min": 0, "max": 100 },
        "default_weight": default_weight,
        "missing_policy": "omit_missing",
        "inputs": inputs,
        "bucket": bucket,
        "version": "review_risk_v1",
        "metadata": { "source": "review_risk" }
    })
}

fn review_risk_score_bucket_definitions() -> Vec<Value> {
    vec![json!({
        "id": REVIEW_RISK_SCORE_BUCKET_ID,
        "slug": REVIEW_RISK_SCORE_BUCKET_ID,
        "name": "Review Risk Weighted Average",
        "description": "Weighted average rollup over the Review Risk atomic score items.",
        "subject_type": "review",
        "aggregation": "weighted_average",
        "output_range": { "min": 0, "max": 100 },
        "scores": review_risk_score_definitions().into_iter().map(|score| json!({
            "score_id": value_text(&score, "id"),
            "weight": number_field(&score, "default_weight", 1.0),
            "required": false
        })).collect::<Vec<_>>(),
        "version": "review_risk_v1",
        "metadata": {
            "source": "review_risk",
            "formula": "sum(score * weight * confidence) / sum(weight * confidence)"
        }
    })]
}

fn score_input_value(input: &Value) -> Option<f64> {
    input
        .get("score")
        .and_then(numeric_value)
        .or_else(|| input.get("value").and_then(numeric_score_value))
}

fn numeric_score_value(value: &Value) -> Option<f64> {
    numeric_value(value).or_else(|| {
        value.as_object().and_then(|object| {
            ["score", "risk_score", "value"]
                .iter()
                .find_map(|key| object.get(*key).and_then(numeric_value))
        })
    })
}

fn numeric_value(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<f64>().ok()))
}

fn prepare_szz_analysis(input: &Value, mode: &str) -> Result<Value, ApiError> {
    let mut request = object_from(input);
    request.insert("_mode".to_string(), json!(mode));
    normalize_szz_defaults(&mut request);
    let cache_key = szz_cache_key(&Value::Object(request.clone()), mode);
    request.insert("cache_key".to_string(), json!(cache_key));
    Ok(Value::Object(request))
}

fn store_szz_analysis_result(input: &Value, provider_run: &Value) -> Result<Value, ApiError> {
    if provider_run.is_null() {
        return Err(ApiError::provider(
            "SZZ provider returned an empty response",
        ));
    }
    let mut analysis_obj = object_from(provider_run);
    let mode = first_non_empty(&[
        value_text(provider_run, "mode"),
        text_field(input, "_mode"),
        "batch".to_string(),
    ]);
    let mut cache_request = object_from(input);
    cache_request.insert("_mode".to_string(), json!(mode));
    normalize_szz_defaults(&mut cache_request);
    let cache_key = first_non_empty(&[
        value_text(provider_run, "cache_key"),
        szz_cache_key(&Value::Object(cache_request), &mode),
    ]);
    analysis_obj.insert("cache_key".to_string(), json!(cache_key));
    analysis_obj.insert("mode".to_string(), json!(mode));
    analysis_obj
        .entry("status".to_string())
        .or_insert_with(|| json!("completed"));
    let saved = upsert_record("szz-runs", &Value::Object(analysis_obj))?;
    if bool_field(&saved, "commit_evidence", true) && !bool_field(input, "dry_run", false) {
        for hit in saved
            .get("evidence_hits")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            upsert_evidence_hit(&hit)?;
        }
    }
    Ok(saved)
}

fn normalize_szz_defaults(request: &mut Map<String, Value>) {
    request
        .entry("min_direct_lines".to_string())
        .or_insert_with(|| json!(4));
    request
        .entry("min_context_lines".to_string())
        .or_insert_with(|| json!(4));
    request
        .entry("include_context_candidates".to_string())
        .or_insert_with(|| json!(true));
    request
        .entry("backfill_missing_reviews".to_string())
        .or_insert_with(|| json!(true));
    request
        .entry("commit_evidence".to_string())
        .or_insert_with(|| json!(true));
}

fn szz_cache_key(input: &Value, mode: &str) -> String {
    let mut normalized = object_from(input);
    normalized.remove("force");
    normalized.remove("dry_run");
    normalized.remove("szz_analysis_id");
    normalized.insert("mode".to_string(), json!(mode));
    normalized.insert("szz_version".to_string(), json!("szz_review_analyze_v1"));
    stable_hash(&Value::Object(normalized).to_string())
}

fn clamp_score_value(value: f64) -> f64 {
    value.max(0.0).min(100.0)
}

fn clamp01_value(value: f64) -> f64 {
    value.max(0.0).min(1.0)
}

fn round_decimal(value: f64, digits: i32) -> f64 {
    let factor = 10_f64.powi(digits);
    (value * factor).round() / factor
}

fn list_records(collection: &str, input: &Value) -> Result<Value, ApiError> {
    let mut records = read_collection(collection)?;
    records.sort_by_key(record_sort_key);
    records.retain(|record| record_matches_filter(record, input));
    Ok(page(records, input))
}

fn search_records(collection: &str, input: &Value) -> Result<Value, ApiError> {
    let query = text_field(input, "query").to_lowercase();
    let mut records = read_collection(collection)?;
    records.sort_by_key(record_sort_key);
    records.retain(|record| {
        record_matches_filter(record, input)
            && (query.is_empty() || record.to_string().to_lowercase().contains(&query))
    });
    Ok(page(records, input))
}

fn create_record(collection: &str, input: &Value) -> Result<Value, ApiError> {
    let mut records = read_collection(collection)?;
    let mut record = object_from(input);
    apply_defaults(collection, &mut record);
    let id = ensure_id(collection, &mut record);
    if records.iter().any(|record| value_text(record, "id") == id) {
        return Err(ApiError::conflict(format!(
            "{collection} record {id} already exists"
        )));
    }
    let value = Value::Object(record);
    records.push(value.clone());
    write_collection(collection, &records)?;
    Ok(value)
}

fn get_record_by_input(collection: &str, id_key: &str, input: &Value) -> Result<Value, ApiError> {
    let id = id_from_input(input, id_key)?;
    get_record(collection, &id)
}

fn get_record(collection: &str, id: &str) -> Result<Value, ApiError> {
    read_collection(collection)?
        .into_iter()
        .find(|record| value_text(record, "id") == id)
        .ok_or_else(|| ApiError::not_found(format!("{collection} record {id} was not found")))
}

fn update_record(collection: &str, id_key: &str, input: &Value) -> Result<Value, ApiError> {
    let id = id_from_input(input, id_key)?;
    let patch = object_from(input);
    let mut records = read_collection(collection)?;
    let Some(index) = records
        .iter()
        .position(|record| value_text(record, "id") == id)
    else {
        return Err(ApiError::not_found(format!(
            "{collection} record {id} was not found"
        )));
    };
    let mut record = object_from(&records[index]);
    for (key, value) in patch {
        if key == id_key || key == "id" || is_empty_value(&value) {
            continue;
        }
        record.insert(key, value);
    }
    stamp_update(&mut record);
    records[index] = Value::Object(record.clone());
    write_collection(collection, &records)?;
    Ok(Value::Object(record))
}

fn delete_record(collection: &str, id_key: &str, input: &Value) -> Result<Value, ApiError> {
    let id = id_from_input(input, id_key)?;
    let mut records = read_collection(collection)?;
    let before = records.len();
    records.retain(|record| value_text(record, "id") != id);
    if before == records.len() {
        return Err(ApiError::not_found(format!(
            "{collection} record {id} was not found"
        )));
    }
    write_collection(collection, &records)?;
    Ok(json!({ "deleted": true, "id": id }))
}

fn upsert_record(collection: &str, input: &Value) -> Result<Value, ApiError> {
    let mut record = object_from(input);
    apply_defaults(collection, &mut record);
    let id = ensure_id(collection, &mut record);
    let mut records = read_collection(collection)?;
    if let Some(index) = records.iter().position(|item| value_text(item, "id") == id) {
        let mut existing = object_from(&records[index]);
        for (key, value) in record {
            if !is_empty_value(&value) {
                existing.insert(key, value);
            }
        }
        stamp_update(&mut existing);
        records[index] = Value::Object(existing.clone());
        write_collection(collection, &records)?;
        Ok(Value::Object(existing))
    } else {
        let value = Value::Object(record);
        records.push(value.clone());
        write_collection(collection, &records)?;
        Ok(value)
    }
}

fn upsert_evidence_hit(input: &Value) -> Result<Value, ApiError> {
    let mut record = object_from(input);
    apply_defaults("evidence-hits", &mut record);
    let id = ensure_id("evidence-hits", &mut record);
    let mut records = read_collection("evidence-hits")?;
    if let Some(index) = records.iter().position(|item| value_text(item, "id") == id) {
        let existing_disposition = value_text(&records[index], "disposition");
        let mut existing = object_from(&records[index]);
        for (key, value) in record {
            if !is_empty_value(&value) {
                existing.insert(key, value);
            }
        }
        if existing_disposition == "committed" {
            existing.insert("disposition".to_string(), json!("committed"));
            for field in [
                "committed_metadata_ids",
                "committed_relationship_ids",
                "reviewer",
                "reviewer_note",
                "reviewed_at",
            ] {
                if let Some(value) = records[index].get(field) {
                    existing.insert(field.to_string(), value.clone());
                }
            }
        }
        stamp_update(&mut existing);
        records[index] = Value::Object(existing.clone());
        write_collection("evidence-hits", &records)?;
        Ok(Value::Object(existing))
    } else {
        let value = Value::Object(record);
        records.push(value.clone());
        write_collection("evidence-hits", &records)?;
        Ok(value)
    }
}

fn member_page(
    collection: &str,
    field: &str,
    id_key: &str,
    input: &Value,
) -> Result<Value, ApiError> {
    let id = id_from_input(input, id_key)?;
    let mut records = read_collection(collection)?;
    records.retain(|record| value_text(record, field) == id);
    records.sort_by_key(record_sort_key);
    Ok(page(records, input))
}

fn status_update(
    collection: &str,
    id_key: &str,
    input: &Value,
    status: &str,
) -> Result<Value, ApiError> {
    let mut patch = object_from(input);
    patch.insert("status".to_string(), json!(status));
    update_record(collection, id_key, &Value::Object(patch))
}

fn bool_update(
    collection: &str,
    id_key: &str,
    input: &Value,
    field: &str,
    value: bool,
) -> Result<Value, ApiError> {
    let mut patch = object_from(input);
    patch.insert(field.to_string(), json!(value));
    update_record(collection, id_key, &Value::Object(patch))
}

fn selected_rules(input: &Value, profile_id: &str) -> Result<Vec<Value>, ApiError> {
    let requested = string_set(input.get("rule_ids"));
    let scenario_ids = string_set(input.get("scenario_ids"));
    let bundle_ids = string_set(input.get("bundle_ids"));
    let bundles = read_collection("extractor-bundles")?;
    let profile_bundle_ids = bundles
        .iter()
        .filter(|bundle| value_text(bundle, "profile_id") == profile_id)
        .map(|bundle| value_text(bundle, "id"))
        .collect::<BTreeSet<_>>();
    let mut rules = read_collection("extractor-rules")?;
    rules.retain(|rule| {
        bool_field(rule, "enabled", true)
            && (requested.is_empty() || requested.contains(&value_text(rule, "id")))
            && (scenario_ids.is_empty() || scenario_ids.contains(&value_text(rule, "scenario_id")))
            && (bundle_ids.is_empty() || bundle_ids.contains(&value_text(rule, "bundle_id")))
            && (profile_bundle_ids.is_empty()
                || profile_bundle_ids.contains(&value_text(rule, "bundle_id")))
    });
    Ok(rules)
}

fn selected_records(
    collection: &str,
    input: &Value,
    ids_field: &str,
    owner_field: &str,
    owner_id: &str,
) -> Result<Vec<Value>, ApiError> {
    let ids = string_set(input.get(ids_field));
    let mut records = read_collection(collection)?;
    records.retain(|record| {
        (ids.is_empty() || ids.contains(&value_text(record, "id")))
            && (owner_id.is_empty() || value_text(record, owner_field) == owner_id)
    });
    Ok(records)
}

fn trace_downstream(
    run_id: &str,
    hit_id: &str,
    downstream_service_id: &str,
    operation: &str,
    method: &str,
    path: &str,
    status_code: i64,
    error: &str,
) -> Result<(), ApiError> {
    let _ = create_record(
        "downstream-calls",
        &json!({
            "collection_run_id": run_id,
            "evidence_hit_id": hit_id,
            "downstream_service_id": downstream_service_id,
            "service": "RepointelFacade",
            "operation": operation,
            "method": method,
            "path": path,
            "request_id": format!("trace-{}", stable_hash(&format!("{}|{}|{}", run_id, operation, now_timestamp()))),
            "status_code": status_code,
            "duration_ms": 0,
            "retry_count": 0,
            "error": error,
            "created_at": now_timestamp()
        }),
    )?;
    Ok(())
}

fn page_items(value: &Value) -> Vec<Value> {
    value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| {
            value
                .get("response")
                .and_then(|response| response.get("items"))
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
}

fn read_collection(collection: &str) -> Result<Vec<Value>, ApiError> {
    let path = collection_path(collection)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path)
        .map_err(|err| ApiError::internal(format!("failed reading {}: {err}", path.display())))?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&text)
        .map_err(|err| ApiError::internal(format!("failed parsing {}: {err}", path.display())))
}

fn write_collection(collection: &str, records: &[Value]) -> Result<(), ApiError> {
    let path = collection_path(collection)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            ApiError::internal(format!("failed creating {}: {err}", parent.display()))
        })?;
    }
    let text = serde_json::to_string_pretty(records)
        .map_err(|err| ApiError::internal(format!("failed serializing {collection}: {err}")))?;
    fs::write(&path, text)
        .map_err(|err| ApiError::internal(format!("failed writing {}: {err}", path.display())))
}

fn collection_path(collection: &str) -> Result<PathBuf, ApiError> {
    if COLLECTIONS.iter().all(|meta| meta.collection != collection) {
        return Err(ApiError::internal(format!(
            "unknown collection {collection}"
        )));
    }
    let root = env::var("METADATA_COLLECTION_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".metadata-collection-data"));
    Ok(root.join(format!("{collection}.json")))
}

fn collection_io_guard() -> Result<MutexGuard<'static, ()>, ApiError> {
    COLLECTION_IO_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| ApiError::internal("metadata collection storage lock was poisoned"))
}

fn collection_for_op(stem: &str) -> Result<CollectionMeta, ApiError> {
    let normalized = stem.replace('-', "_");
    COLLECTIONS
        .iter()
        .copied()
        .find(|meta| {
            normalized == meta.singular
                || normalized == meta.collection.replace('-', "_")
                || normalized == pluralize(meta.singular)
                || (normalized == "profiles" && meta.collection == "profiles")
                || (normalized == "runs" && meta.collection == "runs")
                || (normalized == "bundles" && meta.collection == "extractor-bundles")
                || (normalized == "rules" && meta.collection == "extractor-rules")
        })
        .ok_or_else(|| ApiError::internal(format!("unknown operation collection stem {stem}")))
}

fn pluralize(value: &str) -> String {
    match value {
        "downstream_service" => "downstream_services".to_string(),
        "evidence_hit" => "evidence_hits".to_string(),
        "coverage_report" => "coverage_reports".to_string(),
        "downstream_call" => "downstream_calls".to_string(),
        other => format!("{other}s"),
    }
}

fn apply_defaults(collection: &str, record: &mut Map<String, Value>) {
    let now = now_timestamp();
    record
        .entry("created_at".to_string())
        .or_insert_with(|| json!(now));
    if !matches!(collection, "downstream-calls" | "coverage-reports") {
        record
            .entry("updated_at".to_string())
            .or_insert_with(|| json!(now));
    }
    match collection {
        "profiles" => {
            record
                .entry("status".to_string())
                .or_insert_with(|| json!("active"));
            record
                .entry("default_min_confidence".to_string())
                .or_insert_with(|| json!(0.85));
            record
                .entry("review_below_confidence".to_string())
                .or_insert_with(|| json!(0.85));
            record
                .entry("auto_commit_default".to_string())
                .or_insert_with(|| json!(true));
            record
                .entry("write_extraction_evidence_metadata".to_string())
                .or_insert_with(|| json!(true));
        }
        "scenarios" | "extractor-bundles" | "dictionaries" | "extractor-rules" => {
            record
                .entry("enabled".to_string())
                .or_insert_with(|| json!(true));
        }
        "runs" => {
            record
                .entry("status".to_string())
                .or_insert_with(|| json!("queued"));
            record
                .entry("mode".to_string())
                .or_insert_with(|| json!("incremental"));
        }
        "szz-runs" => {
            record
                .entry("status".to_string())
                .or_insert_with(|| json!("completed"));
            record
                .entry("szz_version".to_string())
                .or_insert_with(|| json!("szz_review_analyze_v1"));
        }
        _ => {}
    }
}

fn stamp_update(record: &mut Map<String, Value>) {
    record.insert("updated_at".to_string(), json!(now_timestamp()));
}

fn ensure_id(collection: &str, record: &mut Map<String, Value>) -> String {
    if let Some(id) = record
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    {
        return id.to_string();
    }
    let meta = COLLECTIONS
        .iter()
        .find(|meta| meta.collection == collection)
        .unwrap();
    if let Some(id) = record
        .get(meta.key)
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    {
        let id = id.to_string();
        record.insert("id".to_string(), json!(id));
        record.remove(meta.key);
        return id;
    }
    let id = format!(
        "{}-{}",
        meta.prefix,
        stable_hash(&natural_key(collection, record))
    );
    record.insert("id".to_string(), json!(id.clone()));
    id
}

fn natural_key(collection: &str, record: &Map<String, Value>) -> String {
    let fields: &[&str] = match collection {
        "profiles" => &["slug"],
        "scenarios" => &["profile_id", "slug"],
        "extractor-bundles" => &["profile_id", "slug", "version"],
        "dictionaries" => &["slug", "version"],
        "extractor-rules" => &["bundle_id", "slug", "version"],
        "evidence-hits" => &["hit_hash"],
        "downstream-services" => &["name", "kind", "base_url"],
        "runs" => &["profile_id", "requested_by", "created_at"],
        "coverage-reports" => &["profile_id", "repository_id", "generated_at"],
        "szz-runs" => &["cache_key"],
        "downstream-calls" => &["collection_run_id", "operation", "created_at"],
        _ => &["id"],
    };
    let mut parts = vec![collection.to_string()];
    for field in fields {
        parts.push(format!(
            "{field}={}",
            record.get(*field).cloned().unwrap_or(Value::Null)
        ));
    }
    parts.join("|")
}

fn page(mut records: Vec<Value>, input: &Value) -> Value {
    let total = records.len();
    let start = cursor(input);
    let limit = limit(input);
    let end = (start + limit).min(records.len());
    let items = if start >= records.len() {
        Vec::new()
    } else {
        records.drain(start..end).collect::<Vec<_>>()
    };
    let next_cursor = if end < total {
        end.to_string()
    } else {
        String::new()
    };
    json!({
        "items": items,
        "page": { "next_cursor": next_cursor, "total": total },
        "next_cursor": next_cursor,
        "total": total
    })
}

fn record_matches_filter(record: &Value, input: &Value) -> bool {
    if let Some(filters) = input.get("filters").and_then(Value::as_object) {
        for (key, expected) in filters {
            if is_empty_value(expected) {
                continue;
            }
            if record.get(key) != Some(expected) {
                return false;
            }
        }
    }
    let Some(object) = input.as_object() else {
        return true;
    };
    for (key, expected) in object {
        if matches!(key.as_str(), "query" | "filters" | "cursor" | "limit")
            || is_empty_value(expected)
        {
            continue;
        }
        if record.get(key) != Some(expected) {
            return false;
        }
    }
    true
}

fn seed_vuln_intel_priority_profile(input: &Value) -> Result<Value, ApiError> {
    let force = bool_field(input, "force", false);
    if force {
        for collection in [
            "profiles",
            "scenarios",
            "extractor-bundles",
            "dictionaries",
            "extractor-rules",
        ] {
            let mut records = read_collection(collection)?;
            records.retain(|record| {
                value_text(record, "id") != PROFILE_ID
                    && value_text(record, "profile_id") != PROFILE_ID
                    && value_text(record, "bundle_id") != BUNDLE_ID
                    && value_text(record, "id") != BUNDLE_ID
            });
            write_collection(collection, &records)?;
        }
    }
    ensure_seeded()?;
    get_record("profiles", PROFILE_ID)
}

fn ensure_seeded() -> Result<(), ApiError> {
    if get_record("profiles", PROFILE_ID).is_ok() {
        return Ok(());
    }
    let profile = json!({
        "id": PROFILE_ID,
        "slug": "vuln_intel_priority_v1",
        "name": "Vulnerability Intelligence Priority v1",
        "description": "Layered metadata extraction for vulnerability identifiers, suspected security fixes, review concerns, issue links, reverts, sensitive paths, dependency manifests, and workflow risk.",
        "status": "active",
        "default_min_confidence": 0.85,
        "review_below_confidence": 0.85,
        "auto_commit_default": true,
        "write_extraction_evidence_metadata": true,
        "created_by": "system"
    });
    let _ = upsert_record("profiles", &profile)?;
    let scenarios = vec![
        (
            0,
            "explicit_vulnerability_identifier",
            true,
            0.95,
            "deterministic",
        ),
        (0, "suspected_security_fix", true, 0.85, "high"),
        (0, "review_security_concern", false, 0.95, "medium"),
        (1, "fix_issue_reference", true, 0.90, "deterministic"),
        (
            1,
            "revert_or_cherry_pick_linkage",
            true,
            0.90,
            "deterministic",
        ),
        (1, "sensitive_component_touched", true, 0.85, "high"),
        (1, "dependency_or_manifest_change", false, 0.85, "high"),
        (1, "workflow_permission_risk", true, 0.90, "deterministic"),
        (
            2,
            "silent_security_fix_candidate",
            false,
            0.95,
            "speculative",
        ),
        (
            2,
            "unresolved_security_review_concern",
            false,
            0.95,
            "speculative",
        ),
    ];
    for (priority, slug, auto, confidence, feasibility) in scenarios {
        let id = format!("scenario_{slug}");
        let _ = upsert_record(
            "scenarios",
            &json!({
                "id": id,
                "profile_id": PROFILE_ID,
                "slug": slug,
                "name": titleize(slug),
                "priority": priority,
                "value_tier": if priority == 0 { "critical" } else if priority == 1 { "high" } else { "medium" },
                "feasibility_tier": feasibility,
                "source_types": ["commits", "bugs", "code_reviews"],
                "providers": ["git", "github", "gitlab", "gerrit", "jira", "bugzilla", "launchpad"],
                "raw_record_types": ["commit", "commit_message", "bug", "bug_comment", "code_review", "code_review_comment"],
                "art_types": ["commit_message", "bug_message", "code_review_message"],
                "required_namespaces": [],
                "enabled": true,
                "auto_commit_min_confidence": confidence,
                "review_required_below_confidence": confidence,
                "auto_commit_default": auto
            }),
        )?;
    }
    let _ = upsert_record(
        "extractor-bundles",
        &json!({
            "id": BUNDLE_ID,
            "profile_id": PROFILE_ID,
            "slug": "vuln_intel_core_extractors",
            "name": "Vulnerability Intelligence Core Extractors",
            "description": "Core deterministic and high-feasibility vulnerability-intelligence extractors.",
            "version": "1",
            "provider": "multi",
            "source_type": "repository_messages",
            "raw_record_types": ["commit", "commit_message", "bug", "bug_comment", "code_review", "code_review_comment"],
            "art_types": ["commit_message", "bug_message", "code_review_message"],
            "status": "active",
            "enabled": true,
            "rules_count": 12
        }),
    )?;
    for (slug, kind, entries) in [
        (
            "security_sensitive_paths_v1",
            "sensitive_paths",
            vec!["auth", "policy", "token", "credential", "session"],
        ),
        (
            "security_terms_v1",
            "security_terms",
            vec![
                "authorization bypass",
                "privilege escalation",
                "credential exposure",
            ],
        ),
        (
            "workflow_permission_risks_v1",
            "workflow_permissions",
            vec!["pull_request_target", "permissions: write-all"],
        ),
        (
            "dependency_manifest_paths_v1",
            "components",
            vec![
                "package-lock.json",
                "requirements.txt",
                "go.mod",
                "Cargo.lock",
            ],
        ),
        (
            "component_path_patterns_v1",
            "components",
            vec!["auth", "policy", "token", "credential", "session"],
        ),
    ] {
        let _ = upsert_record(
            "dictionaries",
            &json!({
                "id": format!("dictionary_{slug}"),
                "slug": slug,
                "name": titleize(slug),
                "version": "1",
                "kind": kind,
                "entries": entries.into_iter().map(|entry| json!({ "key": entry, "label": entry, "patterns": [entry], "metadata": {} })).collect::<Vec<_>>(),
                "enabled": true
            }),
        )?;
    }
    let rules = vec![
        (
            "cve_identifier_from_text_v1",
            "scenario_explicit_vulnerability_identifier",
            "regex",
            0.98,
        ),
        (
            "ghsa_identifier_from_text_v1",
            "scenario_explicit_vulnerability_identifier",
            "regex",
            0.98,
        ),
        (
            "security_fix_phrase_v1",
            "scenario_suspected_security_fix",
            "dictionary",
            0.88,
        ),
        (
            "review_security_concern_v1",
            "scenario_review_security_concern",
            "dictionary",
            0.75,
        ),
        (
            "github_fix_issue_reference_v1",
            "scenario_fix_issue_reference",
            "regex",
            0.93,
        ),
        (
            "git_revert_v1",
            "scenario_revert_or_cherry_pick_linkage",
            "regex",
            0.90,
        ),
        (
            "git_cherry_pick_v1",
            "scenario_revert_or_cherry_pick_linkage",
            "regex",
            0.92,
        ),
        (
            "file_path_component_v1",
            "scenario_sensitive_component_touched",
            "dictionary",
            0.86,
        ),
        (
            "sensitive_component_dictionary_v1",
            "scenario_sensitive_component_touched",
            "dictionary",
            0.86,
        ),
        (
            "dependency_manifest_change_v1",
            "scenario_dependency_or_manifest_change",
            "dictionary",
            0.86,
        ),
        (
            "github_actions_pull_request_target_v1",
            "scenario_workflow_permission_risk",
            "yaml_path",
            0.90,
        ),
        (
            "silent_security_fix_candidate_v1",
            "scenario_silent_security_fix_candidate",
            "heuristic",
            0.65,
        ),
    ];
    for (slug, scenario_id, rule_type, confidence) in rules {
        let _ = upsert_record(
            "extractor-rules",
            &json!({
                "id": format!("rule_{slug}"),
                "bundle_id": BUNDLE_ID,
                "scenario_id": scenario_id,
                "slug": slug,
                "name": titleize(slug),
                "version": "1",
                "type": rule_type,
                "enabled": true,
                "provider": "multi",
                "source_type": "repository_messages",
                "raw_record_types": ["commit", "commit_message", "bug", "bug_comment", "code_review", "code_review_comment"],
                "art_types": ["commit_message", "bug_message", "code_review_message"],
                "field_paths": ["body", "payload.message", "payload.body", "payload.title", "payload.files[].filename"],
                "min_confidence": confidence,
                "default_confidence": confidence,
                "review_required_below_confidence": confidence
            }),
        )?;
    }
    Ok(())
}

fn titleize(slug: &str) -> String {
    slug.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn scenario_for_rule(rule_slug: &str) -> String {
    if rule_slug.contains("cve") || rule_slug.contains("ghsa") {
        "scenario_explicit_vulnerability_identifier"
    } else if rule_slug.contains("security_fix") {
        "scenario_suspected_security_fix"
    } else if rule_slug.contains("review_security_concern") {
        "scenario_review_security_concern"
    } else if rule_slug.contains("fix_issue") {
        "scenario_fix_issue_reference"
    } else if rule_slug.contains("revert") || rule_slug.contains("cherry") {
        "scenario_revert_or_cherry_pick_linkage"
    } else if rule_slug.contains("workflow") {
        "scenario_workflow_permission_risk"
    } else if rule_slug.contains("dependency") {
        "scenario_dependency_or_manifest_change"
    } else {
        "scenario_sensitive_component_touched"
    }
    .to_string()
}

fn scenario_requires_review(scenario_id: &str) -> bool {
    matches!(
        scenario_id,
        "scenario_review_security_concern"
            | "scenario_silent_security_fix_candidate"
            | "scenario_unresolved_security_review_concern"
    )
}

fn arg_value(args: &[String], idx: usize, context: &FlowContext) -> Value {
    args.get(idx)
        .map(|arg| resolve_arg(arg, context))
        .unwrap_or(Value::Null)
}

fn object_from(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn id_from_input(input: &Value, key: &str) -> Result<String, ApiError> {
    let id = text_field(input, key);
    if id.is_empty() {
        Err(ApiError::bad_request(format!("{key} is required")))
    } else {
        Ok(id)
    }
}

fn text_field(value: &Value, key: &str) -> String {
    value_text(value, key)
}

fn value_text(value: &Value, key: &str) -> String {
    value.get(key).and_then(scalar_text).unwrap_or_default()
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn bool_field(value: &Value, key: &str, default: bool) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn number_field(value: &Value, key: &str, default: f64) -> f64 {
    value.get(key).and_then(Value::as_f64).unwrap_or(default)
}

fn integer_field(value: &Value, key: &str, default: i64) -> i64 {
    match value.get(key) {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|value| value as i64))
            .unwrap_or(default),
        Some(Value::String(text)) => text.parse().unwrap_or(default),
        _ => default,
    }
}

fn string_set(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_default()
}

fn cursor(input: &Value) -> usize {
    text_field(input, "cursor").parse().unwrap_or(0)
}

fn limit(input: &Value) -> usize {
    input
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(100)
        .clamp(1, 1000) as usize
}

fn is_empty_value(value: &Value) -> bool {
    value.is_null()
        || value.as_str() == Some("")
        || value.as_array().map(Vec::is_empty) == Some(true)
        || value.as_object().map(Map::is_empty) == Some(true)
}

fn record_sort_key(value: &Value) -> String {
    [
        value_text(value, "created_at"),
        value_text(value, "updated_at"),
        value_text(value, "id"),
    ]
    .join("|")
}

fn stable_hash(text: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn preview(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

fn now_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}", duration.as_secs())
}

fn downstream_token() -> String {
    env::var("METADATA_COLLECTION_REPOINTEL_TOKEN").unwrap_or_default()
}

fn auth_token_registry() -> Result<Value, ApiError> {
    for name in [
        "METADATA_COLLECTION_AUTH_TOKENS_JSON",
        "FRONTPLANE_AUTH_TOKENS_JSON",
    ] {
        if let Ok(raw) = env::var(name) {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            return serde_json::from_str(raw)
                .map_err(|err| ApiError::internal(format!("{name} contains invalid JSON: {err}")));
        }
    }
    for name in [
        "METADATA_COLLECTION_AUTH_TOKENS_FILE",
        "FRONTPLANE_AUTH_TOKENS_FILE",
    ] {
        if let Ok(path) = env::var(name) {
            let path = path.trim();
            if path.is_empty() {
                continue;
            }
            let raw = fs::read_to_string(path)
                .map_err(|err| ApiError::internal(format!("failed reading {name}: {err}")))?;
            return serde_json::from_str(&raw)
                .map_err(|err| ApiError::internal(format!("{name} contains invalid JSON: {err}")));
        }
    }
    Err(ApiError::unauthorized(
        "bearer token registry is not configured",
    ))
}

fn registry_principal_for_token(registry: &Value, token: &str) -> Result<Value, ApiError> {
    let tokens = registry.get("tokens").unwrap_or(registry);
    if let Some(items) = tokens.as_array() {
        for item in items {
            if registry_token_matches(item, token) {
                return Ok(item.clone());
            }
        }
    }
    if let Some(items) = tokens.as_object() {
        for (candidate, principal) in items {
            if constant_time_eq(candidate.as_bytes(), token.as_bytes()) {
                return Ok(principal.clone());
            }
            if registry_token_matches(principal, token) {
                return Ok(principal.clone());
            }
        }
    }
    Err(ApiError::unauthorized("invalid bearer token"))
}

fn registry_token_matches(principal: &Value, token: &str) -> bool {
    ["token", "bearer_token", "access_token", "secret"]
        .iter()
        .filter_map(|key| principal.get(*key).and_then(Value::as_str))
        .any(|candidate| constant_time_eq(candidate.trim().as_bytes(), token.as_bytes()))
}

fn registry_roles(principal: &Value) -> Result<Vec<String>, ApiError> {
    let mut roles = BTreeSet::new();
    for part in principal
        .get("roles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        match part.trim().to_lowercase().as_str() {
            "admin" => {
                roles.insert("admin".to_string());
                roles.insert("writer".to_string());
                roles.insert("reader".to_string());
            }
            "writer" => {
                roles.insert("writer".to_string());
                roles.insert("reader".to_string());
            }
            "reader" | "read" => {
                roles.insert("reader".to_string());
            }
            _ => {}
        }
    }
    let roles = roles.into_iter().collect::<Vec<_>>();
    if roles.is_empty() {
        Err(ApiError::unauthorized(
            "token registry principal has no supported roles",
        ))
    } else {
        Ok(roles)
    }
}

fn looks_like_legacy_role_token(token: &str) -> bool {
    let lower = token.trim().to_ascii_lowercase();
    matches!(lower.as_str(), "reader" | "writer" | "admin")
        || lower.starts_with("role=")
        || lower.starts_with("roles=")
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn context(input: Value) -> FlowContext {
        FlowContext {
            operation: "test".to_string(),
            input,
            path: BTreeMap::new(),
            query: BTreeMap::new(),
            auth: json!({ "authenticated": true, "roles": ["admin", "writer"] }),
            bindings: BTreeMap::new(),
        }
    }

    fn isolated() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap();
        let root = env::temp_dir().join(format!(
            "metadata-collection-runtime-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        env::set_var("METADATA_COLLECTION_DATA_DIR", root);
        guard
    }

    fn clear_auth_registry_env() {
        for name in [
            "METADATA_COLLECTION_AUTH_TOKENS_JSON",
            "FRONTPLANE_AUTH_TOKENS_JSON",
            "METADATA_COLLECTION_AUTH_TOKENS_FILE",
            "FRONTPLANE_AUTH_TOKENS_FILE",
        ] {
            env::remove_var(name);
        }
    }

    #[test]
    fn rejects_legacy_role_word_bearer_tokens() {
        let _guard = isolated();
        clear_auth_registry_env();
        let err = authenticate_bearer("writer").unwrap_err();
        assert_eq!(err.status, 401);
        assert!(err.message.contains("role-name bearer tokens"));
    }

    #[test]
    fn accepts_explicit_token_registry_principal() {
        let _guard = isolated();
        clear_auth_registry_env();
        env::set_var(
            "METADATA_COLLECTION_AUTH_TOKENS_JSON",
            r#"{
              "tokens": {
                "local-reader-token-0123456789abcdef": {
                  "subject_id": "acct-local-reader",
                  "handle": "local-reader",
                  "roles": ["reader"]
                }
              }
            }"#,
        );
        let auth = authenticate_bearer("local-reader-token-0123456789abcdef").unwrap();
        assert_eq!(auth["authenticated"], true);
        assert_eq!(auth["subject_id"], "acct-local-reader");
        assert_eq!(auth["roles"], json!(["reader"]));
        clear_auth_registry_env();
    }

    #[test]
    fn validates_relationship_bulk_endpoints() {
        let ctx = context(json!({
            "relationships": [{
                "from_type": "repository",
                "from_id": "repo-1",
                "to_type": "metadata",
                "to_id": "metadata-1",
                "relation": "describes"
            }]
        }));
        let validation = validate_relationship_bulk_upsert_request(&["input".to_string()], &ctx);
        assert_eq!(validation["valid"], false);
        assert_eq!(validation["code"], "invalid_from_type");
    }

    #[test]
    fn seeds_vulnerability_intelligence_profile() {
        let _guard = isolated();
        ensure_seeded().unwrap();
        assert!(get_record("profiles", PROFILE_ID).is_ok());
        assert!(read_collection("scenarios").unwrap().len() >= 10);
        assert!(read_collection("extractor-rules").unwrap().len() >= 10);
    }

    #[test]
    fn exposes_review_risk_score_catalog() {
        let _guard = isolated();
        let scores = list_scores(&json!({})).unwrap();
        assert_eq!(scores["items"].as_array().unwrap().len(), 10);
        let score = get_score(&json!({ "score_id": "implementation_concern_score" })).unwrap();
        assert_eq!(score["bucket"], "implementation_risk");
        let changed_lines_score = get_score(&json!({ "score_id": "changed_lines_score" })).unwrap();
        assert_eq!(changed_lines_score["bucket"], "change_size");
        let buckets = list_score_buckets(&json!({})).unwrap();
        assert_eq!(buckets["items"].as_array().unwrap().len(), 1);
        let bucket =
            get_score_bucket(&json!({ "score_bucket_id": REVIEW_RISK_SCORE_BUCKET_ID })).unwrap();
        assert_eq!(bucket["aggregation"], "weighted_average");
        assert_eq!(bucket["scores"].as_array().unwrap().len(), 10);
    }

    #[test]
    fn computes_review_risk_weighted_average_bucket() {
        let _guard = isolated();
        let result = compute_score_bucket(&json!({
            "score_bucket_id": REVIEW_RISK_SCORE_BUCKET_ID,
            "subject_id": "review:990485",
            "items": [
                { "score_id": "security_keyword_score", "score": 80.0, "confidence": 1.0 },
                { "score_id": "implementation_concern_score", "score": 60.0, "confidence": 0.5 },
                { "score_id": "review_friction_score", "value": { "score": 40.0 }, "weight": 2.0 }
            ]
        }))
        .unwrap();
        assert_eq!(result["score_bucket_id"], REVIEW_RISK_SCORE_BUCKET_ID);
        assert_eq!(result["items"].as_array().unwrap().len(), 3);
        assert_eq!(result["missing_score_ids"].as_array().unwrap().len(), 7);
        assert!((number_field(&result, "denominator", 0.0) - 4.15).abs() < 0.0001);
        assert!((number_field(&result, "score", 0.0) - 57.1084).abs() < 0.0001);
    }

    #[test]
    fn resolves_saves_and_adjusts_keyword_configs() {
        let _guard = isolated();
        let resolved =
            resolve_keyword_config(&json!({ "repository_id": "openstack/neutron" })).unwrap();
        assert_eq!(resolved["id"], "review-risk-keywords-openstack-neutron");
        assert_eq!(resolved["rules"].as_array().unwrap().len(), 6);

        let saved = save_keyword_config(&json!({
            "repository_id": "openstack/neutron",
            "rules": [{
                "id": "vulnerability_terms",
                "label": "Vulnerability terms",
                "pattern": "(vulnerab|exploit|cve|security)",
                "color": "not-a-color",
                "weight": 99,
                "order": 10,
                "enabled": true
            }]
        }))
        .unwrap();
        let saved_rule = saved["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| value_text(rule, "id") == "vulnerability_terms")
            .unwrap();
        assert_eq!(saved_rule["color"], "#245da8");
        assert_eq!(saved_rule["weight"], 99);

        let adjusted = adjust_keyword_config(&json!({
            "repository_id": "openstack/neutron",
            "keyword_id": "vulnerability_terms",
            "delta": 10
        }))
        .unwrap();
        let adjusted_rule = adjusted["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| value_text(rule, "id") == "vulnerability_terms")
            .unwrap();
        assert_eq!(adjusted_rule["weight"], 100);

        let listed = list_keyword_configs(&json!({})).unwrap();
        assert_eq!(listed["items"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn extracts_cve_and_security_fix_hits_from_art() {
        let _guard = isolated();
        ensure_seeded().unwrap();
        let rules = selected_rules(&json!({}), PROFILE_ID).unwrap();
        let art = json!({
            "repository_id": "repo-1",
            "source_id": "source-1",
            "art_id": "art-1",
            "author_id": "author-1",
            "source_kind": "art",
            "body": "Security fix for CVE-2025-12345 closes #42 and prevents authorization bypass."
        });
        let hits = extract_hits_for_item(
            &art,
            &rules,
            Some("run-1".to_string()),
            String::new(),
            BUNDLE_ID.to_string(),
            true,
            0.85,
            0.85,
        );
        assert!(hits.iter().any(|hit| value_text(hit, "key") == "cve"));
        assert!(hits
            .iter()
            .any(|hit| value_text(hit, "key") == "suspected_security_fix"));
        assert!(hits
            .iter()
            .any(|hit| value_text(hit, "disposition") == "accepted"));
    }

    #[test]
    fn prepare_commit_resolves_metadata_relationship_endpoints() {
        let _guard = isolated();
        ensure_seeded().unwrap();
        let hit = json!({
            "id": "evidence-hit-1",
            "collection_run_id": "run-1",
            "disposition": "accepted",
            "confidence": 0.99,
            "proposed_metadata": [{
                "local_ref": "metadata_local_1",
                "repository_id": "repo-1",
                "subject_type": "art",
                "subject_id": "art-1",
                "namespace": "security.identifier",
                "key": "cve",
                "value": "CVE-2025-12345",
                "value_type": "string"
            }],
            "proposed_relationships": [{
                "local_ref": "relationship_local_1",
                "repository_id": "repo-1",
                "from": { "type": "art", "id": "art-1" },
                "relation": "mentions",
                "to": { "type": "metadata", "metadata_local_ref": "metadata_local_1" },
                "confidence": 0.99,
                "evidence_art_id": "art-1",
                "origin": "test"
            }]
        });
        upsert_record("evidence-hits", &hit).unwrap();
        let metadata_req =
            prepare_metadata_bulk_upsert(&json!({ "evidence_hit_ids": ["evidence-hit-1"] }))
                .unwrap();
        assert_eq!(metadata_req["items"].as_array().unwrap().len(), 1);
        let relationship_req = prepare_relationship_bulk_upsert(
            &json!({ "evidence_hit_ids": ["evidence-hit-1"] }),
            &json!({ "items": [{ "id": "metadata-created-1" }] }),
        )
        .unwrap();
        assert_eq!(
            relationship_req["relationships"][0]["to_id"],
            "metadata-created-1"
        );
        let ctx = context(relationship_req);
        assert_eq!(
            validate_relationship_bulk_upsert_request(&["input".to_string()], &ctx)["valid"],
            true
        );
    }

    #[test]
    fn rerun_preserves_committed_evidence_hit_disposition() {
        let _guard = isolated();
        let committed = json!({
            "id": "evidence-hit-rerun",
            "hit_hash": "rerun",
            "collection_run_id": "run-1",
            "disposition": "committed",
            "confidence": 0.99,
            "committed_metadata_ids": ["metadata-1"],
            "committed_relationship_ids": ["relationship-1"],
            "matched_text_preview": "old"
        });
        upsert_evidence_hit(&committed).unwrap();
        let rerun = json!({
            "id": "evidence-hit-rerun",
            "hit_hash": "rerun",
            "collection_run_id": "run-2",
            "disposition": "accepted",
            "confidence": 0.99,
            "matched_text_preview": "CVE-2025-12345"
        });
        upsert_evidence_hit(&rerun).unwrap();
        let hit = get_record("evidence-hits", "evidence-hit-rerun").unwrap();
        assert_eq!(value_text(&hit, "disposition"), "committed");
        assert_eq!(hit["committed_metadata_ids"][0], "metadata-1");
        assert_eq!(hit["matched_text_preview"], "CVE-2025-12345");
    }
}
