use crate::frontplane_runtime::{resolve_arg, ApiError, FlowContext};
use postgres::{types::Json as PgJson, Client, NoTls};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
struct CollectionMeta {
    collection: &'static str,
    singular: &'static str,
    key: &'static str,
    prefix: &'static str,
}

const COLLECTIONS: &[CollectionMeta] = &[
    CollectionMeta {
        collection: "repository-groups",
        singular: "repository_group",
        key: "repository_group_id",
        prefix: "repository-group",
    },
    CollectionMeta {
        collection: "repositories",
        singular: "repository",
        key: "repository_id",
        prefix: "repository",
    },
    CollectionMeta {
        collection: "sources",
        singular: "source",
        key: "source_id",
        prefix: "source",
    },
    CollectionMeta {
        collection: "normalizers",
        singular: "normalizer",
        key: "normalizer_id",
        prefix: "normalizer",
    },
    CollectionMeta {
        collection: "ingestion-jobs",
        singular: "ingestion_job",
        key: "ingestion_job_id",
        prefix: "ingestion-job",
    },
    CollectionMeta {
        collection: "ingestion-logs",
        singular: "ingestion_log",
        key: "ingestion_log_id",
        prefix: "ingestion-log",
    },
    CollectionMeta {
        collection: "raw-records",
        singular: "raw_record",
        key: "raw_record_id",
        prefix: "raw-record",
    },
    CollectionMeta {
        collection: "authors",
        singular: "author",
        key: "author_id",
        prefix: "author",
    },
    CollectionMeta {
        collection: "arts",
        singular: "art",
        key: "art_id",
        prefix: "art",
    },
    CollectionMeta {
        collection: "metadata",
        singular: "metadata",
        key: "metadata_id",
        prefix: "metadata",
    },
    CollectionMeta {
        collection: "relationships",
        singular: "relationship",
        key: "relationship_id",
        prefix: "relationship",
    },
];

pub fn authenticate_bearer(token: &str) -> Result<Value, ApiError> {
    if token.trim().is_empty() {
        return Err(ApiError::unauthorized("empty bearer token"));
    }
    let roles = roles_from_token(token);
    Ok(json!({
        "authenticated": true,
        "authorization": format!("Bearer {token}"),
        "token": token,
        "subject_id": token.split(':').next().unwrap_or("developer"),
        "roles": roles
    }))
}

pub fn invoke(target: &str, args: &[String], context: &FlowContext) -> Result<Value, ApiError> {
    match target {
        "RepointelRuntime.validate_metadata_art_author_edge" => {
            Ok(validate_metadata_art_author_edge(args, context))
        }
        "RepointelRuntime.validate_bulk_metadata_edges" => {
            Ok(validate_bulk_metadata_edges(args, context))
        }
        "RepointelRuntime.validate_neighborhood_request" => {
            Ok(validate_neighborhood_request(args, context))
        }
        "RepointelRuntime.test_source_connection" => {
            handle_local_executable_target("test_source_connection", args, context)
        }
        "RepointelRuntime.test_normalizer" => {
            handle_local_executable_target("test_normalizer", args, context)
        }
        "RepointelRuntime.reprocess_raw_record" => {
            handle_local_executable_target("reprocess_raw_record", args, context)
        }
        target if target.starts_with("RepointelRuntime.") => {
            handle_persistence_target(target, args, context)
        }
        other => Err(ApiError::internal(format!(
            "call {other} is not implemented by RepointelRuntime backing"
        ))),
    }
}

fn validate_metadata_art_author_edge(args: &[String], context: &FlowContext) -> Value {
    validate_relationship_value(&arg_value(args, 0, context))
}

fn validate_bulk_metadata_edges(args: &[String], context: &FlowContext) -> Value {
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

fn validate_neighborhood_request(args: &[String], context: &FlowContext) -> Value {
    let input = arg_value(args, 0, context);
    let endpoint_type = text_field(&input, "endpoint_type");
    let endpoint_id = text_field(&input, "endpoint_id");
    if !valid_endpoint_type(&endpoint_type) {
        return invalid_result(
            "invalid_endpoint_type",
            "endpoint_type must be one of metadata, art, or author",
            json!({ "endpoint_type": endpoint_type }),
        );
    }
    if endpoint_id.is_empty() {
        return invalid_result(
            "missing_endpoint_id",
            "endpoint_id is required",
            json!({ "endpoint_type": endpoint_type }),
        );
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
    if relation.is_empty() {
        return invalid_result("missing_relation", "relation is required", json!({}));
    }
    if !relation_allowed(&from_type, &to_type, &relation) {
        return invalid_result(
            "invalid_relation",
            "relation is not allowed for the relationship endpoint pair",
            json!({
                "from_type": from_type,
                "to_type": to_type,
                "relation": relation
            }),
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
    let op = target.rsplit('.').next().unwrap_or(target);
    let input = arg_value(args, 0, context);
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        let op = op.to_string();
        return thread::spawn(move || handle_persistence_operation(&op, input))
            .join()
            .map_err(|_| ApiError::internal("postgres persistence worker panicked"))?;
    }
    handle_persistence_operation(op, input)
}

fn handle_persistence_operation(op: &str, input: Value) -> Result<Value, ApiError> {
    ensure_ingestion_scheduler_started();
    match op {
        "bulk_upsert_metadata" => bulk_upsert("metadata", "items", &input),
        "bulk_upsert_relationships" => bulk_upsert_relationships(&input),
        "get_relationship_neighborhood" => relationship_neighborhood(&input),
        "get_relationship_from" => relationship_endpoint(&input, true),
        "get_relationship_to" => relationship_endpoint(&input, false),
        "get_relationship_evidence" => relationship_evidence(&input),
        "get_relationship_raw_record" => referenced_record(
            "relationships",
            "relationship_id",
            &input,
            "raw_record_id",
            "raw-records",
        ),
        "get_metadata_subject" => metadata_subject(&input),
        "get_metadata_raw_record" => referenced_record(
            "metadata",
            "metadata_id",
            &input,
            "raw_record_id",
            "raw-records",
        ),
        "get_ingestion_log_job" => referenced_record(
            "ingestion-logs",
            "ingestion_log_id",
            &input,
            "ingestion_job_id",
            "ingestion-jobs",
        ),
        "get_raw_record_source" => referenced_record(
            "raw-records",
            "raw_record_id",
            &input,
            "source_id",
            "sources",
        ),
        "get_raw_record_ingestion_job" => referenced_record(
            "raw-records",
            "raw_record_id",
            &input,
            "ingestion_job_id",
            "ingestion-jobs",
        ),
        "get_art_author" => referenced_record("arts", "art_id", &input, "author_id", "authors"),
        "get_art_source" => referenced_record("arts", "art_id", &input, "source_id", "sources"),
        "get_art_raw_record" => {
            referenced_record("arts", "art_id", &input, "raw_record_id", "raw-records")
        }
        "enqueue_repository_ingestion" | "enqueue_source_ingestion" | "create_ingestion_job" => {
            create_ingestion_job(&input, "queued")
        }
        "retry_ingestion_job" => queue_ingestion_job(&input),
        "resume_ingestion_job" => queue_ingestion_job(&input),
        "pause_ingestion_job" => {
            status_update("ingestion-jobs", "ingestion_job_id", &input, "paused")
        }
        "cancel_ingestion_job" => {
            status_update("ingestion-jobs", "ingestion_job_id", &input, "cancelled")
        }
        "archive_repository_group" => status_update(
            "repository-groups",
            "repository_group_id",
            &input,
            "archived",
        ),
        "restore_repository_group" => {
            status_update("repository-groups", "repository_group_id", &input, "active")
        }
        "archive_repository" => status_update("repositories", "repository_id", &input, "archived"),
        "restore_repository" => status_update("repositories", "repository_id", &input, "active"),
        "enable_source" => bool_update("sources", "source_id", &input, "enabled", true),
        "disable_source" => bool_update("sources", "source_id", &input, "enabled", false),
        "enable_normalizer" => bool_update("normalizers", "normalizer_id", &input, "enabled", true),
        "disable_normalizer" => {
            bool_update("normalizers", "normalizer_id", &input, "enabled", false)
        }
        "merge_author" => merge_author(&input),
        "split_author" => split_author(&input),
        "search_relationships" => search_relationships(&input),
        other if member_page_operation(other).is_some() => {
            let (collection, field, id_field, mode) = member_page_operation(other).unwrap();
            member_page(collection, field, id_field, mode, &input)
        }
        other if other.starts_with("list_") => {
            let meta = collection_for_stem(other.trim_start_matches("list_"))?;
            list_records(meta.collection, &input)
        }
        other if other.starts_with("search_") => {
            let meta = collection_for_stem(other.trim_start_matches("search_"))?;
            search_records(meta.collection, &input)
        }
        other if other.starts_with("create_") => {
            let meta = collection_for_stem(other.trim_start_matches("create_"))?;
            if meta.collection == "relationships" {
                ensure_valid_relationship(&input)?;
            }
            create_record(meta.collection, &input)
        }
        other if other.starts_with("get_") => {
            let meta = collection_for_stem(other.trim_start_matches("get_"))?;
            get_record_by_input(meta.collection, meta.key, &input)
        }
        other if other.starts_with("update_") => {
            let meta = collection_for_stem(other.trim_start_matches("update_"))?;
            update_record(meta.collection, meta.key, &input)
        }
        other if other.starts_with("delete_") => {
            let meta = collection_for_stem(other.trim_start_matches("delete_"))?;
            delete_record(meta.collection, meta.key, &input)
        }
        other if other.starts_with("upsert_") => {
            let meta = collection_for_stem(other.trim_start_matches("upsert_"))?;
            if meta.collection == "relationships" {
                ensure_valid_relationship(&input)?;
            }
            upsert_record(meta.collection, &input)
        }
        other => Err(ApiError::internal(format!(
            "persistence operation {other} is not implemented"
        ))),
    }
}

fn handle_local_executable_target(
    op: &str,
    args: &[String],
    context: &FlowContext,
) -> Result<Value, ApiError> {
    let input = arg_value(args, 0, context);
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        let op = op.to_string();
        return thread::spawn(move || handle_local_executable_operation(&op, input))
            .join()
            .map_err(|_| ApiError::internal("postgres local executable worker panicked"))?;
    }
    handle_local_executable_operation(op, input)
}

fn handle_local_executable_operation(op: &str, input: Value) -> Result<Value, ApiError> {
    let env_name = match op {
        "test_source_connection" => "REPOINTEL_SOURCE_TEST_COMMAND",
        "test_normalizer" => "REPOINTEL_NORMALIZER_TEST_COMMAND",
        "reprocess_raw_record" => "REPOINTEL_REPROCESS_COMMAND",
        _ => "",
    };
    if let Ok(command) = env::var(env_name) {
        let output = Command::new(command)
            .arg(serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string()))
            .output()
            .map_err(|err| ApiError::provider(format!("{op} command failed: {err}")))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ApiError::provider(format!(
                "{op} command exited unsuccessfully: {stderr}"
            )));
        }
        if let Ok(value) = serde_json::from_str::<Value>(&stdout) {
            return Ok(value);
        }
    }
    match op {
        "test_source_connection" => Ok(json!({
            "ok": true,
            "provider": source_provider(&input).unwrap_or_else(|| "unknown".to_string()),
            "message": "source connection test command is not configured; validation boundary passed",
            "details": { "source_id": text_field(&input, "source_id") }
        })),
        "test_normalizer" => Ok(json!({
            "ok": true,
            "raw_records_count": 0,
            "arts_count": 0,
            "authors_count": 0,
            "metadata_count": 0,
            "relationships_count": 0,
            "logs": ["normalizer test command is not configured; validation boundary passed"],
            "details": { "normalizer_id": text_field(&input, "normalizer_id") }
        })),
        "reprocess_raw_record" => create_ingestion_job(&input, "queued"),
        _ => Err(ApiError::internal(format!(
            "LEcall operation {op} is not implemented"
        ))),
    }
}

fn bulk_upsert(collection: &str, array_field: &str, input: &Value) -> Result<Value, ApiError> {
    let items = input
        .get(array_field)
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad_request(format!("{array_field} must be an array")))?;
    let mut upserted = Vec::new();
    for item in items {
        upserted.push(upsert_record(collection, item)?);
    }
    Ok(page(upserted, input))
}

fn bulk_upsert_relationships(input: &Value) -> Result<Value, ApiError> {
    let validation = validate_relationship_value(input);
    if input
        .get("relationships")
        .and_then(Value::as_array)
        .is_none()
        && validation.get("valid").and_then(Value::as_bool) == Some(false)
    {
        return Err(ApiError::bad_request(
            "relationships must be supplied as an array",
        ));
    }
    let items = input
        .get("relationships")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad_request("relationships must be supplied as an array"))?;
    let mut upserted = Vec::new();
    for item in items {
        ensure_valid_relationship(item)?;
        upserted.push(upsert_record("relationships", item)?);
    }
    Ok(page(upserted, input))
}

fn create_ingestion_job(input: &Value, status: &str) -> Result<Value, ApiError> {
    let mut job = object_from(input);
    job.insert("status".to_string(), json!(status));
    job.entry("mode".to_string())
        .or_insert_with(|| json!("incremental"));
    let created = create_record("ingestion-jobs", &Value::Object(job))?;
    if status == "queued" {
        start_ingestion_worker(value_text(&created, "id"));
    }
    Ok(created)
}

#[derive(Default)]
struct IngestionCounts {
    raw_records: i64,
    arts: i64,
    authors: i64,
    metadata: i64,
    relationships: i64,
}

#[derive(Default)]
struct GitCommitFileMetadata {
    files: Vec<Value>,
    changed_files: Vec<String>,
    insertions: i64,
    deletions: i64,
    binary_files: i64,
}

#[derive(Clone, Default)]
struct GitLineOwner {
    commit_sha: String,
    author_key: String,
    author_name: String,
    author_email: String,
    authored_at: String,
    track_stats: bool,
}

#[derive(Clone, Default)]
struct GitLineSurvivalCommitStats {
    sha: String,
    authored_at: String,
    author_key: String,
    author_name: String,
    author_email: String,
    files: BTreeSet<String>,
    insertions: i64,
    deletions: i64,
    surviving_lines: i64,
    self_reworked_lines: i64,
    cross_author_overwritten_lines: i64,
    overwritten_by: BTreeMap<String, i64>,
}

#[derive(Clone, Default)]
struct GitLineSurvivalAuthorStats {
    author_key: String,
    author_name: String,
    author_email: String,
    commits: BTreeSet<String>,
    insertions: i64,
    deletions: i64,
    surviving_lines: i64,
    self_reworked_lines: i64,
    cross_author_overwritten_lines: i64,
    overwrote_other_author_lines: i64,
}

#[derive(Default)]
struct GitLineSurvivalAnalysis {
    branch: String,
    head_sha: String,
    commit_count: i64,
    since_epoch: Option<i64>,
    commits_replayed: i64,
    commits_seen: i64,
    commits_before_since: i64,
    commits_analyzed: i64,
    commits_skipped_by_size: i64,
    max_changed_lines: i64,
    files_tracked: i64,
    commits: BTreeMap<String, GitLineSurvivalCommitStats>,
    authors: BTreeMap<String, GitLineSurvivalAuthorStats>,
}

#[derive(Clone, Default)]
struct GerritApprovalLineSurvivalApproval {
    raw: Value,
    source: Value,
    reviewer_author_id: String,
    reviewer_key: String,
    gerrit_account_id: String,
    change_number: String,
    change_id: String,
    commit_sha: String,
    labels: BTreeSet<String>,
    change_insertions: i64,
    change_deletions: i64,
    change_lines: i64,
    updated_at: String,
}

#[derive(Default)]
struct GerritApprovalLineSurvivalReviewerStats {
    reviewer_author_id: String,
    reviewer_key: String,
    gerrit_account_ids: BTreeSet<String>,
    reviewed_changes: BTreeSet<String>,
    commit_shas: BTreeSet<String>,
    labels: BTreeMap<String, i64>,
    approvals_count: i64,
    insertions: i64,
    deletions: i64,
    surviving_lines: i64,
    self_reworked_lines: i64,
    cross_author_overwritten_lines: i64,
    first_raw: Value,
    first_source: Value,
}

fn ensure_ingestion_scheduler_started() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let _ = thread::Builder::new()
            .name("repointel-ingestion-scheduler".to_string())
            .spawn(|| loop {
                if let Ok(jobs) = read_collection("ingestion-jobs") {
                    for job in jobs {
                        if should_start_ingestion_job(&job) {
                            start_ingestion_worker(value_text(&job, "id"));
                        }
                    }
                }
                thread::sleep(Duration::from_secs(5));
            });
    });
}

fn should_start_ingestion_job(job: &Value) -> bool {
    matches!(value_text(job, "status").as_str(), "queued" | "running")
        && value_text(job, "finished_at").is_empty()
}

fn active_ingestion_jobs() -> &'static Mutex<BTreeSet<String>> {
    static ACTIVE: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn mark_ingestion_job_active(job_id: &str) -> bool {
    let mut active = active_ingestion_jobs()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    active.insert(job_id.to_string())
}

fn mark_ingestion_job_inactive(job_id: &str) {
    let mut active = active_ingestion_jobs()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    active.remove(job_id);
}

fn store_write_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StorageBackend {
    Json,
    Postgres(String),
}

struct PostgresClientState {
    database_url: String,
    client: Client,
}

fn storage_backend() -> Result<StorageBackend, ApiError> {
    let mode = env::var("REPOINTEL_STORAGE")
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    if mode == "json" || mode == "file" {
        return Ok(StorageBackend::Json);
    }
    let database_url = env::var("REPOINTEL_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .unwrap_or_default();
    if !database_url.trim().is_empty() {
        return Ok(StorageBackend::Postgres(database_url));
    }
    if mode == "postgres" || mode == "postgresql" {
        return Err(ApiError::internal(
            "REPOINTEL_STORAGE=postgres requires REPOINTEL_DATABASE_URL".to_string(),
        ));
    }
    Ok(StorageBackend::Json)
}

fn postgres_client_state() -> &'static Mutex<Option<PostgresClientState>> {
    static STATE: OnceLock<Mutex<Option<PostgresClientState>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

fn with_postgres_client<T>(
    action: impl FnOnce(&mut Client) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let StorageBackend::Postgres(database_url) = storage_backend()? else {
        return Err(ApiError::internal(
            "postgres backend is not configured".to_string(),
        ));
    };
    let mut guard = postgres_client_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let should_connect = guard
        .as_ref()
        .map(|state| state.database_url != database_url)
        .unwrap_or(true);
    if should_connect {
        let mut client = Client::connect(&database_url, NoTls)
            .map_err(|err| ApiError::internal(format!("failed connecting to postgres: {err}")))?;
        ensure_postgres_schema(&mut client)?;
        maybe_import_json_store(&mut client)?;
        *guard = Some(PostgresClientState {
            database_url: database_url.clone(),
            client,
        });
    }
    let state = guard
        .as_mut()
        .ok_or_else(|| ApiError::internal("postgres client was not initialized".to_string()))?;
    match action(&mut state.client) {
        Ok(value) => Ok(value),
        Err(err) => {
            *guard = None;
            Err(err)
        }
    }
}

fn ensure_postgres_schema(client: &mut Client) -> Result<(), ApiError> {
    client
        .batch_execute(
            r#"
            CREATE TABLE IF NOT EXISTS repointel_records (
                collection TEXT NOT NULL,
                id TEXT NOT NULL,
                doc JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY (collection, id)
            );
            CREATE TABLE IF NOT EXISTS repointel_store_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            CREATE INDEX IF NOT EXISTS repointel_records_collection_idx
                ON repointel_records (collection);
            CREATE INDEX IF NOT EXISTS repointel_records_source_idx
                ON repointel_records (collection, (doc->>'source_id'));
            CREATE INDEX IF NOT EXISTS repointel_records_job_idx
                ON repointel_records (collection, (doc->>'ingestion_job_id'));
            CREATE INDEX IF NOT EXISTS repointel_records_repo_idx
                ON repointel_records (collection, (doc->>'repository_id'));
            CREATE INDEX IF NOT EXISTS repointel_records_doc_gin_idx
                ON repointel_records USING GIN (doc);
            CREATE INDEX IF NOT EXISTS repointel_relationship_from_idx
                ON repointel_records ((doc->>'from_type'), (doc->>'from_id'))
                WHERE collection = 'relationships';
            CREATE INDEX IF NOT EXISTS repointel_relationship_to_idx
                ON repointel_records ((doc->>'to_type'), (doc->>'to_id'))
                WHERE collection = 'relationships';
            CREATE INDEX IF NOT EXISTS repointel_relationship_relation_idx
                ON repointel_records ((doc->>'relation'))
                WHERE collection = 'relationships';
            CREATE INDEX IF NOT EXISTS repointel_relationship_origin_idx
                ON repointel_records ((doc->>'origin'))
                WHERE collection = 'relationships';
            CREATE INDEX IF NOT EXISTS repointel_metadata_namespace_key_idx
                ON repointel_records ((doc->>'namespace'), (doc->>'key'))
                WHERE collection = 'metadata';
            CREATE INDEX IF NOT EXISTS repointel_metadata_subject_idx
                ON repointel_records ((doc->>'subject_type'), (doc->>'subject_id'))
                WHERE collection = 'metadata';
            CREATE INDEX IF NOT EXISTS repointel_raw_record_type_idx
                ON repointel_records ((doc->>'source_id'), (doc->>'record_type'))
                WHERE collection = 'raw-records';
            CREATE INDEX IF NOT EXISTS repointel_art_context_idx
                ON repointel_records ((doc->>'source_id'), (doc->>'context_type'), (doc->>'context_external_id'))
                WHERE collection = 'arts';
            CREATE INDEX IF NOT EXISTS repointel_art_raw_record_idx
                ON repointel_records ((doc->>'raw_record_id'))
                WHERE collection = 'arts';
            CREATE INDEX IF NOT EXISTS repointel_art_review_context_idx
                ON repointel_records ((doc->>'context_external_id'), (doc->>'type'), (doc->>'author_id'))
                WHERE collection = 'arts';
            CREATE INDEX IF NOT EXISTS repointel_author_external_idx
                ON repointel_records ((doc->>'external_author_id'))
                WHERE collection = 'authors';
            CREATE INDEX IF NOT EXISTS repointel_author_email_idx
                ON repointel_records ((doc->>'email'))
                WHERE collection = 'authors';
            CREATE INDEX IF NOT EXISTS repointel_metadata_subject_namespace_key_idx
                ON repointel_records ((doc->>'subject_type'), (doc->>'subject_id'), (doc->>'namespace'), (doc->>'key'))
                WHERE collection = 'metadata';
            CREATE INDEX IF NOT EXISTS repointel_raw_gerrit_change_lookup_idx
                ON repointel_records (
                    (doc->>'repository_id'),
                    ((doc->'payload'->>'project')),
                    (upper(coalesce(nullif(doc->'payload'->>'status', ''), 'UNKNOWN'))),
                    ((doc->'payload'->>'_number'))
                )
                WHERE collection = 'raw-records' AND doc->>'record_type' = 'gerrit_change';
            "#,
        )
        .map_err(|err| ApiError::internal(format!("failed preparing postgres schema: {err}")))
}

fn maybe_import_json_store(client: &mut Client) -> Result<(), ApiError> {
    let import_dir = env::var("REPOINTEL_IMPORT_JSON_DIR")
        .or_else(|_| env::var("REPOINTEL_DATA_DIR"))
        .unwrap_or_default();
    if import_dir.trim().is_empty() {
        return Ok(());
    }
    let force = env_flag("REPOINTEL_IMPORT_JSON_FORCE");
    let marker = format!("json_imported:{}", import_dir);
    if !force
        && client
            .query_opt(
                "SELECT value FROM repointel_store_meta WHERE key = $1",
                &[&marker],
            )
            .map_err(|err| ApiError::internal(format!("failed checking import marker: {err}")))?
            .is_some()
    {
        return Ok(());
    }
    if !force {
        let count: i64 = client
            .query_one("SELECT COUNT(*) FROM repointel_records", &[])
            .map_err(|err| ApiError::internal(format!("failed checking postgres store: {err}")))?
            .get(0);
        if count > 0 {
            return Ok(());
        }
    }
    let root = PathBuf::from(import_dir.trim());
    if !root.exists() {
        return Ok(());
    }
    let mut imported = 0i64;
    let mut transaction = client
        .transaction()
        .map_err(|err| ApiError::internal(format!("failed starting import transaction: {err}")))?;
    for meta in COLLECTIONS {
        let path = root.join(format!("{}.json", meta.collection));
        if !path.exists() {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|err| {
            ApiError::internal(format!(
                "failed reading import file {}: {err}",
                path.display()
            ))
        })?;
        if text.trim().is_empty() {
            continue;
        }
        let records = serde_json::from_str::<Vec<Value>>(&text).map_err(|err| {
            ApiError::internal(format!(
                "failed parsing import file {}: {err}",
                path.display()
            ))
        })?;
        for record in records {
            let id = value_text(&record, "id");
            if id.is_empty() {
                continue;
            }
            let doc = PgJson(&record);
            transaction
                .execute(
                    r#"
                    INSERT INTO repointel_records (collection, id, doc, created_at, updated_at)
                    VALUES ($1, $2, $3, now(), now())
                    ON CONFLICT (collection, id) DO UPDATE
                    SET doc = EXCLUDED.doc, updated_at = now()
                    "#,
                    &[&meta.collection, &id, &doc],
                )
                .map_err(|err| {
                    ApiError::internal(format!(
                        "failed importing {} record {}: {err}",
                        meta.collection, id
                    ))
                })?;
            imported += 1;
        }
    }
    transaction
        .execute(
            r#"
            INSERT INTO repointel_store_meta (key, value, updated_at)
            VALUES ($1, $2, now())
            ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value, updated_at = now()
            "#,
            &[&marker, &imported.to_string()],
        )
        .map_err(|err| ApiError::internal(format!("failed writing import marker: {err}")))?;
    transaction
        .commit()
        .map_err(|err| ApiError::internal(format!("failed committing json import: {err}")))
}

fn env_flag(key: &str) -> bool {
    matches!(
        env::var(key)
            .unwrap_or_default()
            .trim()
            .to_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn ingestion_stop_status(job_id: &str) -> Option<String> {
    let status = get_record("ingestion-jobs", job_id)
        .ok()
        .map(|job| value_text(&job, "status"))?;
    if is_ingestion_stop_status(&status) {
        Some(status)
    } else {
        None
    }
}

fn is_ingestion_stop_status(status: &str) -> bool {
    matches!(status, "cancelled" | "canceled" | "pausing" | "paused")
}

fn start_ingestion_worker(job_id: String) {
    if job_id.is_empty() {
        return;
    }
    if !mark_ingestion_job_active(&job_id) {
        return;
    }
    let worker_job_id = job_id.clone();
    let spawn_result = thread::Builder::new()
        .name(format!("repointel-ingest-{job_id}"))
        .spawn(move || {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                process_ingestion_job(&worker_job_id)
            })) {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    let _ = fail_ingestion_job(&worker_job_id, &err.message);
                }
                Err(payload) => {
                    let _ = fail_ingestion_job(
                        &worker_job_id,
                        &format!(
                            "ingestion worker panicked: {}",
                            panic_payload_message(&payload)
                        ),
                    );
                }
            }
            mark_ingestion_job_inactive(&worker_job_id);
        });
    if spawn_result.is_err() {
        mark_ingestion_job_inactive(&job_id);
    }
}

fn panic_payload_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

fn process_ingestion_job(job_id: &str) -> Result<(), ApiError> {
    let started = now_timestamp();
    update_record(
        "ingestion-jobs",
        "ingestion_job_id",
        &json!({
            "ingestion_job_id": job_id,
            "status": "running",
            "started_at": started,
            "error": ""
        }),
    )?;
    let job = get_record("ingestion-jobs", job_id)?;
    log_ingestion(&job, "job", "info", "ingestion job started", json!({}))?;

    if is_art_metadata_reprocess_job(&job) {
        let counts = reprocess_art_metadata_job(&job)?;
        update_ingestion_job_counts(
            job_id,
            "completed",
            &counts,
            json!({ "finished_at": now_timestamp() }),
        )?;
        let finished_job = get_record("ingestion-jobs", job_id)?;
        log_ingestion(
            &finished_job,
            "job",
            "info",
            "art metadata reprocess job completed",
            json!({
                "arts_count": counts.arts,
                "metadata_count": counts.metadata,
                "relationships_count": counts.relationships
            }),
        )?;
        return Ok(());
    } else if is_raw_metadata_reprocess_job(&job) {
        let counts = reprocess_raw_metadata_job(&job)?;
        update_ingestion_job_counts(
            job_id,
            "completed",
            &counts,
            json!({ "finished_at": now_timestamp() }),
        )?;
        let finished_job = get_record("ingestion-jobs", job_id)?;
        log_ingestion(
            &finished_job,
            "job",
            "info",
            "raw metadata reprocess job completed",
            json!({
                "raw_records_count": counts.raw_records,
                "metadata_count": counts.metadata,
                "relationships_count": counts.relationships
            }),
        )?;
        return Ok(());
    }

    let sources = job_sources(&job)?;
    let job_sources_for_post_pass = sources.clone();
    let mut counts = IngestionCounts::default();
    for source in sources {
        if let Some(status) = ingestion_stop_status(job_id) {
            let current_job = get_record("ingestion-jobs", job_id).unwrap_or_else(|_| job.clone());
            log_ingestion(
                &current_job,
                "job",
                "info",
                &format!("ingestion job stopped with status {status}"),
                json!({ "status": status }),
            )?;
            return Ok(());
        }
        let provider = value_text(&source, "provider");
        let source_counts = match provider.as_str() {
            "git" => ingest_git_source(&job, &source),
            "launchpad" => ingest_launchpad_source(&job, &source),
            "gerrit" => ingest_gerrit_source(&job, &source),
            other => {
                log_ingestion(
                    &job,
                    "source",
                    "warn",
                    &format!("no built-in ingester for provider {other}"),
                    json!({ "source_id": value_text(&source, "id"), "provider": other }),
                )?;
                Ok(IngestionCounts::default())
            }
        }?;
        counts.raw_records += source_counts.raw_records;
        counts.arts += source_counts.arts;
        counts.authors += source_counts.authors;
        counts.metadata += source_counts.metadata;
        counts.relationships += source_counts.relationships;
        update_ingestion_job_counts(job_id, "running", &counts, json!({}))?;
    }
    if let Some(status) = ingestion_stop_status(job_id) {
        let current_job = get_record("ingestion-jobs", job_id).unwrap_or_else(|_| job.clone());
        log_ingestion(
            &current_job,
            "job",
            "info",
            &format!("ingestion job stopped with status {status}"),
            json!({ "status": status }),
        )?;
        return Ok(());
    }
    if should_run_repository_approval_line_survival_after_sources(&job) {
        let extra =
            run_repository_approval_line_survival_after_sources(&job, &job_sources_for_post_pass)?;
        merge_ingestion_counts(&mut counts, extra);
        update_ingestion_job_counts(
            job_id,
            "running",
            &counts,
            json!({ "approval_line_survival": "post_source_pass_completed" }),
        )?;
    }
    if should_reprocess_all_metadata_normalizers(&job) {
        let normalized = run_metadata_normalizer_reprocess_job(&job)?;
        counts.metadata += normalized.metadata;
        counts.relationships += normalized.relationships;
        update_ingestion_job_counts(
            job_id,
            "running",
            &counts,
            json!({
                "metadata_normalizers": "completed",
                "metadata_normalizer_counts": {
                    "raw_records_reprocessed": normalized.raw_records,
                    "arts_reprocessed": normalized.arts,
                    "authors_reprocessed": normalized.authors,
                    "metadata_count": normalized.metadata,
                    "relationships_count": normalized.relationships
                }
            }),
        )?;
    }
    if should_run_sensitivity_scoring(&job) {
        let scored_metadata = run_sensitivity_scoring_job(&job)?;
        counts.metadata += scored_metadata;
        update_ingestion_job_counts(
            job_id,
            "running",
            &counts,
            json!({
                "sensitivity_scoring": "completed",
                "sensitivity_metadata_count": scored_metadata
            }),
        )?;
    }
    update_ingestion_job_counts(
        job_id,
        "completed",
        &counts,
        json!({ "finished_at": now_timestamp() }),
    )?;
    let finished_job = get_record("ingestion-jobs", job_id)?;
    log_ingestion(
        &finished_job,
        "job",
        "info",
        "ingestion job completed",
        json!({
            "raw_records_count": counts.raw_records,
            "arts_count": counts.arts,
            "authors_count": counts.authors
        }),
    )?;
    Ok(())
}

fn fail_ingestion_job(job_id: &str, message: &str) -> Result<(), ApiError> {
    update_record(
        "ingestion-jobs",
        "ingestion_job_id",
        &json!({
            "ingestion_job_id": job_id,
            "status": "failed",
            "finished_at": now_timestamp(),
            "error": message
        }),
    )?;
    if let Ok(job) = get_record("ingestion-jobs", job_id) {
        let _ = log_ingestion(
            &job,
            "job",
            "error",
            "ingestion job failed",
            json!({ "error": message }),
        );
    }
    Ok(())
}

fn update_ingestion_job_counts(
    job_id: &str,
    status: &str,
    counts: &IngestionCounts,
    extra: Value,
) -> Result<Value, ApiError> {
    let current_record = if matches!(status, "running" | "completed" | "failed") {
        match get_record("ingestion-jobs", job_id) {
            Ok(current) => {
                if is_ingestion_stop_status(&value_text(&current, "status")) {
                    return Ok(current);
                }
                Some(current)
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let mut patch = object_from(&extra);
    if let Some(extra_stats) = patch.get("stats").cloned() {
        if let Some(extra_stats_obj) = extra_stats.as_object() {
            let mut merged_stats = current_record
                .as_ref()
                .and_then(|current| current.get("stats"))
                .map(object_from)
                .unwrap_or_default();
            for (key, value) in extra_stats_obj {
                merged_stats.insert(key.clone(), value.clone());
            }
            patch.insert("stats".to_string(), Value::Object(merged_stats));
        }
    }
    patch.insert("ingestion_job_id".to_string(), json!(job_id));
    patch.insert("status".to_string(), json!(status));
    patch.insert("raw_records_count".to_string(), json!(counts.raw_records));
    patch.insert("arts_count".to_string(), json!(counts.arts));
    patch.insert("authors_count".to_string(), json!(counts.authors));
    patch.insert("metadata_count".to_string(), json!(counts.metadata));
    patch.insert(
        "relationships_count".to_string(),
        json!(counts.relationships),
    );
    if status == "completed" {
        patch.insert("error".to_string(), json!(""));
    }
    if status == "completed" || status == "failed" {
        patch
            .entry("finished_at".to_string())
            .or_insert_with(|| json!(now_timestamp()));
    }
    update_record("ingestion-jobs", "ingestion_job_id", &Value::Object(patch))
}

fn job_sources(job: &Value) -> Result<Vec<Value>, ApiError> {
    let source_id = value_text(job, "source_id");
    if !source_id.is_empty() {
        return Ok(vec![get_record("sources", &source_id)?]);
    }
    let repository_id = value_text(job, "repository_id");
    let mut sources = read_collection("sources")?;
    if !repository_id.is_empty() {
        sources.retain(|source| value_text(source, "repository_id") == repository_id);
    }
    sources.retain(|source| source.get("enabled").and_then(Value::as_bool) != Some(false));
    Ok(sources)
}

fn should_reprocess_all_metadata_normalizers(job: &Value) -> bool {
    job_param_bool(job, "reprocess_all_normalizers", false)
        || job_param_bool(job, "reprocess_all_metadata_normalizers", false)
        || job_param_bool(
            job,
            "run_metadata_normalizers_over_persisted_records",
            false,
        )
}

fn run_metadata_normalizer_reprocess_job(job: &Value) -> Result<IngestionCounts, ApiError> {
    log_ingestion(
        job,
        "metadata-normalizers",
        "info",
        "running metadata normalizers over persisted records",
        json!({
            "repository_id": value_text(job, "repository_id"),
            "source_id": value_text(job, "source_id")
        }),
    )?;

    let raw_counts = reprocess_raw_metadata_job(job)?;
    let art_counts = reprocess_art_metadata_job(job)?;
    let author_counts = reprocess_author_metadata_job(job)?;

    let mut counts = IngestionCounts::default();
    counts.raw_records = raw_counts.raw_records;
    counts.arts = art_counts.arts;
    counts.authors = author_counts.authors;
    counts.metadata = raw_counts.metadata + art_counts.metadata + author_counts.metadata;
    counts.relationships =
        raw_counts.relationships + art_counts.relationships + author_counts.relationships;

    log_ingestion(
        job,
        "metadata-normalizers",
        "info",
        "metadata normalizers completed",
        json!({
            "raw_records_reprocessed": counts.raw_records,
            "arts_reprocessed": counts.arts,
            "authors_reprocessed": counts.authors,
            "metadata_count": counts.metadata,
            "relationships_count": counts.relationships
        }),
    )?;
    Ok(counts)
}

fn should_run_sensitivity_scoring(job: &Value) -> bool {
    job_param_bool(job, "run_sensitivity_scoring", false)
}

fn run_sensitivity_scoring_job(job: &Value) -> Result<i64, ApiError> {
    let command = env::var("REPOINTEL_SENSITIVITY_SCORER_COMMAND")
        .or_else(|_| env::var("REPOINTEL_ONNX_SCORER_COMMAND"))
        .unwrap_or_default();
    if command.trim().is_empty() {
        log_ingestion(
            job,
            "scoring",
            "warn",
            "sensitivity scoring requested but REPOINTEL_SENSITIVITY_SCORER_COMMAND is not configured",
            json!({}),
        )?;
        return Ok(0);
    }
    log_ingestion(
        job,
        "scoring",
        "info",
        "running sensitivity scorer",
        json!({ "command": command }),
    )?;
    let output = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .map_err(|err| ApiError::provider(format!("sensitivity scorer failed: {err}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        log_ingestion(
            job,
            "scoring",
            "error",
            "sensitivity scorer exited unsuccessfully",
            json!({
                "status": output.status.code(),
                "stdout": compact_log_text(&stdout, 2000),
                "stderr": compact_log_text(&stderr, 2000)
            }),
        )?;
        return Err(ApiError::provider(format!(
            "sensitivity scorer exited unsuccessfully: {}",
            compact_log_text(&stderr, 500)
        )));
    }
    let written = parse_sensitivity_written_count(&stdout);
    log_ingestion(
        job,
        "scoring",
        "info",
        "sensitivity scoring completed",
        json!({
            "metadata_count": written,
            "stdout": compact_log_text(&stdout, 2000),
            "stderr": compact_log_text(&stderr, 1000)
        }),
    )?;
    Ok(written)
}

fn parse_sensitivity_written_count(stdout: &str) -> i64 {
    for line in stdout.lines().rev() {
        if !line.contains("security-score-complete") {
            continue;
        }
        for part in line.split_whitespace() {
            if let Some(value) = part.strip_prefix("written=") {
                return value.parse::<i64>().unwrap_or(0);
            }
        }
    }
    0
}

fn compact_log_text(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    trimmed
        .chars()
        .rev()
        .take(max_chars)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

fn is_raw_metadata_reprocess_job(job: &Value) -> bool {
    !value_text(job, "raw_record_id").is_empty()
        || matches!(
            value_text(job, "mode").as_str(),
            "raw-metadata-reprocess" | "metadata-reprocess" | "reprocess-raw-metadata"
        )
}

fn is_art_metadata_reprocess_job(job: &Value) -> bool {
    !value_text(job, "art_id").is_empty()
        || matches!(
            value_text(job, "mode").as_str(),
            "art-metadata-reprocess" | "reprocess-art-metadata"
        )
}

fn reprocess_art_metadata_job(job: &Value) -> Result<IngestionCounts, ApiError> {
    let mut arts = read_collection("arts")?;
    let art_id = value_text(job, "art_id");
    let source_id = value_text(job, "source_id");
    let repository_id = value_text(job, "repository_id");
    let art_type = job_param_text(job, "art_type");
    if !art_id.is_empty() {
        arts.retain(|art| value_text(art, "id") == art_id);
    }
    if !source_id.is_empty() {
        arts.retain(|art| value_text(art, "source_id") == source_id);
    }
    if !repository_id.is_empty() {
        arts.retain(|art| value_text(art, "repository_id") == repository_id);
    }
    if !art_type.is_empty() {
        arts.retain(|art| value_text(art, "type") == art_type);
    }
    arts.sort_by(|left, right| value_text(left, "id").cmp(&value_text(right, "id")));

    let source_ids = arts
        .iter()
        .map(|art| value_text(art, "source_id"))
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>();
    let raw_ids = arts
        .iter()
        .map(|art| value_text(art, "raw_record_id"))
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>();
    let author_ids = arts
        .iter()
        .map(|art| value_text(art, "author_id"))
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>();
    let source_cache = records_by_id("sources", &source_ids)?;
    let raw_cache = records_by_id("raw-records", &raw_ids)?;
    let author_cache = records_by_id("authors", &author_ids)?;
    let explicit_normalizer = explicit_job_normalizer(job)?;
    let mut counts = IngestionCounts::default();
    for art in arts {
        if let Some(status) = ingestion_stop_status(&value_text(job, "id")) {
            log_ingestion(
                job,
                "art-metadata",
                "info",
                &format!("stopping art metadata reprocess because job is {status}"),
                json!({ "status": status }),
            )?;
            return Ok(counts);
        }
        let art_source_id = value_text(&art, "source_id");
        let source = indexed_record_or_get(&source_cache, "sources", &art_source_id)?;
        let raw = indexed_record_or_get(
            &raw_cache,
            "raw-records",
            &value_text(&art, "raw_record_id"),
        )?;
        let author =
            indexed_record_or_get(&author_cache, "authors", &value_text(&art, "author_id"))?;
        let extra = if let Some(normalizer) = explicit_normalizer.as_ref() {
            persist_art_metadata_with_normalizer(job, &source, &raw, &author, &art, normalizer)?
        } else {
            persist_art_metadata(job, &source, &raw, &author, &art)?
        };
        merge_ingestion_counts(&mut counts, extra);
        counts.arts += 1;
        if counts.arts % 500 == 0 {
            let _ = update_ingestion_job_counts(
                &value_text(job, "id"),
                "running",
                &counts,
                json!({
                    "active_source_id": art_source_id,
                    "arts_reprocessed": counts.arts
                }),
            );
        }
    }
    Ok(counts)
}

fn reprocess_author_metadata_job(job: &Value) -> Result<IngestionCounts, ApiError> {
    let mut authors = read_collection("authors")?;
    let author_id = value_text(job, "author_id");
    let source_id = value_text(job, "source_id");
    let repository_id = value_text(job, "repository_id");
    if !author_id.is_empty() {
        authors.retain(|author| value_text(author, "id") == author_id);
    }
    if !source_id.is_empty() {
        authors.retain(|author| value_text(author, "source_id") == source_id);
    }
    if !repository_id.is_empty() {
        authors.retain(|author| value_text(author, "repository_id") == repository_id);
    }
    authors.sort_by(|left, right| value_text(left, "id").cmp(&value_text(right, "id")));

    let source_ids = authors
        .iter()
        .map(|author| value_text(author, "source_id"))
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>();
    let raw_ids = authors
        .iter()
        .map(|author| value_text(author, "raw_record_id"))
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>();
    let source_cache = records_by_id("sources", &source_ids)?;
    let raw_cache = records_by_id("raw-records", &raw_ids)?;
    let explicit_normalizer = explicit_job_normalizer(job)?;
    let mut counts = IngestionCounts::default();
    for author in authors {
        if let Some(status) = ingestion_stop_status(&value_text(job, "id")) {
            log_ingestion(
                job,
                "author-metadata",
                "info",
                &format!("stopping author metadata reprocess because job is {status}"),
                json!({ "status": status }),
            )?;
            return Ok(counts);
        }
        let author_source_id = value_text(&author, "source_id");
        let source = indexed_record_or_get(&source_cache, "sources", &author_source_id)?;
        let raw = indexed_record_or_get(
            &raw_cache,
            "raw-records",
            &value_text(&author, "raw_record_id"),
        )?;
        let extra = if let Some(normalizer) = explicit_normalizer.as_ref() {
            persist_author_metadata_with_normalizer(job, &source, &raw, &author, normalizer)?
        } else {
            persist_author_metadata(job, &source, &raw, &author)?
        };
        merge_ingestion_counts(&mut counts, extra);
        counts.authors += 1;
        if counts.authors % 500 == 0 {
            let _ = update_ingestion_job_counts(
                &value_text(job, "id"),
                "running",
                &counts,
                json!({
                    "active_source_id": author_source_id,
                    "authors_reprocessed": counts.authors
                }),
            );
        }
    }
    Ok(counts)
}

fn explicit_job_normalizer(job: &Value) -> Result<Option<Value>, ApiError> {
    let normalizer_id = value_text(job, "normalizer_id");
    if normalizer_id.is_empty() {
        return Ok(None);
    }
    let normalizer = get_record("normalizers", &normalizer_id)?;
    if normalizer.get("enabled").and_then(Value::as_bool) == Some(false) {
        return Ok(None);
    }
    Ok(Some(normalizer))
}

fn records_by_id(
    collection: &str,
    ids: &BTreeSet<String>,
) -> Result<BTreeMap<String, Value>, ApiError> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut indexed = BTreeMap::new();
    for record in read_collection(collection)? {
        let id = value_text(&record, "id");
        if ids.contains(&id) {
            indexed.insert(id, record);
        }
    }
    Ok(indexed)
}

fn indexed_record_or_get(
    index: &BTreeMap<String, Value>,
    collection: &str,
    id: &str,
) -> Result<Value, ApiError> {
    if id.is_empty() {
        return Ok(Value::Null);
    }
    if let Some(record) = index.get(id) {
        return Ok(record.clone());
    }
    get_record(collection, id)
}

fn reprocess_raw_metadata_job(job: &Value) -> Result<IngestionCounts, ApiError> {
    let mut raws = read_collection("raw-records")?;
    let raw_record_id = value_text(job, "raw_record_id");
    let source_id = value_text(job, "source_id");
    let repository_id = value_text(job, "repository_id");
    let raw_record_type = first_non_empty(&[
        job_param_text(job, "raw_record_type"),
        job_param_text(job, "record_type"),
    ]);
    if !raw_record_id.is_empty() {
        raws.retain(|raw| value_text(raw, "id") == raw_record_id);
    }
    if !source_id.is_empty() {
        raws.retain(|raw| value_text(raw, "source_id") == source_id);
    }
    if !repository_id.is_empty() {
        raws.retain(|raw| value_text(raw, "repository_id") == repository_id);
    }
    if !raw_record_type.is_empty() {
        raws.retain(|raw| value_text(raw, "record_type") == raw_record_type);
    }
    raws.sort_by(|left, right| value_text(left, "id").cmp(&value_text(right, "id")));

    let arts_by_raw = normalizer_art_index()?;
    let mut source_cache = BTreeMap::<String, Value>::new();
    let mut counts = IngestionCounts::default();
    for raw in raws {
        if let Some(status) = ingestion_stop_status(&value_text(job, "id")) {
            log_ingestion(
                job,
                "raw-metadata",
                "info",
                &format!("stopping raw metadata reprocess because job is {status}"),
                json!({ "status": status }),
            )?;
            return Ok(counts);
        }
        let raw_source_id = value_text(&raw, "source_id");
        let source = if let Some(source) = source_cache.get(&raw_source_id) {
            source.clone()
        } else {
            let source = get_record("sources", &raw_source_id)?;
            source_cache.insert(raw_source_id.clone(), source.clone());
            source
        };
        merge_ingestion_counts(
            &mut counts,
            persist_raw_metadata_with_art_index(job, &source, &raw, Some(&arts_by_raw))?,
        );
        counts.raw_records += 1;
        if counts.raw_records % 1000 == 0 {
            let _ = update_ingestion_job_counts(
                &value_text(job, "id"),
                "running",
                &counts,
                json!({
                    "active_source_id": raw_source_id,
                    "raw_records_reprocessed": counts.raw_records
                }),
            );
        }
    }
    Ok(counts)
}

fn ingest_git_source(job: &Value, source: &Value) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let repo_path = git_repo_path(source)?;
    if should_fetch_git_source(job) {
        fetch_git_source(job, source, &repo_path)?;
    }
    let limit = git_commit_limit(source);
    log_ingestion(
        job,
        "fetch",
        "info",
        "reading git commit messages",
        json!({
            "source_id": value_text(source, "id"),
            "local_path": repo_path,
            "commit_limit": limit
        }),
    )?;
    let output = Command::new("git")
        .arg("-C")
        .arg(&repo_path)
        .arg("log")
        .arg(format!("-n{limit}"))
        .arg("--date=iso-strict")
        .arg("--pretty=format:%x1e%H%x00%aI%x00%an%x00%ae%x00%B%x00")
        .arg("--no-renames")
        .arg("--numstat")
        .output()
        .map_err(|err| {
            ApiError::provider(format!("running git log in {repo_path} failed: {err}"))
        })?;
    if !output.status.success() {
        return Err(ApiError::provider(format!(
            "git log in {repo_path} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut git_commits_seen = 0_i64;
    let mut skipped_unchanged_git_commits = 0_i64;
    for record in stdout.split('\x1e') {
        if ingestion_stop_status(&value_text(job, "id")).is_some() {
            break;
        }
        let record = record.trim_matches('\n').trim_matches('\0');
        if record.is_empty() {
            continue;
        }
        let fields = record.split('\0').collect::<Vec<_>>();
        if fields.len() < 5 {
            continue;
        }
        let sha = fields[0].trim();
        let authored_at = fields[1].trim();
        let author_name = fields[2].trim();
        let author_email = fields[3].trim();
        let body = fields[4].trim();
        let file_metadata = git_commit_file_metadata(fields.get(5).copied().unwrap_or(""));
        let changed_file_count = file_metadata.files.len();
        if sha.is_empty() {
            continue;
        }
        git_commits_seen += 1;
        let url = git_commit_url(source, sha);
        let raw_external_id = format!("git-commit-{sha}");
        let raw_payload = json!({
            "sha": sha,
            "authored_at": authored_at,
            "author_name": author_name,
            "author_email": author_email,
            "message": body,
            "files": file_metadata.files,
            "changed_files": file_metadata.changed_files,
            "changed_file_count": changed_file_count,
            "insertions": file_metadata.insertions,
            "deletions": file_metadata.deletions,
            "binary_file_count": file_metadata.binary_files,
            "local_path": repo_path
        });
        let art_external_id = format!("git-commit-{sha}-message");
        if git_commit_already_ingested(
            job,
            source,
            &raw_external_id,
            &raw_payload,
            body,
            &art_external_id,
        )? {
            skipped_unchanged_git_commits += 1;
            if git_commits_seen % 500 == 0 {
                let _ = update_ingestion_job_counts(
                    &value_text(job, "id"),
                    "running",
                    &counts,
                    json!({
                        "active_source_id": value_text(source, "id"),
                        "stats": {
                            "git_commits_seen": git_commits_seen,
                            "skipped_unchanged_git_commits": skipped_unchanged_git_commits
                        }
                    }),
                );
            }
            continue;
        }
        let raw = persist_raw_record(
            job,
            source,
            &raw_external_id,
            "git_commit",
            &url,
            raw_payload,
            authored_at.to_string(),
        )?;
        counts.raw_records += 1;
        if is_git_raw_refresh_job(job) {
            if counts.raw_records % 500 == 0 {
                let _ = update_ingestion_job_counts(
                    &value_text(job, "id"),
                    "running",
                    &counts,
                    json!({ "active_source_id": value_text(source, "id") }),
                );
            }
            continue;
        }
        let external_author = if author_email.is_empty() {
            author_name
        } else {
            author_email
        };
        let author = persist_author(
            job,
            source,
            &raw,
            "git",
            external_author,
            if author_email.is_empty() {
                author_name
            } else {
                author_email
            },
            author_name,
            author_email,
            "",
        )?;
        counts.authors += 1;
        merge_ingestion_counts(
            &mut counts,
            persist_author_metadata(job, source, &raw, &author)?,
        );
        let mut raw_arts = Vec::new();
        if !body.is_empty() {
            let extracted = persist_art(
                job,
                source,
                &raw,
                &author,
                "commit_message",
                &art_external_id,
                &url,
                body,
                authored_at.to_string(),
                json!({
                    "context_type": "git_commit",
                    "context_external_id": sha,
                    "context_external_key": sha,
                    "commit_sha": sha,
                    "local_path": repo_path
                }),
            )?;
            counts.arts += 1;
            merge_ingestion_counts(&mut counts, extracted);
            if let Ok(art) = get_record(
                "arts",
                &art_id_for(source, &art_external_id, "commit_message"),
            ) {
                raw_arts.push(art);
            }
        }
        let mut art_index = NormalizerArtIndex::default();
        for art in raw_arts {
            art_index.add(art);
        }
        merge_ingestion_counts(
            &mut counts,
            persist_raw_metadata_with_art_index(job, source, &raw, Some(&art_index))?,
        );
        if counts.raw_records % 100 == 0 {
            let _ = update_ingestion_job_counts(
                &value_text(job, "id"),
                "running",
                &counts,
                json!({
                    "active_source_id": value_text(source, "id"),
                    "stats": {
                        "git_commits_seen": git_commits_seen,
                        "skipped_unchanged_git_commits": skipped_unchanged_git_commits
                    }
                }),
            );
        }
    }
    let _ = update_ingestion_job_counts(
        &value_text(job, "id"),
        "running",
        &counts,
        json!({
            "active_source_id": value_text(source, "id"),
            "stats": {
                "git_commits_seen": git_commits_seen,
                "skipped_unchanged_git_commits": skipped_unchanged_git_commits
            }
        }),
    );
    if should_run_git_line_survival_normalizer(job, source) {
        match persist_git_line_survival_metadata(job, source, &repo_path) {
            Ok(extra) => {
                merge_ingestion_counts(&mut counts, extra);
                let _ = update_ingestion_job_counts(
                    &value_text(job, "id"),
                    "running",
                    &counts,
                    json!({
                        "active_source_id": value_text(source, "id"),
                        "stats": { "git_line_survival": "completed" }
                    }),
                );
            }
            Err(err) => {
                log_ingestion(
                    job,
                    "line-survival",
                    "warn",
                    "git line survival normalizer failed",
                    json!({ "error": err.message }),
                )?;
            }
        }
    }
    if should_run_gerrit_approval_line_survival_normalizer(job, source) {
        match persist_gerrit_approval_line_survival_metadata(job, source, &repo_path) {
            Ok(extra) => {
                merge_ingestion_counts(&mut counts, extra);
                let _ = update_ingestion_job_counts(
                    &value_text(job, "id"),
                    "running",
                    &counts,
                    json!({
                        "active_source_id": value_text(source, "id"),
                        "stats": { "gerrit_approval_line_survival": "completed" }
                    }),
                );
            }
            Err(err) => {
                log_ingestion(
                    job,
                    "approval-line-survival",
                    "warn",
                    "gerrit approval line survival normalizer failed",
                    json!({ "error": err.message }),
                )?;
            }
        }
    }
    log_ingestion(
        job,
        "source",
        "info",
        "git commit messages ingested",
        json!({
            "raw_records_count": counts.raw_records,
            "arts_count": counts.arts,
            "authors_count": counts.authors,
            "git_commits_seen": git_commits_seen,
            "skipped_unchanged_git_commits": skipped_unchanged_git_commits,
            "local_path": repo_path
        }),
    )?;
    Ok(counts)
}

fn should_fetch_git_source(job: &Value) -> bool {
    job_param_bool(job, "git_fetch", false) || job_param_bool(job, "sync_current", false)
}

fn fetch_git_source(job: &Value, source: &Value, repo_path: &str) -> Result<(), ApiError> {
    log_ingestion(
        job,
        "fetch",
        "info",
        "fetching git repository before ingest",
        json!({
            "source_id": value_text(source, "id"),
            "local_path": repo_path
        }),
    )?;
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("fetch")
        .arg("--all")
        .arg("--prune")
        .output()
        .map_err(|err| ApiError::provider(format!("git fetch in {repo_path} failed: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(ApiError::provider(format!(
            "git fetch in {repo_path} failed: {}",
            compact_log_text(&stderr, 500)
        )));
    }
    log_ingestion(job, "fetch", "info", "git repository fetched", {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        json!({
            "source_id": value_text(source, "id"),
            "stdout": compact_log_text(&stdout, 1000),
            "stderr": compact_log_text(&stderr, 1000)
        })
    })?;
    Ok(())
}

fn is_git_raw_refresh_job(job: &Value) -> bool {
    matches!(
        value_text(job, "mode").as_str(),
        "git-raw-refresh" | "raw-refresh" | "raw-record-refresh" | "raw-records-only"
    )
}

fn should_run_git_line_survival_normalizer(job: &Value, source: &Value) -> bool {
    if job_param_bool(job, "disable_line_survival", false)
        || job_param_bool(job, "skip_line_survival", false)
    {
        return false;
    }
    job_param_bool(
        job,
        "run_git_line_survival",
        source_policy_bool(source, "line_survival_enabled", true),
    )
}

fn persist_git_line_survival_metadata(
    job: &Value,
    source: &Value,
    repo_path: &str,
) -> Result<IngestionCounts, ApiError> {
    let branch = select_git_line_survival_branch(source, repo_path)?;
    let head_sha = git_ref_head_sha(repo_path, &branch)?;
    let limit = git_line_survival_commit_limit(source);
    let max_changed_lines = git_line_survival_max_changed_lines(job, source);
    let since_epoch = git_line_survival_since_epoch(job, source);
    let config_key = git_line_survival_config_key(&branch, limit, max_changed_lines, since_epoch);
    let previous_head = source_policy_text(source, "line_survival_head_sha");
    let previous_config_key = source_policy_text(source, "line_survival_config_key");
    if previous_head == head_sha
        && previous_config_key == config_key
        && !job_param_bool(job, "force_line_survival", false)
        && !job_param_bool(job, "force_normalize", false)
        && !job_param_bool(job, "force_ingest", false)
    {
        log_ingestion(
            job,
            "line-survival",
            "info",
            "git line survival skipped because branch head is unchanged",
            json!({
                "source_id": value_text(source, "id"),
                "branch": branch,
                "head_sha": head_sha,
                "config_key": config_key
            }),
        )?;
        return Ok(IngestionCounts::default());
    }

    log_ingestion(
        job,
        "line-survival",
        "info",
        "running git line survival normalizer",
        json!({
            "source_id": value_text(source, "id"),
            "local_path": repo_path,
            "branch": branch,
            "head_sha": head_sha,
            "commit_limit": limit,
            "max_changed_lines": max_changed_lines,
            "since_epoch": since_epoch
        }),
    )?;

    let analysis =
        analyze_git_line_survival(repo_path, &branch, limit, max_changed_lines, since_epoch)?;
    let raw_by_sha = git_raw_records_by_sha(source)?;
    let mut counts = IngestionCounts::default();
    let empty_rule = json!({});

    for stats in analysis.commits.values() {
        let Some(raw) = raw_by_sha.get(&stats.sha) else {
            continue;
        };
        merge_ingestion_counts(
            &mut counts,
            persist_raw_metadata_fact(
                job,
                source,
                raw,
                &empty_rule,
                "git.line_survival",
                "commit",
                git_line_survival_commit_value(stats, &analysis),
                "object",
                "describes",
                None,
            )?,
        );
    }

    for stats in analysis.authors.values() {
        let Some(author_id) = find_author_id_for_external_ref(source, "git", &stats.author_key)?
        else {
            continue;
        };
        let author = get_record("authors", &author_id)?;
        let raw = stats
            .commits
            .iter()
            .find_map(|sha| raw_by_sha.get(sha))
            .cloned()
            .unwrap_or(Value::Null);
        merge_ingestion_counts(
            &mut counts,
            persist_author_metadata_fact(
                job,
                source,
                &raw,
                &author,
                "git.line_survival",
                "summary",
                git_line_survival_author_value(stats, &analysis),
                "object",
            )?,
        );
    }

    update_source_ingestion_policy(
        source,
        vec![
            ("line_survival_branch", json!(analysis.branch)),
            ("line_survival_head_sha", json!(analysis.head_sha)),
            ("line_survival_config_key", json!(config_key)),
            ("line_survival_analyzed_at", json!(now_timestamp())),
            (
                "line_survival_since_epoch",
                analysis.since_epoch.map(Value::from).unwrap_or(Value::Null),
            ),
            (
                "line_survival_commits_replayed",
                json!(analysis.commits_replayed),
            ),
            (
                "line_survival_commits_before_since",
                json!(analysis.commits_before_since),
            ),
            (
                "line_survival_commits_analyzed",
                json!(analysis.commits_analyzed),
            ),
            (
                "line_survival_commits_skipped_by_size",
                json!(analysis.commits_skipped_by_size),
            ),
            (
                "line_survival_max_changed_lines",
                json!(analysis.max_changed_lines),
            ),
        ],
    )?;

    log_ingestion(
        job,
        "line-survival",
        "info",
        "git line survival normalizer completed",
        json!({
            "source_id": value_text(source, "id"),
            "branch": analysis.branch,
            "head_sha": analysis.head_sha,
            "commit_count": analysis.commit_count,
            "since_epoch": analysis.since_epoch,
            "commits_replayed": analysis.commits_replayed,
            "commits_seen": analysis.commits_seen,
            "commits_before_since": analysis.commits_before_since,
            "commits_analyzed": analysis.commits_analyzed,
            "commits_skipped_by_size": analysis.commits_skipped_by_size,
            "max_changed_lines": analysis.max_changed_lines,
            "files_tracked": analysis.files_tracked,
            "metadata_count": counts.metadata,
            "relationships_count": counts.relationships
        }),
    )?;
    Ok(counts)
}

fn should_run_gerrit_approval_line_survival_normalizer(job: &Value, source: &Value) -> bool {
    if job_param_bool(job, "disable_approval_line_survival", false)
        || job_param_bool(job, "skip_approval_line_survival", false)
    {
        return false;
    }
    job_param_bool(
        job,
        "run_approval_line_survival",
        source_policy_bool(source, "approval_line_survival_enabled", true),
    )
}

fn should_run_repository_approval_line_survival_after_sources(job: &Value) -> bool {
    if !value_text(job, "source_id").is_empty() || value_text(job, "repository_id").is_empty() {
        return false;
    }
    if job_param_bool(job, "disable_approval_line_survival", false)
        || job_param_bool(job, "skip_approval_line_survival", false)
    {
        return false;
    }
    job_param_bool(job, "run_repository_approval_line_survival", true)
}

fn run_repository_approval_line_survival_after_sources(
    job: &Value,
    sources: &[Value],
) -> Result<IngestionCounts, ApiError> {
    let git_sources = sources
        .iter()
        .filter(|source| value_text(source, "provider") == "git")
        .filter(|source| {
            source.get("enabled").and_then(Value::as_bool) != Some(false)
                && source_policy_bool(source, "approval_line_survival_enabled", true)
        })
        .cloned()
        .collect::<Vec<_>>();
    if git_sources.is_empty() {
        log_ingestion(
            job,
            "approval-line-survival",
            "info",
            "repository approval line survival skipped because no enabled git source was found",
            json!({ "repository_id": value_text(job, "repository_id") }),
        )?;
        return Ok(IngestionCounts::default());
    }

    log_ingestion(
        job,
        "approval-line-survival",
        "info",
        "running repository post-source approval line survival pass",
        json!({
            "repository_id": value_text(job, "repository_id"),
            "git_source_ids": git_sources.iter().map(|source| value_text(source, "id")).collect::<Vec<_>>()
        }),
    )?;

    let mut counts = IngestionCounts::default();
    for git_source in git_sources {
        if let Some(status) = ingestion_stop_status(&value_text(job, "id")) {
            log_ingestion(
                job,
                "approval-line-survival",
                "info",
                &format!("stopping repository approval line survival because job is {status}"),
                json!({ "status": status }),
            )?;
            return Ok(counts);
        }
        let repo_path = match git_repo_path(&git_source) {
            Ok(path) => path,
            Err(err) => {
                log_ingestion(
                    job,
                    "approval-line-survival",
                    "warn",
                    "repository approval line survival skipped git source without usable local_path",
                    json!({
                        "source_id": value_text(&git_source, "id"),
                        "error": err.message
                    }),
                )?;
                continue;
            }
        };
        match persist_gerrit_approval_line_survival_metadata(job, &git_source, &repo_path) {
            Ok(extra) => merge_ingestion_counts(&mut counts, extra),
            Err(err) => {
                log_ingestion(
                    job,
                    "approval-line-survival",
                    "warn",
                    "repository approval line survival normalizer failed",
                    json!({
                        "source_id": value_text(&git_source, "id"),
                        "error": err.message
                    }),
                )?;
            }
        }
    }
    Ok(counts)
}

fn persist_gerrit_approval_line_survival_metadata(
    job: &Value,
    source: &Value,
    repo_path: &str,
) -> Result<IngestionCounts, ApiError> {
    let branch = select_git_line_survival_branch(source, repo_path)?;
    let head_sha = git_ref_head_sha(repo_path, &branch)?;
    let limit = git_line_survival_commit_limit(source);
    let max_review_changed_lines = approval_line_survival_max_changed_lines(job, source);
    let since_epoch = approval_line_survival_since_epoch(job, source);
    let approval_fingerprint =
        gerrit_approval_line_survival_fingerprint(&value_text(source, "repository_id"))?;
    let config_key = approval_line_survival_config_key(
        &branch,
        limit,
        max_review_changed_lines,
        since_epoch,
        &approval_fingerprint,
    );
    let previous_head = source_policy_text(source, "approval_line_survival_head_sha");
    let previous_config_key = source_policy_text(source, "approval_line_survival_config_key");
    if previous_head == head_sha
        && previous_config_key == config_key
        && !job_param_bool(job, "force_approval_line_survival", false)
        && !job_param_bool(job, "force_line_survival", false)
        && !job_param_bool(job, "force_normalize", false)
        && !job_param_bool(job, "force_ingest", false)
    {
        log_ingestion(
            job,
            "approval-line-survival",
            "info",
            "gerrit approval line survival skipped because inputs are unchanged",
            json!({
                "source_id": value_text(source, "id"),
                "branch": branch,
                "head_sha": head_sha,
                "config_key": config_key
            }),
        )?;
        return Ok(IngestionCounts::default());
    }

    log_ingestion(
        job,
        "approval-line-survival",
        "info",
        "running gerrit approval line survival normalizer",
        json!({
            "source_id": value_text(source, "id"),
            "local_path": repo_path,
            "branch": branch,
            "head_sha": head_sha,
            "commit_limit": limit,
            "max_review_changed_lines": max_review_changed_lines,
            "since_epoch": since_epoch
        }),
    )?;

    let analysis = analyze_git_line_survival(
        repo_path,
        &branch,
        limit,
        max_review_changed_lines,
        since_epoch,
    )?;
    let approvals =
        collect_gerrit_approval_line_survival_approvals(source, max_review_changed_lines)?;
    let mut counts = IngestionCounts::default();
    let mut reviewer_stats = BTreeMap::<String, GerritApprovalLineSurvivalReviewerStats>::new();
    let mut approvals_with_commit_stats = 0_i64;
    let mut approvals_missing_commit_stats = 0_i64;

    prune_gerrit_approval_line_survival_metadata(&value_text(source, "repository_id"))?;

    for approval in approvals {
        let Some(commit_stats) = analysis.commits.get(&approval.commit_sha) else {
            approvals_missing_commit_stats += 1;
            continue;
        };
        approvals_with_commit_stats += 1;
        let change_value =
            gerrit_approval_line_survival_change_value(&approval, commit_stats, &analysis);
        merge_ingestion_counts(
            &mut counts,
            persist_approval_line_survival_change_fact(job, &approval, change_value)?,
        );

        let entry = reviewer_stats
            .entry(approval.reviewer_author_id.clone())
            .or_insert_with(|| GerritApprovalLineSurvivalReviewerStats {
                reviewer_author_id: approval.reviewer_author_id.clone(),
                reviewer_key: approval.reviewer_key.clone(),
                first_raw: approval.raw.clone(),
                first_source: approval.source.clone(),
                ..GerritApprovalLineSurvivalReviewerStats::default()
            });
        entry
            .gerrit_account_ids
            .insert(approval.gerrit_account_id.clone());
        entry
            .reviewed_changes
            .insert(approval.change_number.clone());
        if entry.commit_shas.insert(approval.commit_sha.clone()) {
            entry.insertions += commit_stats.insertions;
            entry.deletions += commit_stats.deletions;
            entry.surviving_lines += commit_stats.surviving_lines;
            entry.self_reworked_lines += commit_stats.self_reworked_lines;
            entry.cross_author_overwritten_lines += commit_stats.cross_author_overwritten_lines;
        }
        entry.approvals_count += approval.labels.len() as i64;
        for label in &approval.labels {
            *entry.labels.entry(label.clone()).or_insert(0) += 1;
        }
    }

    for stats in reviewer_stats.values() {
        let author = get_record("authors", &stats.reviewer_author_id)?;
        merge_ingestion_counts(
            &mut counts,
            persist_author_metadata_fact(
                job,
                &stats.first_source,
                &stats.first_raw,
                &author,
                "review.approval_line_survival",
                "summary",
                gerrit_approval_line_survival_author_value(
                    stats,
                    &analysis,
                    max_review_changed_lines,
                ),
                "object",
            )?,
        );
    }

    update_source_ingestion_policy(
        source,
        vec![
            ("approval_line_survival_branch", json!(analysis.branch)),
            ("approval_line_survival_head_sha", json!(analysis.head_sha)),
            ("approval_line_survival_config_key", json!(config_key)),
            (
                "approval_line_survival_fingerprint",
                json!(approval_fingerprint),
            ),
            ("approval_line_survival_analyzed_at", json!(now_timestamp())),
            (
                "approval_line_survival_since_epoch",
                analysis.since_epoch.map(Value::from).unwrap_or(Value::Null),
            ),
            (
                "approval_line_survival_commits_replayed",
                json!(analysis.commits_replayed),
            ),
            (
                "approval_line_survival_commits_before_since",
                json!(analysis.commits_before_since),
            ),
            (
                "approval_line_survival_commits_analyzed",
                json!(analysis.commits_analyzed),
            ),
            (
                "approval_line_survival_commits_skipped_by_size",
                json!(analysis.commits_skipped_by_size),
            ),
            (
                "approval_line_survival_max_review_changed_lines",
                json!(max_review_changed_lines),
            ),
            (
                "approval_line_survival_approvals_with_commit_stats",
                json!(approvals_with_commit_stats),
            ),
            (
                "approval_line_survival_approvals_missing_commit_stats",
                json!(approvals_missing_commit_stats),
            ),
            (
                "approval_line_survival_reviewers_analyzed",
                json!(reviewer_stats.len()),
            ),
        ],
    )?;

    log_ingestion(
        job,
        "approval-line-survival",
        "info",
        "gerrit approval line survival normalizer completed",
        json!({
            "source_id": value_text(source, "id"),
            "branch": analysis.branch,
            "head_sha": analysis.head_sha,
            "max_review_changed_lines": max_review_changed_lines,
            "approvals_with_commit_stats": approvals_with_commit_stats,
            "approvals_missing_commit_stats": approvals_missing_commit_stats,
            "reviewers_analyzed": reviewer_stats.len(),
            "metadata_count": counts.metadata,
            "relationships_count": counts.relationships
        }),
    )?;
    Ok(counts)
}

fn prune_gerrit_approval_line_survival_metadata(repository_id: &str) -> Result<(), ApiError> {
    if repository_id.trim().is_empty() {
        return Ok(());
    }
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        with_postgres_client(|client| {
            client
                .execute(
                    r#"
                    DELETE FROM repointel_records
                    WHERE collection = 'relationships'
                      AND doc->>'repository_id' = $1
                      AND doc->>'origin' = 'normalizer.approval_line_survival.v1'
                    "#,
                    &[&repository_id],
                )
                .map_err(|err| {
                    ApiError::internal(format!(
                        "failed pruning approval line survival relationships: {err}"
                    ))
                })?;
            client
                .execute(
                    r#"
                    DELETE FROM repointel_records
                    WHERE collection = 'metadata'
                      AND doc->>'repository_id' = $1
                      AND doc->>'namespace' = 'review.approval_line_survival'
                    "#,
                    &[&repository_id],
                )
                .map_err(|err| {
                    ApiError::internal(format!(
                        "failed pruning approval line survival metadata: {err}"
                    ))
                })?;
            Ok(())
        })?;
        return Ok(());
    }

    let _guard = store_write_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut relationships = read_collection("relationships")?;
    relationships.retain(|relationship| {
        value_text(relationship, "repository_id") != repository_id
            || value_text(relationship, "origin") != "normalizer.approval_line_survival.v1"
    });
    write_collection("relationships", &relationships)?;

    let mut metadata = read_collection("metadata")?;
    metadata.retain(|item| {
        value_text(item, "repository_id") != repository_id
            || value_text(item, "namespace") != "review.approval_line_survival"
    });
    write_collection("metadata", &metadata)?;
    Ok(())
}

fn analyze_git_line_survival(
    repo_path: &str,
    branch: &str,
    limit: usize,
    max_changed_lines: i64,
    since_epoch: Option<i64>,
) -> Result<GitLineSurvivalAnalysis, ApiError> {
    let head_sha = git_ref_head_sha(repo_path, branch)?;
    let commit_count = git_ref_commit_count(repo_path, branch)?;
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo_path)
        .arg("log")
        .arg("--reverse")
        .arg(format!("-n{limit}"))
        .arg(branch)
        .arg("--no-merges")
        .arg("--date=iso-strict")
        .arg("--pretty=format:%x1e%H%x00%at%x00%aI%x00%an%x00%ae%x00")
        .arg("--no-renames")
        .arg("--unified=0")
        .arg("--patch");
    let output = command.output().map_err(|err| {
        ApiError::provider(format!(
            "running git line survival log in {repo_path} failed: {err}"
        ))
    })?;
    if !output.status.success() {
        return Err(ApiError::provider(format!(
            "git line survival log in {repo_path} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut analysis = GitLineSurvivalAnalysis {
        branch: branch.to_string(),
        head_sha,
        commit_count,
        since_epoch,
        max_changed_lines,
        ..GitLineSurvivalAnalysis::default()
    };
    let mut file_lines = BTreeMap::<String, Vec<GitLineOwner>>::new();

    for record in stdout.split('\x1e') {
        let record = record.trim_matches('\n').trim_matches('\0');
        if record.is_empty() {
            continue;
        }
        let fields = record.splitn(6, '\0').collect::<Vec<_>>();
        if fields.len() < 6 {
            continue;
        }
        let commit_epoch = fields[1].trim().parse::<i64>().unwrap_or(0);
        let in_window = since_epoch
            .map(|since| commit_epoch >= since)
            .unwrap_or(true);
        let changed_lines = git_patch_changed_lines(fields[5]);
        let track_stats =
            in_window && (max_changed_lines <= 0 || changed_lines <= max_changed_lines);
        let owner = GitLineOwner {
            commit_sha: fields[0].trim().to_string(),
            authored_at: fields[2].trim().to_string(),
            author_name: fields[3].trim().to_string(),
            author_email: fields[4].trim().to_string(),
            author_key: git_author_key(fields[3], fields[4]),
            track_stats,
        };
        if owner.commit_sha.is_empty() {
            continue;
        }
        analysis.commits_replayed += 1;
        if in_window {
            analysis.commits_seen += 1;
            if owner.track_stats {
                analysis.commits_analyzed += 1;
                ensure_line_survival_commit_stats(&mut analysis, &owner);
                ensure_line_survival_author_stats(&mut analysis, &owner)
                    .commits
                    .insert(owner.commit_sha.clone());
            } else {
                analysis.commits_skipped_by_size += 1;
            }
        } else {
            analysis.commits_before_since += 1;
        }
        apply_git_patch_to_line_state(fields[5], &owner, &mut file_lines, &mut analysis);
    }

    for lines in file_lines.values() {
        for owner in lines {
            if !owner.track_stats {
                continue;
            }
            ensure_line_survival_commit_stats(&mut analysis, owner).surviving_lines += 1;
            ensure_line_survival_author_stats(&mut analysis, owner).surviving_lines += 1;
        }
    }
    analysis.files_tracked = file_lines.len() as i64;
    Ok(analysis)
}

fn apply_git_patch_to_line_state(
    patch: &str,
    owner: &GitLineOwner,
    file_lines: &mut BTreeMap<String, Vec<GitLineOwner>>,
    analysis: &mut GitLineSurvivalAnalysis,
) {
    let mut old_path = String::new();
    let mut new_path = String::new();
    let mut current_path = String::new();
    let mut line_delta = 0_isize;
    let mut current_index = 0_usize;
    let mut in_hunk = false;

    for line in patch.lines() {
        if line.starts_with("diff --git ") {
            old_path.clear();
            new_path.clear();
            current_path.clear();
            line_delta = 0;
            current_index = 0;
            in_hunk = false;
            continue;
        }
        if let Some(path) = line.strip_prefix("--- ") {
            old_path = normalize_git_diff_path(path);
            continue;
        }
        if let Some(path) = line.strip_prefix("+++ ") {
            new_path = normalize_git_diff_path(path);
            current_path = if new_path == "/dev/null" {
                old_path.clone()
            } else {
                new_path.clone()
            };
            continue;
        }
        if line.starts_with("@@ ") {
            if let Some(old_start) = parse_git_hunk_old_start(line) {
                let base = if old_start == 0 { 0 } else { old_start - 1 };
                current_index = base.saturating_add_signed(line_delta);
                in_hunk = !current_path.is_empty() && current_path != "/dev/null";
            }
            continue;
        }
        if !in_hunk || line.starts_with("\\ ") {
            continue;
        }

        if line.starts_with('-') && !line.starts_with("--- ") {
            record_git_line_deletion(owner, &current_path, current_index, file_lines, analysis);
            line_delta -= 1;
        } else if line.starts_with('+') && !line.starts_with("+++ ") {
            record_git_line_addition(owner, &current_path, current_index, file_lines, analysis);
            current_index += 1;
            line_delta += 1;
        } else if line.starts_with(' ') {
            current_index += 1;
        }
    }
}

fn git_patch_changed_lines(patch: &str) -> i64 {
    let mut changed = 0_i64;
    let mut in_hunk = false;
    for line in patch.lines() {
        if line.starts_with("diff --git ") {
            in_hunk = false;
            continue;
        }
        if line.starts_with("@@ ") {
            in_hunk = true;
            continue;
        }
        if !in_hunk || line.starts_with("\\ ") {
            continue;
        }
        if (line.starts_with('-') && !line.starts_with("--- "))
            || (line.starts_with('+') && !line.starts_with("+++ "))
        {
            changed += 1;
        }
    }
    changed
}

fn record_git_line_addition(
    owner: &GitLineOwner,
    path: &str,
    index: usize,
    file_lines: &mut BTreeMap<String, Vec<GitLineOwner>>,
    analysis: &mut GitLineSurvivalAnalysis,
) {
    let lines = file_lines.entry(path.to_string()).or_default();
    let index = index.min(lines.len());
    lines.insert(index, owner.clone());
    if !owner.track_stats {
        return;
    }
    let commit_stats = ensure_line_survival_commit_stats(analysis, owner);
    commit_stats.insertions += 1;
    commit_stats.files.insert(path.to_string());
    let author_stats = ensure_line_survival_author_stats(analysis, owner);
    author_stats.insertions += 1;
}

fn record_git_line_deletion(
    owner: &GitLineOwner,
    path: &str,
    index: usize,
    file_lines: &mut BTreeMap<String, Vec<GitLineOwner>>,
    analysis: &mut GitLineSurvivalAnalysis,
) {
    if owner.track_stats {
        let commit_stats = ensure_line_survival_commit_stats(analysis, owner);
        commit_stats.deletions += 1;
        commit_stats.files.insert(path.to_string());
        ensure_line_survival_author_stats(analysis, owner).deletions += 1;
    }

    let Some(lines) = file_lines.get_mut(path) else {
        return;
    };
    if index >= lines.len() {
        return;
    }
    let previous = lines.remove(index);
    if !previous.track_stats {
        return;
    }
    if previous.author_key == owner.author_key && owner.track_stats {
        ensure_line_survival_commit_stats(analysis, &previous).self_reworked_lines += 1;
        ensure_line_survival_author_stats(analysis, &previous).self_reworked_lines += 1;
    } else if owner.track_stats {
        let previous_commit = ensure_line_survival_commit_stats(analysis, &previous);
        previous_commit.cross_author_overwritten_lines += 1;
        *previous_commit
            .overwritten_by
            .entry(owner.author_key.clone())
            .or_insert(0) += 1;
        ensure_line_survival_author_stats(analysis, &previous).cross_author_overwritten_lines += 1;
        ensure_line_survival_author_stats(analysis, owner).overwrote_other_author_lines += 1;
    }
}

fn ensure_line_survival_commit_stats<'a>(
    analysis: &'a mut GitLineSurvivalAnalysis,
    owner: &GitLineOwner,
) -> &'a mut GitLineSurvivalCommitStats {
    analysis
        .commits
        .entry(owner.commit_sha.clone())
        .or_insert_with(|| GitLineSurvivalCommitStats {
            sha: owner.commit_sha.clone(),
            authored_at: owner.authored_at.clone(),
            author_key: owner.author_key.clone(),
            author_name: owner.author_name.clone(),
            author_email: owner.author_email.clone(),
            ..GitLineSurvivalCommitStats::default()
        })
}

fn ensure_line_survival_author_stats<'a>(
    analysis: &'a mut GitLineSurvivalAnalysis,
    owner: &GitLineOwner,
) -> &'a mut GitLineSurvivalAuthorStats {
    analysis
        .authors
        .entry(owner.author_key.clone())
        .or_insert_with(|| GitLineSurvivalAuthorStats {
            author_key: owner.author_key.clone(),
            author_name: owner.author_name.clone(),
            author_email: owner.author_email.clone(),
            ..GitLineSurvivalAuthorStats::default()
        })
}

fn git_line_survival_commit_value(
    stats: &GitLineSurvivalCommitStats,
    analysis: &GitLineSurvivalAnalysis,
) -> Value {
    json!({
        "branch": analysis.branch,
        "head_sha": analysis.head_sha,
        "since_epoch": analysis.since_epoch,
        "sha": stats.sha,
        "authored_at": stats.authored_at,
        "author_key": stats.author_key,
        "author_name": stats.author_name,
        "author_email": stats.author_email,
        "files": stats.files.iter().cloned().collect::<Vec<_>>(),
        "changed_file_count": stats.files.len(),
        "changed_lines_tracked": stats.insertions + stats.deletions,
        "insertions_tracked": stats.insertions,
        "deletions_tracked": stats.deletions,
        "surviving_lines": stats.surviving_lines,
        "self_reworked_lines": stats.self_reworked_lines,
        "cross_author_overwritten_lines": stats.cross_author_overwritten_lines,
        "max_changed_lines": analysis.max_changed_lines,
        "commits_replayed": analysis.commits_replayed,
        "commits_seen": analysis.commits_seen,
        "commits_before_since": analysis.commits_before_since,
        "commits_skipped_by_size": analysis.commits_skipped_by_size,
        "line_survival_rate": ratio_value(stats.surviving_lines, stats.insertions),
        "cross_author_overwrite_rate": ratio_value(stats.cross_author_overwritten_lines, stats.insertions),
        "self_rework_rate": ratio_value(stats.self_reworked_lines, stats.insertions),
        "overwritten_by": stats.overwritten_by.iter().map(|(author, lines)| {
            json!({ "author_key": author, "lines": lines })
        }).collect::<Vec<_>>()
    })
}

fn git_line_survival_author_value(
    stats: &GitLineSurvivalAuthorStats,
    analysis: &GitLineSurvivalAnalysis,
) -> Value {
    json!({
        "branch": analysis.branch,
        "head_sha": analysis.head_sha,
        "since_epoch": analysis.since_epoch,
        "author_key": stats.author_key,
        "author_name": stats.author_name,
        "author_email": stats.author_email,
        "commits_analyzed": stats.commits.len(),
        "max_changed_lines": analysis.max_changed_lines,
        "commits_replayed": analysis.commits_replayed,
        "commits_seen": analysis.commits_seen,
        "commits_before_since": analysis.commits_before_since,
        "commits_skipped_by_size": analysis.commits_skipped_by_size,
        "insertions_tracked": stats.insertions,
        "deletions_tracked": stats.deletions,
        "surviving_lines": stats.surviving_lines,
        "self_reworked_lines": stats.self_reworked_lines,
        "cross_author_overwritten_lines": stats.cross_author_overwritten_lines,
        "overwrote_other_author_lines": stats.overwrote_other_author_lines,
        "line_survival_rate": ratio_value(stats.surviving_lines, stats.insertions),
        "cross_author_overwrite_rate": ratio_value(stats.cross_author_overwritten_lines, stats.insertions),
        "self_rework_rate": ratio_value(stats.self_reworked_lines, stats.insertions),
        "overwrites_other_author_rate": ratio_value(stats.overwrote_other_author_lines, stats.deletions)
    })
}

fn collect_gerrit_approval_line_survival_approvals(
    git_source: &Value,
    max_review_changed_lines: i64,
) -> Result<Vec<GerritApprovalLineSurvivalApproval>, ApiError> {
    let repository_id = value_text(git_source, "repository_id");
    let mut sources_by_id = BTreeMap::<String, Value>::new();
    for source in read_collection("sources")? {
        sources_by_id.insert(value_text(&source, "id"), source);
    }

    let mut approvals_by_change_reviewer =
        BTreeMap::<String, GerritApprovalLineSurvivalApproval>::new();
    for raw in read_collection("raw-records")? {
        if value_text(&raw, "repository_id") != repository_id
            || value_text(&raw, "record_type") != "gerrit_change"
        {
            continue;
        }
        let payload = raw.get("payload").cloned().unwrap_or_else(|| json!({}));
        if value_text(&payload, "status") != "MERGED" {
            continue;
        }
        let current_revision = value_text(&payload, "current_revision");
        if current_revision.is_empty() {
            continue;
        }
        let insertions = value_i64(payload.get("insertions").unwrap_or(&Value::Null));
        let deletions = value_i64(payload.get("deletions").unwrap_or(&Value::Null));
        let changed_lines = insertions + deletions;
        if max_review_changed_lines > 0 && changed_lines > max_review_changed_lines {
            continue;
        }
        let raw_source = sources_by_id
            .get(&value_text(&raw, "source_id"))
            .cloned()
            .unwrap_or_else(|| git_source.clone());
        let change_number = value_text(&payload, "_number");
        let change_id = value_text(&payload, "change_id");
        let updated_at = value_text(&payload, "updated");

        for label in values_at_path(&payload, "submit_records.labels") {
            let label_name = value_text(&label, "label");
            if !is_review_approval_survival_label(&label_name) {
                continue;
            }
            let account_id = label
                .get("applied_by")
                .map(|applied_by| value_text(applied_by, "_account_id"))
                .unwrap_or_default();
            add_gerrit_approval_line_survival_approval(
                &mut approvals_by_change_reviewer,
                &raw_source,
                &raw,
                &account_id,
                &label_name,
                &change_number,
                &change_id,
                &current_revision,
                insertions,
                deletions,
                changed_lines,
                &updated_at,
            )?;
        }

        for message in payload
            .get("messages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let account_id = message
                .get("author")
                .map(|author| value_text(author, "_account_id"))
                .unwrap_or_default();
            let body = value_text(&message, "message");
            for vote in extract_gerrit_votes(&body) {
                let label_name = value_text(&vote, "label");
                if !is_review_approval_survival_label(&label_name)
                    || value_i64(vote.get("value").unwrap_or(&Value::Null)) <= 0
                {
                    continue;
                }
                add_gerrit_approval_line_survival_approval(
                    &mut approvals_by_change_reviewer,
                    &raw_source,
                    &raw,
                    &account_id,
                    &label_name,
                    &change_number,
                    &change_id,
                    &current_revision,
                    insertions,
                    deletions,
                    changed_lines,
                    &updated_at,
                )?;
            }
        }
    }
    Ok(approvals_by_change_reviewer.into_values().collect())
}

#[allow(clippy::too_many_arguments)]
fn add_gerrit_approval_line_survival_approval(
    approvals: &mut BTreeMap<String, GerritApprovalLineSurvivalApproval>,
    source: &Value,
    raw: &Value,
    account_id: &str,
    label: &str,
    change_number: &str,
    change_id: &str,
    commit_sha: &str,
    insertions: i64,
    deletions: i64,
    changed_lines: i64,
    updated_at: &str,
) -> Result<(), ApiError> {
    if account_id.trim().is_empty() {
        return Ok(());
    }
    let Some(author_id) = find_author_id_for_external_ref(source, "gerrit", account_id)? else {
        return Ok(());
    };
    let author = get_record("authors", &author_id)?;
    let reviewer_key = first_non_empty(&[
        value_text(&author, "email"),
        value_text(&author, "username"),
        value_text(&author, "display_name"),
        format!("gerrit:{account_id}"),
    ]);
    let key = format!("{change_number}|{commit_sha}|{author_id}");
    let entry = approvals
        .entry(key)
        .or_insert_with(|| GerritApprovalLineSurvivalApproval {
            raw: raw.clone(),
            source: source.clone(),
            reviewer_author_id: author_id,
            reviewer_key,
            gerrit_account_id: account_id.to_string(),
            change_number: change_number.to_string(),
            change_id: change_id.to_string(),
            commit_sha: commit_sha.to_string(),
            change_insertions: insertions,
            change_deletions: deletions,
            change_lines: changed_lines,
            updated_at: updated_at.to_string(),
            ..GerritApprovalLineSurvivalApproval::default()
        });
    entry.labels.insert(label.to_string());
    Ok(())
}

fn persist_approval_line_survival_change_fact(
    job: &Value,
    approval: &GerritApprovalLineSurvivalApproval,
    value: Value,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let metadata = persist_metadata_fact(
        job,
        &approval.source,
        &approval.raw,
        "raw_record",
        &value_text(&approval.raw, "id"),
        "review.approval_line_survival",
        "change",
        value,
        "object",
        first_non_empty(&[
            approval.updated_at.clone(),
            value_text(&approval.raw, "fetched_at"),
        ]),
    )?;
    counts.metadata += 1;
    persist_relationship(
        job,
        &approval.source,
        &approval.raw,
        "metadata",
        &value_text(&metadata, "id"),
        "about_author",
        "author",
        &approval.reviewer_author_id,
        "",
        &value_text(&metadata, "id"),
        "normalizer.approval_line_survival.v1",
    )?;
    counts.relationships += 1;
    Ok(counts)
}

fn gerrit_approval_line_survival_change_value(
    approval: &GerritApprovalLineSurvivalApproval,
    stats: &GitLineSurvivalCommitStats,
    analysis: &GitLineSurvivalAnalysis,
) -> Value {
    json!({
        "branch": analysis.branch,
        "head_sha": analysis.head_sha,
        "since_epoch": analysis.since_epoch,
        "reviewer_author_id": approval.reviewer_author_id,
        "reviewer_key": approval.reviewer_key,
        "gerrit_account_id": approval.gerrit_account_id,
        "change_number": approval.change_number,
        "change_id": approval.change_id,
        "commit_sha": approval.commit_sha,
        "labels": approval.labels.iter().cloned().collect::<Vec<_>>(),
        "review_changed_lines": approval.change_lines,
        "review_insertions": approval.change_insertions,
        "review_deletions": approval.change_deletions,
        "commit_insertions_tracked": stats.insertions,
        "commit_deletions_tracked": stats.deletions,
        "surviving_lines": stats.surviving_lines,
        "self_reworked_lines": stats.self_reworked_lines,
        "cross_author_overwritten_lines": stats.cross_author_overwritten_lines,
        "line_survival_rate": ratio_value(stats.surviving_lines, stats.insertions),
        "updated_at": approval.updated_at
    })
}

fn gerrit_approval_line_survival_author_value(
    stats: &GerritApprovalLineSurvivalReviewerStats,
    analysis: &GitLineSurvivalAnalysis,
    max_review_changed_lines: i64,
) -> Value {
    json!({
        "branch": analysis.branch,
        "head_sha": analysis.head_sha,
        "since_epoch": analysis.since_epoch,
        "reviewer_author_id": stats.reviewer_author_id,
        "reviewer_key": stats.reviewer_key,
        "gerrit_account_ids": stats.gerrit_account_ids.iter().cloned().collect::<Vec<_>>(),
        "max_review_changed_lines": max_review_changed_lines,
        "approvals_count": stats.approvals_count,
        "reviewed_changes_count": stats.reviewed_changes.len(),
        "approved_commits_count": stats.commit_shas.len(),
        "labels": stats.labels.iter().map(|(label, count)| {
            json!({ "label": label, "count": count })
        }).collect::<Vec<_>>(),
        "insertions_tracked": stats.insertions,
        "deletions_tracked": stats.deletions,
        "surviving_lines": stats.surviving_lines,
        "self_reworked_lines": stats.self_reworked_lines,
        "cross_author_overwritten_lines": stats.cross_author_overwritten_lines,
        "line_survival_rate": ratio_value(stats.surviving_lines, stats.insertions),
        "self_rework_rate": ratio_value(stats.self_reworked_lines, stats.insertions),
        "cross_author_overwrite_rate": ratio_value(stats.cross_author_overwritten_lines, stats.insertions)
    })
}

fn is_review_approval_survival_label(label: &str) -> bool {
    matches!(label, "Code-Review" | "Workflow")
}

fn ratio_value(numerator: i64, denominator: i64) -> Value {
    if denominator <= 0 {
        return json!(0.0);
    }
    let value = numerator as f64 / denominator as f64;
    json!((value * 10000.0).round() / 10000.0)
}

fn git_raw_records_by_sha(source: &Value) -> Result<BTreeMap<String, Value>, ApiError> {
    let source_id = value_text(source, "id");
    let mut records = BTreeMap::new();
    for raw in read_collection("raw-records")? {
        if value_text(&raw, "source_id") != source_id
            || value_text(&raw, "record_type") != "git_commit"
        {
            continue;
        }
        let sha = raw
            .get("payload")
            .and_then(|payload| payload.get("sha"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !sha.is_empty() {
            records.insert(sha, raw);
        }
    }
    Ok(records)
}

fn select_git_line_survival_branch(source: &Value, repo_path: &str) -> Result<String, ApiError> {
    let mut candidates = Vec::new();
    for candidate in [
        source_policy_text(source, "line_survival_branch"),
        source_policy_text(source, "branch"),
        source_policy_text(source, "default_branch"),
        repository_default_branch(source),
        git_current_branch(repo_path).unwrap_or_default(),
        "master".to_string(),
        "main".to_string(),
    ] {
        if !candidate.trim().is_empty() {
            candidates.push(candidate);
        }
    }
    for candidate in candidates {
        if git_ref_exists(repo_path, &candidate) {
            return Ok(candidate);
        }
    }
    most_active_git_branch(repo_path).ok_or_else(|| {
        ApiError::bad_request(format!(
            "could not determine a git branch to analyze for {repo_path}"
        ))
    })
}

fn repository_default_branch(source: &Value) -> String {
    let repository_id = value_text(source, "repository_id");
    if repository_id.is_empty() {
        return String::new();
    }
    get_record("repositories", &repository_id)
        .map(|repository| value_text(&repository, "default_branch"))
        .unwrap_or_default()
}

fn git_current_branch(repo_path: &str) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("symbolic-ref")
        .arg("--quiet")
        .arg("--short")
        .arg("HEAD")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!branch.is_empty()).then_some(branch)
}

fn most_active_git_branch(repo_path: &str) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("for-each-ref")
        .arg("--format=%(refname:short)")
        .arg("refs/heads")
        .arg("refs/remotes")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut best = None::<(String, i64)>;
    let mut seen = BTreeSet::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let branch = line.trim();
        if branch.is_empty() || branch.ends_with("/HEAD") || !seen.insert(branch.to_string()) {
            continue;
        }
        let count = git_ref_commit_count(repo_path, branch).unwrap_or(0);
        if count <= 0 {
            continue;
        }
        if best
            .as_ref()
            .map(|(_, best_count)| count > *best_count)
            .unwrap_or(true)
        {
            best = Some((branch.to_string(), count));
        }
    }
    best.map(|(branch, _)| branch)
}

fn git_ref_exists(repo_path: &str, reference: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("rev-parse")
        .arg("--verify")
        .arg("--quiet")
        .arg(format!("{reference}^{{commit}}"))
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn git_ref_head_sha(repo_path: &str, reference: &str) -> Result<String, ApiError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("rev-parse")
        .arg(format!("{reference}^{{commit}}"))
        .output()
        .map_err(|err| ApiError::provider(format!("git rev-parse {reference} failed: {err}")))?;
    if !output.status.success() {
        return Err(ApiError::provider(format!(
            "git rev-parse {reference} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_ref_commit_count(repo_path: &str, reference: &str) -> Result<i64, ApiError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("rev-list")
        .arg("--count")
        .arg(reference)
        .output()
        .map_err(|err| ApiError::provider(format!("git rev-list {reference} failed: {err}")))?;
    if !output.status.success() {
        return Err(ApiError::provider(format!(
            "git rev-list {reference} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i64>()
        .unwrap_or(0))
}

fn git_line_survival_commit_limit(source: &Value) -> usize {
    source
        .get("ingestion_policy")
        .and_then(|policy| policy.get("line_survival_commit_limit"))
        .and_then(Value::as_u64)
        .or_else(|| {
            env::var("REPOINTEL_GIT_LINE_SURVIVAL_LIMIT")
                .ok()?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(100_000)
        .clamp(1, 500_000) as usize
}

fn git_line_survival_max_changed_lines(job: &Value, source: &Value) -> i64 {
    let default = source_policy_i64(source, "line_survival_max_changed_lines", 100);
    job_param_i64(job, "line_survival_max_changed_lines", default).clamp(0, 1_000_000)
}

fn git_line_survival_since_epoch(job: &Value, source: &Value) -> Option<i64> {
    let explicit_since = job_param_i64(
        job,
        "line_survival_since_epoch",
        source_policy_i64(source, "line_survival_since_epoch", 0),
    );
    if explicit_since > 0 {
        return Some(explicit_since);
    }
    let window_days = job_param_i64(
        job,
        "line_survival_window_days",
        source_policy_i64(source, "line_survival_window_days", 0),
    );
    if window_days <= 0 {
        return None;
    }
    Some(now_unix_seconds().saturating_sub(window_days.saturating_mul(86_400)))
}

fn git_line_survival_config_key(
    branch: &str,
    limit: usize,
    max_changed_lines: i64,
    since_epoch: Option<i64>,
) -> String {
    format!(
        "branch={branch};limit={limit};max_changed_lines={max_changed_lines};since_epoch={}",
        since_epoch.unwrap_or(0)
    )
}

fn approval_line_survival_max_changed_lines(job: &Value, source: &Value) -> i64 {
    let default = source_policy_i64(source, "approval_line_survival_max_changed_lines", 200);
    job_param_i64(job, "approval_line_survival_max_changed_lines", default).clamp(0, 1_000_000)
}

fn approval_line_survival_since_epoch(job: &Value, source: &Value) -> Option<i64> {
    let explicit_since = job_param_i64(
        job,
        "approval_line_survival_since_epoch",
        source_policy_i64(source, "approval_line_survival_since_epoch", 0),
    );
    if explicit_since > 0 {
        return Some(explicit_since);
    }
    let window_days = job_param_i64(
        job,
        "approval_line_survival_window_days",
        source_policy_i64(
            source,
            "approval_line_survival_window_days",
            source_policy_i64(source, "line_survival_window_days", 0),
        ),
    );
    if window_days <= 0 {
        return None;
    }
    Some(now_unix_seconds().saturating_sub(window_days.saturating_mul(86_400)))
}

fn approval_line_survival_config_key(
    branch: &str,
    limit: usize,
    max_review_changed_lines: i64,
    since_epoch: Option<i64>,
    approval_fingerprint: &str,
) -> String {
    format!(
        "branch={branch};limit={limit};max_review_changed_lines={max_review_changed_lines};since_epoch={};approvals={approval_fingerprint}",
        since_epoch.unwrap_or(0)
    )
}

fn gerrit_approval_line_survival_fingerprint(repository_id: &str) -> Result<String, ApiError> {
    let mut parts = Vec::new();
    for raw in read_collection("raw-records")? {
        if value_text(&raw, "repository_id") != repository_id
            || value_text(&raw, "record_type") != "gerrit_change"
        {
            continue;
        }
        let payload = raw.get("payload").cloned().unwrap_or_else(|| json!({}));
        if value_text(&payload, "status") != "MERGED" {
            continue;
        }
        parts.push(format!(
            "{}|{}|{}|{}|{}|{}",
            value_text(&raw, "id"),
            value_text(&payload, "updated"),
            value_text(&payload, "current_revision"),
            value_text(&payload, "insertions"),
            value_text(&payload, "deletions"),
            stable_hash(&canonical_json(&json!({
                "submit_records": payload.get("submit_records").cloned().unwrap_or(Value::Null),
                "messages": payload.get("messages").cloned().unwrap_or(Value::Null)
            })))
        ));
    }
    parts.sort();
    Ok(stable_hash(&parts.join("\n")))
}

fn git_author_key(name: &str, email: &str) -> String {
    let email = email.trim();
    if !email.is_empty() {
        email.to_string()
    } else {
        name.trim().to_string()
    }
}

fn normalize_git_diff_path(path: &str) -> String {
    let path = path.trim().trim_matches('"');
    if path == "/dev/null" {
        return path.to_string();
    }
    path.trim_start_matches("a/")
        .trim_start_matches("b/")
        .to_string()
}

fn parse_git_hunk_old_start(line: &str) -> Option<usize> {
    let range = line.strip_prefix("@@ -")?.split_whitespace().next()?;
    let start = range.split(',').next().unwrap_or(range);
    start.parse::<usize>().ok()
}

fn ingest_launchpad_source(job: &Value, source: &Value) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let limit = launchpad_bug_limit(source);
    let use_watermark = use_source_watermarks(job);
    let previous_watermark = if use_watermark {
        source_policy_text(source, "launchpad_updated_watermark")
    } else {
        String::new()
    };
    let mut max_seen = if use_watermark {
        source_policy_text(source, "launchpad_pending_watermark")
    } else {
        String::new()
    };
    let mut offset = if use_watermark {
        source_policy_usize(source, "launchpad_cursor")
    } else {
        0
    };
    let watermark_replay_days = source_watermark_replay_days(job, source);
    let replay_watermark = if use_watermark && offset == 0 {
        replay_watermark_for(&previous_watermark, watermark_replay_days)
    } else {
        previous_watermark.clone()
    };
    let mut reached_watermark = false;
    let mut exhausted = false;
    let mut newest_updated_order = true;
    let base = value_text(source, "base_url");
    let target = if base.is_empty() {
        "https://api.launchpad.net/1.0/swift".to_string()
    } else {
        base
    };
    log_ingestion(
        job,
        "fetch",
        "info",
        "fetching launchpad bugs",
        json!({
            "url": launchpad_search_tasks_url(&target, offset, newest_updated_order),
            "source_id": value_text(source, "id"),
            "bug_limit": limit,
            "offset": offset,
            "updated_watermark": previous_watermark,
            "replay_watermark": replay_watermark,
            "watermark_replay_days": watermark_replay_days,
            "uses_watermark": use_watermark
        }),
    )?;
    while counts.raw_records < limit as i64 {
        if let Some(status) = ingestion_stop_status(&value_text(job, "id")) {
            log_ingestion(
                job,
                "source",
                "info",
                &format!("stopping launchpad source ingestion because job is {status}"),
                json!({ "status": status }),
            )?;
            return Ok(counts);
        }
        let url = launchpad_search_tasks_url(&target, offset, newest_updated_order);
        let page = match fetch_json(&url) {
            Ok(page) => page,
            Err(err) if newest_updated_order && offset == 0 => {
                newest_updated_order = false;
                log_ingestion(
                    job,
                    "fetch",
                    "warn",
                    "launchpad newest-updated ordering failed; falling back to created ordering",
                    json!({
                        "url": url,
                        "source_id": value_text(source, "id"),
                        "error": err.message
                    }),
                )?;
                fetch_json(&launchpad_search_tasks_url(
                    &target,
                    offset,
                    newest_updated_order,
                ))?
            }
            Err(err) => return Err(err),
        };
        let tasks = page
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if tasks.is_empty() {
            exhausted = true;
            break;
        }
        let task_count = tasks.len();
        let mut consumed = 0usize;
        for task in tasks {
            if let Some(status) = ingestion_stop_status(&value_text(job, "id")) {
                log_ingestion(
                    job,
                    "source",
                    "info",
                    &format!("stopping launchpad source ingestion because job is {status}"),
                    json!({
                        "status": status,
                        "bugs_processed": counts.raw_records
                    }),
                )?;
                return Ok(counts);
            }
            if counts.raw_records >= limit as i64 {
                break;
            }
            let bug_link = value_text(&task, "bug_link");
            let bug = if bug_link.is_empty() {
                task.clone()
            } else {
                fetch_json(&bug_link).unwrap_or_else(|_| task.clone())
            };
            let updated_at = launchpad_updated_at(&task, &bug);
            max_seen = max_timestamp(&max_seen, &updated_at);
            if use_watermark
                && newest_updated_order
                && !replay_watermark.is_empty()
                && !timestamp_after(&updated_at, &replay_watermark)
            {
                reached_watermark = true;
                break;
            }
            let raw = persist_raw_record(
                job,
                source,
                &format!("launchpad-bug-{}", value_text(&bug, "id")),
                "launchpad_bug",
                &value_text(&task, "web_link"),
                bug.clone(),
                value_text(&bug, "date_created"),
            )?;
            counts.raw_records += 1;
            let author =
                persist_launchpad_author(job, source, &raw, &value_text(&bug, "owner_link"))?;
            counts.authors += 1;
            merge_ingestion_counts(
                &mut counts,
                persist_author_metadata(job, source, &raw, &author)?,
            );
            let body = [value_text(&bug, "title"), value_text(&bug, "description")]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("\n\n");
            if !body.trim().is_empty() {
                let extracted = persist_art(
                    job,
                    source,
                    &raw,
                    &author,
                    "bug_message",
                    &format!("launchpad-bug-{}-description", value_text(&bug, "id")),
                    &value_text(&task, "web_link"),
                    &body,
                    value_text(&bug, "date_created"),
                    json!({
                        "context_type": "launchpad_bug",
                        "context_external_id": value_text(&bug, "id"),
                        "context_external_key": value_text(&task, "self_link")
                    }),
                )?;
                counts.arts += 1;
                merge_ingestion_counts(&mut counts, extracted);
            }
            persist_launchpad_messages(job, source, &raw, &bug, &task, &mut counts)?;
            if counts.raw_records % 10 == 0 {
                let _ = update_ingestion_job_counts(
                    &value_text(job, "id"),
                    "running",
                    &counts,
                    json!({
                        "active_source_id": value_text(source, "id"),
                        "bugs_processed": counts.raw_records,
                        "bug_limit": limit
                    }),
                );
            }
            consumed += 1;
        }
        offset += consumed;
        if reached_watermark {
            break;
        }
        if consumed < task_count {
            break;
        }
        if launchpad_next_collection_link(&page).is_none() {
            exhausted = true;
            break;
        }
    }
    if use_watermark && newest_updated_order {
        if reached_watermark || exhausted || counts.raw_records < limit as i64 {
            update_source_ingestion_policy(
                source,
                vec![
                    (
                        "launchpad_updated_watermark",
                        json!(max_timestamp(&previous_watermark, &max_seen)),
                    ),
                    ("launchpad_cursor", Value::Null),
                    ("launchpad_pending_watermark", Value::Null),
                ],
            )?;
        } else {
            update_source_ingestion_policy(
                source,
                vec![
                    ("launchpad_cursor", json!(offset)),
                    ("launchpad_pending_watermark", json!(max_seen)),
                ],
            )?;
        }
    }
    log_ingestion(
        job,
        "source",
        "info",
        "launchpad source ingested",
        json!({
            "raw_records_count": counts.raw_records,
            "arts_count": counts.arts,
            "offset": offset,
            "reached_watermark": reached_watermark,
            "exhausted": exhausted,
            "updated_watermark": if use_watermark { max_timestamp(&previous_watermark, &max_seen) } else { String::new() }
        }),
    )?;
    Ok(counts)
}

fn persist_launchpad_messages(
    job: &Value,
    source: &Value,
    raw: &Value,
    bug: &Value,
    task: &Value,
    counts: &mut IngestionCounts,
) -> Result<(), ApiError> {
    let task_link = value_text(task, "self_link");
    let messages_link = value_text(bug, "messages_collection_link");
    let mut next_url = launchpad_messages_collection_url(&messages_link).or_else(|| {
        if task_link.is_empty() {
            None
        } else {
            launchpad_messages_collection_url(&format!(
                "{}/messages",
                task_link.trim_end_matches('/')
            ))
        }
    });
    while let Some(url) = next_url.take() {
        if ingestion_stop_status(&value_text(job, "id")).is_some() {
            return Ok(());
        }
        let Ok(messages) = fetch_json(&url) else {
            break;
        };
        let entries = messages
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if entries.is_empty() {
            break;
        }
        for message in entries {
            if ingestion_stop_status(&value_text(job, "id")).is_some() {
                return Ok(());
            }
            let content = value_text(&message, "content");
            if content.trim().is_empty() {
                continue;
            }
            let msg_author =
                persist_launchpad_author(job, source, raw, &value_text(&message, "owner_link"))?;
            counts.authors += 1;
            merge_ingestion_counts(
                counts,
                persist_author_metadata(job, source, raw, &msg_author)?,
            );
            let extracted = persist_art(
                job,
                source,
                raw,
                &msg_author,
                "bug_message",
                &format!("{}-comment", value_text(&message, "self_link")),
                &value_text(&message, "web_link"),
                &content,
                value_text(&message, "date_created"),
                json!({
                    "context_type": "launchpad_bug",
                    "context_external_id": value_text(bug, "id"),
                    "context_external_key": value_text(task, "self_link")
                }),
            )?;
            counts.arts += 1;
            merge_ingestion_counts(counts, extracted);
        }
        next_url = launchpad_next_collection_link(&messages);
    }
    Ok(())
}

fn ingest_gerrit_source(job: &Value, source: &Value) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let review_limit = gerrit_review_limit(job, source);
    let reviews_per_minute = gerrit_reviews_per_minute(job, source);
    let page_size = gerrit_page_size(job, source, reviews_per_minute);
    let comments_per_change = gerrit_comments_per_change(job, source);
    let include_automated_messages = gerrit_include_automated_messages(source);
    let use_watermark = use_source_watermarks(job);
    let sync_current = job_param_bool(job, "sync_current", false);
    let stored_watermark = source_policy_text(source, "gerrit_updated_watermark");
    let pending_watermark = source_policy_text(source, "gerrit_pending_watermark");
    let previous_watermark = if use_watermark {
        if sync_current {
            max_timestamp(&stored_watermark, &pending_watermark)
        } else {
            stored_watermark.clone()
        }
    } else {
        String::new()
    };
    let mut max_seen = if use_watermark {
        if sync_current {
            previous_watermark.clone()
        } else {
            pending_watermark.clone()
        }
    } else {
        String::new()
    };
    let mut offset = if use_watermark && !sync_current {
        source_policy_usize(source, "gerrit_cursor")
    } else {
        0
    };
    let watermark_replay_days = source_watermark_replay_days(job, source);
    let replay_watermark = if use_watermark && offset == 0 {
        replay_watermark_for(&previous_watermark, watermark_replay_days)
    } else {
        previous_watermark.clone()
    };
    let base = if value_text(source, "base_url").is_empty() {
        "https://review.opendev.org".to_string()
    } else {
        value_text(source, "base_url")
    };
    let project = if value_text(source, "external_key").is_empty() {
        "openstack/swift".to_string()
    } else {
        value_text(source, "external_key")
    };
    log_ingestion(
        job,
        "source",
        "info",
        "starting gerrit source ingestion",
        json!({
            "source_id": value_text(source, "id"),
            "review_limit": review_limit,
            "reviews_per_minute": reviews_per_minute,
            "page_size": page_size,
            "comments_per_change": comments_per_change,
            "include_automated_messages": include_automated_messages,
            "updated_watermark": previous_watermark,
            "stored_updated_watermark": stored_watermark,
            "pending_watermark": pending_watermark,
            "replay_watermark": replay_watermark,
            "watermark_replay_days": watermark_replay_days,
            "sync_current": sync_current,
            "uses_watermark": use_watermark
        }),
    )?;
    let mut reviews_processed = 0i64;
    let mut reached_watermark = false;
    let mut exhausted = false;
    while reviews_processed < review_limit as i64 {
        if let Some(status) = ingestion_stop_status(&value_text(job, "id")) {
            log_ingestion(
                job,
                "source",
                "info",
                &format!("stopping gerrit source ingestion because job is {status}"),
                json!({ "status": status }),
            )?;
            return Ok(counts);
        }
        let remaining = review_limit.saturating_sub(reviews_processed as usize);
        let batch_size = page_size.min(remaining);
        let query = if use_watermark && !replay_watermark.is_empty() {
            format!(
                "project:{project} after:{}",
                gerrit_after_date(&replay_watermark)
            )
        } else {
            format!("project:{project}")
        };
        let url = format!(
            "{}/changes/?q={}&o=MESSAGES&o=CURRENT_REVISION&o=CURRENT_COMMIT&o=CURRENT_FILES&o=DETAILED_ACCOUNTS&n={}&S={}",
            base.trim_end_matches('/'),
            url_query_encode(&query),
            batch_size,
            offset
        );
        log_ingestion(
            job,
            "fetch",
            "info",
            "fetching gerrit review page",
            json!({
                "url": url,
                "source_id": value_text(source, "id"),
                "offset": offset,
                "batch_size": batch_size,
                "processed_reviews": reviews_processed,
                "review_limit": review_limit,
                "query": query
            }),
        )?;
        let changes = fetch_json(&url)?;
        let mut changes = changes.as_array().cloned().unwrap_or_default();
        if changes.is_empty() {
            exhausted = true;
            break;
        }
        let more_changes = changes.iter().any(|change| {
            change
                .get("_more_changes")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        });
        changes.sort_by(|left, right| {
            timestamp_key(&value_text(right, "updated"))
                .cmp(&timestamp_key(&value_text(left, "updated")))
        });
        let fetched_count = changes.len();
        let mut consumed = 0usize;
        for change in changes {
            if let Some(status) = ingestion_stop_status(&value_text(job, "id")) {
                log_ingestion(
                    job,
                    "source",
                    "info",
                    &format!("stopping gerrit source ingestion because job is {status}"),
                    json!({
                        "status": status,
                        "reviews_processed": reviews_processed
                    }),
                )?;
                return Ok(counts);
            }
            if reviews_processed >= review_limit as i64 {
                break;
            }
            let updated_at = value_text(&change, "updated");
            max_seen = max_timestamp(&max_seen, &updated_at);
            if use_watermark
                && !replay_watermark.is_empty()
                && !timestamp_after(&updated_at, &replay_watermark)
            {
                reached_watermark = true;
                break;
            }
            throttle_gerrit_review(reviews_processed, reviews_per_minute);
            let change = normalize_gerrit_change_payload(change);
            let number = value_text(&change, "_number");
            let change_url = format!("{}/c/{}/+/{}", base.trim_end_matches('/'), project, number);
            let raw = persist_raw_record(
                job,
                source,
                &format!("gerrit-change-{number}"),
                "gerrit_change",
                &change_url,
                change.clone(),
                value_text(&change, "created"),
            )?;
            counts.raw_records += 1;
            merge_ingestion_counts(
                &mut counts,
                persist_raw_metadata_with_art_index(job, source, &raw, None)?,
            );
            reviews_processed += 1;
            let owner = change.get("owner").cloned().unwrap_or_else(|| json!({}));
            let owner_author = persist_gerrit_author(job, source, &raw, &base, &owner)?;
            counts.authors += 1;
            merge_ingestion_counts(
                &mut counts,
                persist_author_metadata(job, source, &raw, &owner_author)?,
            );
            let subject = value_text(&change, "subject");
            if !subject.trim().is_empty() {
                let extracted = persist_art(
                    job,
                    source,
                    &raw,
                    &owner_author,
                    "code_review_message",
                    &format!("gerrit-change-{number}-subject"),
                    &change_url,
                    &subject,
                    value_text(&change, "created"),
                    json!({
                        "context_type": "gerrit_change",
                        "context_external_id": number,
                        "context_external_key": value_text(&change, "id"),
                        "review_message_kind": "change_subject",
                        "automated": false
                    }),
                )?;
                counts.arts += 1;
                merge_ingestion_counts(&mut counts, extracted);
            }
            for message in change
                .get("messages")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                let body = value_text(&message, "message");
                if body.trim().is_empty() {
                    continue;
                }
                let automated = is_gerrit_automated_message(&message, &body);
                let summary_only = is_gerrit_review_summary_only(&body);
                if !include_automated_messages && (automated || summary_only) {
                    continue;
                }
                let author = message.get("author").cloned().unwrap_or_else(|| json!({}));
                persist_gerrit_art_from_raw_payload(
                    &mut counts,
                    job,
                    source,
                    &base,
                    &format!(
                        "gerrit-change-{number}-message-{}",
                        value_text(&message, "id")
                    ),
                    "gerrit_change_message",
                    &change_url,
                    json!({
                        "change_id": value_text(&change, "id"),
                        "change_number": number,
                        "message": message.clone()
                    }),
                    value_text(&message, "date"),
                    author,
                    "code_review_message",
                    &format!(
                        "gerrit-change-{number}-message-{}",
                        value_text(&message, "id")
                    ),
                    &body,
                    value_text(&message, "date"),
                    json!({
                    "context_type": "gerrit_change",
                    "context_external_id": number,
                    "context_external_key": value_text(&change, "id"),
                    "review_message_kind": if automated { "automated_change_message" } else { "change_message" },
                    "automated": automated,
                    "summary_only": summary_only,
                    "gerrit_message_tag": value_text(&message, "tag"),
                    "patch_set": message
                        .get("_revision_number")
                    .cloned()
                    .unwrap_or_else(|| json!(null))
                    }),
                )?;
            }
            if comments_per_change > 0
                && change
                    .get("total_comment_count")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    > 0
            {
                let comments_url =
                    format!("{}/changes/{}/comments", base.trim_end_matches('/'), number);
                match fetch_json(&comments_url) {
                    Ok(comments) => {
                        let mut persisted_comments = 0usize;
                        'comments: for (path, comments_for_file) in
                            comments.as_object().into_iter().flatten()
                        {
                            for comment in comments_for_file.as_array().into_iter().flatten() {
                                if ingestion_stop_status(&value_text(job, "id")).is_some() {
                                    break 'comments;
                                }
                                if persisted_comments >= comments_per_change {
                                    break 'comments;
                                }
                                let body = value_text(comment, "message");
                                if body.trim().is_empty() {
                                    continue;
                                }
                                let author =
                                    comment.get("author").cloned().unwrap_or_else(|| json!({}));
                                persist_gerrit_art_from_raw_payload(
                                    &mut counts,
                                    job,
                                    source,
                                    &base,
                                    &format!(
                                        "gerrit-change-{number}-comment-{}",
                                        value_text(comment, "id")
                                    ),
                                    "gerrit_inline_comment",
                                    &change_url,
                                    json!({
                                        "change_id": value_text(&change, "id"),
                                        "change_number": number,
                                        "file_path": path,
                                        "comment": comment.clone()
                                    }),
                                    value_text(comment, "updated"),
                                    author,
                                    "code_review_message",
                                    &format!(
                                        "gerrit-change-{number}-comment-{}",
                                        value_text(comment, "id")
                                    ),
                                    &body,
                                    value_text(comment, "updated"),
                                    json!({
                                    "context_type": "gerrit_change",
                                    "context_external_id": number,
                                    "context_external_key": path,
                                    "review_message_kind": "inline_comment",
                                    "automated": false,
                                    "file_path": path,
                                    "line": comment
                                        .get("line")
                                        .cloned()
                                        .unwrap_or_else(|| json!(null)),
                                    "patch_set": comment
                                        .get("patch_set")
                                        .or_else(|| comment.get("patch_set_number"))
                                        .cloned()
                                        .unwrap_or_else(|| json!(null))
                                    }),
                                )?;
                                persisted_comments += 1;
                            }
                        }
                    }
                    Err(err) => {
                        log_ingestion(
                            job,
                            "comments",
                            "warn",
                            "fetching gerrit inline comments failed",
                            json!({
                                "url": comments_url,
                                "change": number,
                                "error": err.message
                            }),
                        )?;
                    }
                }
            }
            merge_ingestion_counts(
                &mut counts,
                apply_gerrit_implementation_risk_rules(job, source, &raw, None)?,
            );
            let _ = update_ingestion_job_counts(
                &value_text(job, "id"),
                "running",
                &counts,
                json!({
                    "stats": {
                        "active_source_id": value_text(source, "id"),
                        "reviews_processed": reviews_processed,
                        "review_limit": review_limit,
                        "reviews_per_minute": reviews_per_minute
                    }
                }),
            );
            consumed += 1;
        }
        offset += consumed;
        if reached_watermark {
            break;
        }
        if consumed < fetched_count {
            break;
        }
        if fetched_count < batch_size || !more_changes {
            exhausted = true;
            break;
        }
    }
    if use_watermark {
        if reached_watermark || exhausted || reviews_processed < review_limit as i64 {
            update_source_ingestion_policy(
                source,
                vec![
                    (
                        "gerrit_updated_watermark",
                        json!(max_timestamp(&previous_watermark, &max_seen)),
                    ),
                    ("gerrit_cursor", Value::Null),
                    ("gerrit_pending_watermark", Value::Null),
                ],
            )?;
        } else if sync_current {
            update_source_ingestion_policy(
                source,
                vec![
                    (
                        "gerrit_pending_watermark",
                        json!(max_timestamp(&previous_watermark, &max_seen)),
                    ),
                    ("gerrit_cursor", Value::Null),
                ],
            )?;
        } else {
            update_source_ingestion_policy(
                source,
                vec![
                    ("gerrit_cursor", json!(offset)),
                    ("gerrit_pending_watermark", json!(max_seen)),
                ],
            )?;
        }
    }
    log_ingestion(
        job,
        "source",
        "info",
        "gerrit source ingested",
        json!({
            "raw_records_count": counts.raw_records,
            "arts_count": counts.arts,
            "offset": offset,
            "reached_watermark": reached_watermark,
            "exhausted": exhausted,
            "updated_watermark": if use_watermark { max_timestamp(&previous_watermark, &max_seen) } else { String::new() }
        }),
    )?;
    Ok(counts)
}

fn normalize_gerrit_change_payload(mut change: Value) -> Value {
    let current_revision = value_text(&change, "current_revision");
    let revision = change
        .get("revisions")
        .and_then(Value::as_object)
        .and_then(|revisions| {
            if current_revision.is_empty() {
                revisions.values().next()
            } else {
                revisions
                    .get(&current_revision)
                    .or_else(|| revisions.values().next())
            }
        })
        .cloned();

    let Some(revision) = revision else {
        return change;
    };

    let commit = revision.get("commit").cloned().unwrap_or(Value::Null);
    let files = revision.get("files").cloned().unwrap_or(Value::Null);
    let changed_files = gerrit_revision_changed_files(&files);
    let file_details = gerrit_revision_file_details(&files);
    let commit_message = value_text(&commit, "message");
    let commit_subject = value_text(&commit, "subject");

    if let Some(map) = change.as_object_mut() {
        if !commit_message.is_empty() {
            map.insert(
                "current_revision_commit_message".to_string(),
                json!(commit_message),
            );
        }
        if !commit_subject.is_empty() {
            map.insert(
                "current_revision_subject".to_string(),
                json!(commit_subject),
            );
        }
        if !changed_files.is_empty() {
            map.insert("changed_files".to_string(), json!(changed_files));
            map.insert("changed_file_count".to_string(), json!(file_details.len()));
            map.insert("files".to_string(), json!(file_details));
        }
        if let Some(parents) = commit.get("parents") {
            map.insert("current_revision_parents".to_string(), parents.clone());
        }
        if let Some(author) = commit.get("author") {
            map.insert("current_revision_author".to_string(), author.clone());
        }
        if let Some(committer) = commit.get("committer") {
            map.insert("current_revision_committer".to_string(), committer.clone());
        }
    }

    change
}

fn gerrit_revision_changed_files(files: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    let Some(map) = files.as_object() else {
        return paths;
    };
    for path in map.keys() {
        if path == "/COMMIT_MSG" || path.trim().is_empty() {
            continue;
        }
        paths.push(path.to_string());
    }
    paths.sort();
    paths
}

fn gerrit_revision_file_details(files: &Value) -> Vec<Value> {
    let mut details = Vec::new();
    let Some(map) = files.as_object() else {
        return details;
    };
    for (path, value) in map {
        if path == "/COMMIT_MSG" || path.trim().is_empty() {
            continue;
        }
        details.push(json!({
            "path": path,
            "status": value_text(value, "status"),
            "lines_inserted": value_i64(value.get("lines_inserted").unwrap_or(&Value::Null)),
            "lines_deleted": value_i64(value.get("lines_deleted").unwrap_or(&Value::Null)),
            "size_delta": value_i64(value.get("size_delta").unwrap_or(&Value::Null)),
            "size": value_i64(value.get("size").unwrap_or(&Value::Null))
        }));
    }
    details.sort_by(|left, right| value_text(left, "path").cmp(&value_text(right, "path")));
    details
}

fn persist_raw_record(
    job: &Value,
    source: &Value,
    external_id: &str,
    record_type: &str,
    url: &str,
    payload: Value,
    fetched_at: String,
) -> Result<Value, ApiError> {
    let source_id = value_text(source, "id");
    let id = raw_record_id_for(source, external_id);
    let fetched = if fetched_at.is_empty() {
        now_timestamp()
    } else {
        fetched_at
    };
    upsert_record(
        "raw-records",
        &json!({
            "id": id,
            "repository_id": value_text(source, "repository_id"),
            "source_id": source_id,
            "ingestion_job_id": value_text(job, "id"),
            "external_id": external_id,
            "external_key": external_id,
            "record_type": record_type,
            "url": url,
            "content_type": "application/json",
            "payload": payload,
            "fetched_at": fetched
        }),
    )
}

fn raw_record_id_for(source: &Value, external_id: &str) -> String {
    let source_id = value_text(source, "id");
    format!(
        "raw-record-{}",
        stable_hash(&format!("{source_id}|{external_id}"))
    )
}

fn payload_hash_for(payload: &Value) -> String {
    stable_hash(&payload.to_string())
}

fn git_commit_already_ingested(
    job: &Value,
    source: &Value,
    raw_external_id: &str,
    payload: &Value,
    body: &str,
    art_external_id: &str,
) -> Result<bool, ApiError> {
    if job_param_bool(job, "force_ingest", false) {
        return Ok(false);
    }
    let raw_id = raw_record_id_for(source, raw_external_id);
    let existing_raw = match get_record("raw-records", &raw_id) {
        Ok(raw) => raw,
        Err(_) => return Ok(false),
    };
    if value_text(&existing_raw, "payload_hash") != payload_hash_for(payload) {
        return Ok(false);
    }
    if body.is_empty() {
        return Ok(true);
    }
    let art_id = art_id_for(source, art_external_id, "commit_message");
    let existing_art = match get_record("arts", &art_id) {
        Ok(art) => art,
        Err(_) => return Ok(false),
    };
    Ok(value_text(&existing_art, "body_hash") == stable_hash(body))
}

#[allow(clippy::too_many_arguments)]
fn persist_gerrit_art_from_raw_payload(
    counts: &mut IngestionCounts,
    job: &Value,
    source: &Value,
    base_url: &str,
    raw_external_id: &str,
    raw_record_type: &str,
    url: &str,
    payload: Value,
    fetched_at: String,
    author_payload: Value,
    art_type: &str,
    art_external_id: &str,
    body: &str,
    source_created_at: String,
    context: Value,
) -> Result<(), ApiError> {
    let raw = persist_raw_record(
        job,
        source,
        raw_external_id,
        raw_record_type,
        url,
        payload,
        fetched_at,
    )?;
    counts.raw_records += 1;
    merge_ingestion_counts(
        counts,
        persist_raw_metadata_with_art_index(job, source, &raw, None)?,
    );

    let author = persist_gerrit_author(job, source, &raw, base_url, &author_payload)?;
    counts.authors += 1;
    merge_ingestion_counts(counts, persist_author_metadata(job, source, &raw, &author)?);

    let extracted = persist_art(
        job,
        source,
        &raw,
        &author,
        art_type,
        art_external_id,
        url,
        body,
        source_created_at,
        context,
    )?;
    counts.arts += 1;
    merge_ingestion_counts(counts, extracted);
    Ok(())
}

fn launchpad_person_cache() -> &'static Mutex<BTreeMap<String, Value>> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, Value>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn launchpad_person(owner_link: &str) -> Value {
    let owner_link = owner_link.trim();
    if owner_link.is_empty() {
        return json!({});
    }
    if let Some(person) = launchpad_person_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(owner_link)
        .cloned()
    {
        return person;
    }
    let person = fetch_json(owner_link).unwrap_or_else(|_| json!({}));
    launchpad_person_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(owner_link.to_string(), person.clone());
    person
}

fn persist_launchpad_author(
    job: &Value,
    source: &Value,
    raw: &Value,
    owner_link: &str,
) -> Result<Value, ApiError> {
    let person = launchpad_person(owner_link);
    let external_id = first_non_empty(&[
        value_text(&person, "self_link"),
        owner_link.to_string(),
        value_text(&person, "name"),
    ]);
    persist_author(
        job,
        source,
        raw,
        "launchpad",
        &external_id,
        &value_text(&person, "name"),
        &value_text(&person, "display_name"),
        &first_non_empty(&[
            value_text(&person, "email"),
            value_text(&person, "email_address"),
        ]),
        &value_text(&person, "web_link"),
    )
}

fn persist_gerrit_author(
    job: &Value,
    source: &Value,
    raw: &Value,
    base_url: &str,
    account: &Value,
) -> Result<Value, ApiError> {
    let account_id = value_text(account, "_account_id");
    let username = first_non_empty(&[value_text(account, "username"), account_id.clone()]);
    let email = value_text(account, "email");
    let display_name = first_non_empty(&[
        value_text(account, "name"),
        username.clone(),
        email.clone(),
        account_id.clone(),
    ]);
    let profile_url = if account_id.is_empty() {
        String::new()
    } else {
        format!("{}/q/owner:{}", base_url.trim_end_matches('/'), account_id)
    };
    persist_author(
        job,
        source,
        raw,
        "gerrit",
        &account_id,
        &username,
        &display_name,
        &email,
        &profile_url,
    )
}

fn persist_author(
    job: &Value,
    source: &Value,
    raw: &Value,
    provider: &str,
    external_author_id: &str,
    username: &str,
    display_name: &str,
    email: &str,
    profile_url: &str,
) -> Result<Value, ApiError> {
    let external_source = first_non_empty(&[
        external_author_id.to_string(),
        email.to_string(),
        username.to_string(),
        display_name.to_string(),
        "unknown".to_string(),
    ]);
    let external = external_source
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(&external_source)
        .to_string();
    let username = first_non_empty(&[
        username.to_string(),
        email.to_string(),
        display_name.to_string(),
        format!("{provider}:{external}"),
    ]);
    let source_id = value_text(source, "id");
    let id = format!(
        "author-{}",
        stable_hash(&format!("{source_id}|{provider}|{external}"))
    );
    let author = upsert_record(
        "authors",
        &json!({
            "id": id,
            "repository_id": value_text(source, "repository_id"),
            "source_id": source_id,
            "ingestion_job_id": value_text(job, "id"),
            "raw_record_id": value_text(raw, "id"),
            "external_author_id": format!("{provider}:{external}"),
            "username": username,
            "display_name": display_name,
            "email": email,
            "profile_url": profile_url
        }),
    )?;
    cache_author_external_mapping(&author);
    Ok(author)
}

fn persist_art(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    art_type: &str,
    external_id: &str,
    url: &str,
    body: &str,
    source_created_at: String,
    context: Value,
) -> Result<IngestionCounts, ApiError> {
    let source_id = value_text(source, "id");
    let id = art_id_for(source, external_id, art_type);
    let source_time = if source_created_at.is_empty() {
        now_timestamp()
    } else {
        source_created_at
    };
    let mut record = json!({
        "id": id,
        "repository_id": value_text(source, "repository_id"),
        "source_id": source_id,
        "ingestion_job_id": value_text(job, "id"),
        "raw_record_id": value_text(raw, "id"),
        "author_id": value_text(author, "id"),
        "type": art_type,
        "external_id": external_id,
        "external_key": external_id,
        "url": url,
        "body": body,
        "body_format": "text/plain",
        "source_created_at": source_time.clone(),
        "source_updated_at": source_time
    });
    if let (Some(record_obj), Some(context_obj)) = (record.as_object_mut(), context.as_object()) {
        for (key, value) in context_obj {
            record_obj.insert(key.clone(), value.clone());
        }
    }
    let art = upsert_record("arts", &record)?;
    persist_art_metadata(job, source, raw, author, &art)
}

fn art_id_for(source: &Value, external_id: &str, art_type: &str) -> String {
    let source_id = value_text(source, "id");
    format!(
        "art-{}",
        stable_hash(&format!("{source_id}|{external_id}|{art_type}"))
    )
}

fn merge_ingestion_counts(counts: &mut IngestionCounts, extra: IngestionCounts) {
    counts.raw_records += extra.raw_records;
    counts.arts += extra.arts;
    counts.authors += extra.authors;
    counts.metadata += extra.metadata;
    counts.relationships += extra.relationships;
}

fn persist_art_metadata(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    art: &Value,
) -> Result<IngestionCounts, ApiError> {
    let Some(normalizer) = resolve_normalizer(job, source)? else {
        return Ok(IngestionCounts::default());
    };
    persist_art_metadata_with_normalizer(job, source, raw, author, art, &normalizer)
}

fn persist_art_metadata_with_normalizer(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    art: &Value,
    normalizer: &Value,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    if normalizer_processing_is_current(job, source, raw, "art", art, normalizer)? {
        return Ok(counts);
    }
    let rule_id_filter = job_param_text(job, "rule_id");
    for rule in normalizer_rules(&normalizer, "art_rules") {
        if !rule_id_filter.is_empty() && value_text(&rule, "id") != rule_id_filter {
            continue;
        }
        if !rule_applies_to_art(&rule, art) {
            continue;
        }
        merge_ingestion_counts(
            &mut counts,
            apply_art_rule(job, source, raw, author, art, &rule)?,
        );
    }
    if rule_id_filter.is_empty() {
        persist_normalizer_processing_marker(job, source, raw, "art", art, normalizer)?;
    }

    Ok(counts)
}

fn persist_author_metadata(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
) -> Result<IngestionCounts, ApiError> {
    if value_text(author, "id").is_empty() {
        return Ok(IngestionCounts::default());
    }
    let Some(normalizer) = resolve_normalizer(job, source)? else {
        return Ok(IngestionCounts::default());
    };
    persist_author_metadata_with_normalizer(job, source, raw, author, &normalizer)
}

fn persist_author_metadata_with_normalizer(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    normalizer: &Value,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    if value_text(author, "id").is_empty() {
        return Ok(counts);
    }
    if normalizer_processing_is_current(job, source, raw, "author", author, normalizer)? {
        return Ok(counts);
    }
    for rule in normalizer_rules(&normalizer, "author_rules") {
        merge_ingestion_counts(
            &mut counts,
            apply_author_rule(job, source, raw, author, &rule)?,
        );
    }
    persist_normalizer_processing_marker(job, source, raw, "author", author, normalizer)?;
    Ok(counts)
}

#[cfg(test)]
fn persist_raw_metadata(
    job: &Value,
    source: &Value,
    raw: &Value,
) -> Result<IngestionCounts, ApiError> {
    persist_raw_metadata_with_art_index(job, source, raw, None)
}

fn persist_raw_metadata_with_art_index(
    job: &Value,
    source: &Value,
    raw: &Value,
    art_index: Option<&NormalizerArtIndex>,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let Some(normalizer) = resolve_normalizer(job, source)? else {
        return Ok(counts);
    };
    if normalizer_processing_is_current(job, source, raw, "raw_record", raw, &normalizer)? {
        return Ok(counts);
    }
    let rule_id_filter = job_param_text(job, "rule_id");
    for rule in normalizer_rules(&normalizer, "raw_rules") {
        if !rule_id_filter.is_empty() && value_text(&rule, "id") != rule_id_filter {
            continue;
        }
        if !rule_applies_to_raw(&rule, raw) {
            continue;
        }
        merge_ingestion_counts(
            &mut counts,
            apply_raw_rule(job, source, raw, &rule, art_index)?,
        );
    }
    if rule_id_filter.is_empty() {
        persist_normalizer_processing_marker(job, source, raw, "raw_record", raw, &normalizer)?;
    }
    Ok(counts)
}

fn resolve_normalizer(job: &Value, source: &Value) -> Result<Option<Value>, ApiError> {
    if job_param_bool(job, "skip_normalizers", false)
        || job_param_bool(job, "skip_metadata_normalizers", false)
    {
        return Ok(None);
    }
    let normalizer_id = first_non_empty(&[
        value_text(job, "normalizer_id"),
        value_text(source, "normalizer_id"),
    ]);
    if normalizer_id.is_empty() {
        return Ok(None);
    }
    let normalizer = get_record("normalizers", &normalizer_id)?;
    if normalizer.get("enabled").and_then(Value::as_bool) == Some(false) {
        return Ok(None);
    }
    Ok(Some(normalizer))
}

fn normalizer_rules(normalizer: &Value, field: &str) -> Vec<Value> {
    normalizer
        .get("rules")
        .and_then(|rules| rules.get(field))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn normalizer_processing_is_current(
    job: &Value,
    source: &Value,
    raw: &Value,
    subject_type: &str,
    subject: &Value,
    normalizer: &Value,
) -> Result<bool, ApiError> {
    if job_param_bool(job, "force_normalize", false) || job_param_bool(job, "force_ingest", false) {
        return Ok(false);
    }
    let marker_id = normalizer_processing_marker_id(source, subject_type, subject, normalizer);
    if marker_id.is_empty() {
        return Ok(false);
    }
    match get_record("metadata", &marker_id) {
        Ok(marker) => {
            let expected = normalizer_processing_fingerprint(subject_type, subject, normalizer);
            Ok(marker
                .get("value")
                .and_then(|value| value.get("fingerprint"))
                .and_then(Value::as_str)
                == Some(expected.as_str())
                && value_text(&marker, "raw_record_id") == value_text(raw, "id"))
        }
        Err(_) => Ok(false),
    }
}

fn persist_normalizer_processing_marker(
    job: &Value,
    source: &Value,
    raw: &Value,
    subject_type: &str,
    subject: &Value,
    normalizer: &Value,
) -> Result<(), ApiError> {
    let subject_id = value_text(subject, "id");
    if subject_id.is_empty() {
        return Ok(());
    }
    let marker_id = normalizer_processing_marker_id(source, subject_type, subject, normalizer);
    if marker_id.is_empty() {
        return Ok(());
    }
    let input_hash = normalizer_subject_input_hash(subject_type, subject);
    let rules_hash = stable_hash(&canonical_json(
        normalizer.get("rules").unwrap_or(&Value::Null),
    ));
    upsert_record(
        "metadata",
        &json!({
            "id": marker_id,
            "repository_id": first_non_empty(&[
                value_text(source, "repository_id"),
                value_text(subject, "repository_id")
            ]),
            "source_id": first_non_empty(&[
                value_text(source, "id"),
                value_text(subject, "source_id")
            ]),
            "ingestion_job_id": value_text(job, "id"),
            "raw_record_id": value_text(raw, "id"),
            "subject_type": subject_type,
            "subject_id": subject_id,
            "namespace": "ingestion.processing",
            "key": "normalizer_fingerprint",
            "value": {
                "normalizer_id": value_text(normalizer, "id"),
                "normalizer_version": value_text(normalizer, "version"),
                "normalizer_rules_hash": rules_hash,
                "input_hash": input_hash,
                "fingerprint": normalizer_processing_fingerprint(subject_type, subject, normalizer)
            },
            "value_type": "object",
            "source_created_at": first_non_empty(&[
                value_text(subject, "source_created_at"),
                value_text(raw, "fetched_at"),
                now_timestamp()
            ]),
            "source_updated_at": first_non_empty(&[
                value_text(subject, "source_updated_at"),
                value_text(raw, "fetched_at"),
                now_timestamp()
            ])
        }),
    )?;
    Ok(())
}

fn normalizer_processing_marker_id(
    source: &Value,
    subject_type: &str,
    subject: &Value,
    normalizer: &Value,
) -> String {
    let repository_id = first_non_empty(&[
        value_text(source, "repository_id"),
        value_text(subject, "repository_id"),
    ]);
    let source_id = first_non_empty(&[value_text(source, "id"), value_text(subject, "source_id")]);
    let subject_id = value_text(subject, "id");
    if repository_id.is_empty() || subject_id.is_empty() {
        return String::new();
    }
    let fingerprint = normalizer_processing_fingerprint(subject_type, subject, normalizer);
    format!(
        "metadata-{}",
        stable_hash(&format!(
            "{repository_id}|{source_id}|{subject_type}|{subject_id}|ingestion.processing|normalizer_fingerprint|{fingerprint}"
        ))
    )
}

fn normalizer_processing_fingerprint(
    subject_type: &str,
    subject: &Value,
    normalizer: &Value,
) -> String {
    let rules_hash = stable_hash(&canonical_json(
        normalizer.get("rules").unwrap_or(&Value::Null),
    ));
    stable_hash(&format!(
        "{}|{}|{}|{}|{}",
        value_text(normalizer, "id"),
        value_text(normalizer, "version"),
        rules_hash,
        subject_type,
        normalizer_subject_input_hash(subject_type, subject)
    ))
}

fn normalizer_subject_input_hash(subject_type: &str, subject: &Value) -> String {
    match subject_type {
        "raw_record" => first_non_empty(&[
            value_text(subject, "payload_hash"),
            stable_hash(&canonical_json(
                subject.get("payload").unwrap_or(&Value::Null),
            )),
        ]),
        "art" => first_non_empty(&[
            value_text(subject, "body_hash"),
            stable_hash(&value_text(subject, "body")),
        ]),
        "author" => stable_hash(&format!(
            "{}|{}|{}|{}|{}",
            value_text(subject, "external_author_id"),
            value_text(subject, "username"),
            value_text(subject, "display_name"),
            value_text(subject, "email"),
            value_text(subject, "profile_url")
        )),
        _ => stable_hash(&canonical_json(subject)),
    }
}

fn rule_applies_to_art(rule: &Value, art: &Value) -> bool {
    let art_type = value_text(art, "type");
    let allowed = rule.get("art_types").and_then(Value::as_array);
    allowed
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .any(|candidate| candidate == art_type)
        })
        .unwrap_or(true)
}

fn rule_applies_to_raw(rule: &Value, raw: &Value) -> bool {
    let record_type = value_text(raw, "record_type");
    let allowed = rule.get("record_types").and_then(Value::as_array);
    allowed
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .any(|candidate| candidate == record_type)
        })
        .unwrap_or(true)
}

fn apply_art_rule(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    art: &Value,
    rule: &Value,
) -> Result<IngestionCounts, ApiError> {
    let primitive = value_text(rule, "primitive");
    match primitive.as_str() {
        "relationship" => apply_art_relationship_rule(job, source, raw, author, art, rule),
        "field_map" => apply_art_metadata_values(
            job,
            source,
            raw,
            art,
            rule,
            apply_rule_transform(
                rule,
                values_for_path(
                    job,
                    source,
                    raw,
                    Some(art),
                    Some(author),
                    &value_text(rule, "field"),
                ),
            ),
        ),
        "text_stats" => {
            let body = value_text(art, "body");
            apply_art_metadata_values(
                job,
                source,
                raw,
                art,
                rule,
                vec![json!({
                    "bytes": body.len(),
                    "chars": body.chars().count(),
                    "lines": body.lines().count()
                })],
            )
        }
        "dictionary" => apply_dictionary_rule(job, source, raw, art, rule),
        "review_concern" => apply_review_concern_rule(job, source, raw, author, art, rule),
        "named_extractor" => {
            let field = if value_text(rule, "field").is_empty() {
                "art.body".to_string()
            } else {
                value_text(rule, "field")
            };
            let text = values_for_path(job, source, raw, Some(art), Some(author), &field)
                .into_iter()
                .filter_map(|value| scalar_text(&value))
                .collect::<Vec<_>>()
                .join("\n");
            let values = extract_named_values(&value_text(rule, "extractor"), &text);
            apply_art_metadata_values(job, source, raw, art, rule, values)
        }
        "" => Ok(IngestionCounts::default()),
        other => Err(ApiError::bad_request(format!(
            "unsupported art normalizer primitive {other}"
        ))),
    }
}

fn apply_raw_rule(
    job: &Value,
    source: &Value,
    raw: &Value,
    rule: &Value,
    art_index: Option<&NormalizerArtIndex>,
) -> Result<IngestionCounts, ApiError> {
    let primitive = value_text(rule, "primitive");
    match primitive.as_str() {
        "field_map" => apply_raw_metadata_values(
            job,
            source,
            raw,
            rule,
            apply_rule_transform(
                rule,
                values_for_rule_fields(job, source, raw, None, None, rule),
            ),
            art_index,
        ),
        "text_stats" => {
            let text = text_for_rule_fields(job, source, raw, None, None, rule);
            apply_raw_metadata_values(
                job,
                source,
                raw,
                rule,
                vec![json!({
                    "bytes": text.len(),
                    "chars": text.chars().count(),
                    "lines": text.lines().count()
                })],
                art_index,
            )
        }
        "dictionary" => apply_raw_dictionary_rule(job, source, raw, rule, art_index),
        "gerrit_implementation_risk" => {
            apply_gerrit_implementation_risk_rule(job, source, raw, rule, art_index)
        }
        "named_extractor" => {
            let text = text_for_rule_fields(job, source, raw, None, None, rule);
            let values = extract_named_values(&value_text(rule, "extractor"), &text);
            apply_raw_metadata_values(job, source, raw, rule, values, art_index)
        }
        "" => Ok(IngestionCounts::default()),
        other => Err(ApiError::bad_request(format!(
            "unsupported raw normalizer primitive {other}"
        ))),
    }
}

fn apply_author_rule(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    rule: &Value,
) -> Result<IngestionCounts, ApiError> {
    let primitive = value_text(rule, "primitive");
    match primitive.as_str() {
        "field_map" => {
            let values = apply_rule_transform(
                rule,
                values_for_path(
                    job,
                    source,
                    raw,
                    None,
                    Some(author),
                    &value_text(rule, "field"),
                ),
            );
            apply_author_metadata_values(job, source, raw, author, rule, values)
        }
        "named_extractor" => {
            let field = value_text(rule, "field");
            let text = values_for_path(job, source, raw, None, Some(author), &field)
                .into_iter()
                .filter_map(|value| scalar_text(&value))
                .collect::<Vec<_>>()
                .join("\n");
            let values = extract_named_values(&value_text(rule, "extractor"), &text);
            apply_author_metadata_values(job, source, raw, author, rule, values)
        }
        "" => Ok(IngestionCounts::default()),
        other => Err(ApiError::bad_request(format!(
            "unsupported author normalizer primitive {other}"
        ))),
    }
}

fn apply_art_relationship_rule(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    art: &Value,
    rule: &Value,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let relation = value_text(rule, "relation");
    if relation == "authored_by" {
        let art_id = value_text(art, "id");
        let author_id = value_text(author, "id");
        if !art_id.is_empty() && !author_id.is_empty() {
            persist_relationship(
                job,
                source,
                raw,
                "art",
                &art_id,
                "authored_by",
                "author",
                &author_id,
                &art_id,
                "",
                &rule_origin(rule, "normalizer.relationship"),
            )?;
            counts.relationships += 1;
        }
    }
    Ok(counts)
}

fn apply_dictionary_rule(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: &Value,
    rule: &Value,
) -> Result<IngestionCounts, ApiError> {
    let field = if value_text(rule, "field").is_empty() {
        "art.body".to_string()
    } else {
        value_text(rule, "field")
    };
    let text = values_for_path(job, source, raw, Some(art), None, &field)
        .into_iter()
        .filter_map(|value| scalar_text(&value))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    let mut counts = IngestionCounts::default();
    for term in rule
        .get("terms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let term_text = term
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| value_text(term, "term"));
        if term_text.is_empty() || !text.contains(&term_text.to_lowercase()) {
            continue;
        }
        let mut derived_rule = object_from(rule);
        if let Some(namespace) = term.get("namespace").and_then(Value::as_str) {
            derived_rule.insert("namespace".to_string(), json!(namespace));
        }
        if let Some(key) = term.get("key").and_then(Value::as_str) {
            derived_rule.insert("key".to_string(), json!(key));
        } else if let Some(category) = term.get("category").and_then(Value::as_str) {
            derived_rule.insert("key".to_string(), json!(category));
        }
        let value = term
            .get("value")
            .cloned()
            .unwrap_or_else(|| json!({ "term": term_text }));
        merge_ingestion_counts(
            &mut counts,
            apply_art_metadata_values(
                job,
                source,
                raw,
                art,
                &Value::Object(derived_rule),
                vec![value],
            )?,
        );
    }
    Ok(counts)
}

fn apply_raw_dictionary_rule(
    job: &Value,
    source: &Value,
    raw: &Value,
    rule: &Value,
    art_index: Option<&NormalizerArtIndex>,
) -> Result<IngestionCounts, ApiError> {
    let text = text_for_rule_fields(job, source, raw, None, None, rule).to_lowercase();
    let mut counts = IngestionCounts::default();
    for term in rule
        .get("terms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let term_text = term
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| value_text(term, "term"));
        if term_text.is_empty() || !text.contains(&term_text.to_lowercase()) {
            continue;
        }
        let mut derived_rule = object_from(rule);
        if let Some(namespace) = term.get("namespace").and_then(Value::as_str) {
            derived_rule.insert("namespace".to_string(), json!(namespace));
        }
        if let Some(key) = term.get("key").and_then(Value::as_str) {
            derived_rule.insert("key".to_string(), json!(key));
        } else if let Some(category) = term.get("category").and_then(Value::as_str) {
            derived_rule.insert("key".to_string(), json!(category));
        }
        let value = term
            .get("value")
            .cloned()
            .unwrap_or_else(|| json!({ "term": term_text }));
        merge_ingestion_counts(
            &mut counts,
            apply_raw_metadata_values(
                job,
                source,
                raw,
                &Value::Object(derived_rule),
                vec![value],
                art_index,
            )?,
        );
    }
    Ok(counts)
}

fn apply_art_metadata_values(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: &Value,
    rule: &Value,
    values: Vec<Value>,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    for value in values.into_iter().flat_map(expand_metadata_value) {
        if is_empty_value(&value) {
            continue;
        }
        let namespace = value_text(rule, "namespace");
        let key = value_text(rule, "key");
        if namespace.is_empty() || key.is_empty() {
            continue;
        }
        let relation = first_non_empty(&[value_text(rule, "relation"), "describes".to_string()]);
        let direction =
            first_non_empty(&[value_text(rule, "direction"), "metadata_to_art".to_string()]);
        merge_ingestion_counts(
            &mut counts,
            persist_art_metadata_fact(
                job,
                source,
                raw,
                art,
                rule,
                &namespace,
                &key,
                value,
                &rule_value_type(rule),
                &relation,
                &direction,
            )?,
        );
    }
    Ok(counts)
}

fn apply_raw_metadata_values(
    job: &Value,
    source: &Value,
    raw: &Value,
    rule: &Value,
    values: Vec<Value>,
    art_index: Option<&NormalizerArtIndex>,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    for value in values.into_iter().flat_map(expand_metadata_value) {
        if is_empty_value(&value) {
            continue;
        }
        let namespace = value_text(rule, "namespace");
        let key = value_text(rule, "key");
        if namespace.is_empty() || key.is_empty() {
            continue;
        }
        let relation = first_non_empty(&[value_text(rule, "relation"), "evidenced_by".to_string()]);
        merge_ingestion_counts(
            &mut counts,
            persist_raw_metadata_fact(
                job,
                source,
                raw,
                rule,
                &namespace,
                &key,
                value,
                &rule_value_type(rule),
                &relation,
                art_index,
            )?,
        );
    }
    Ok(counts)
}

fn apply_author_metadata_values(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    rule: &Value,
    values: Vec<Value>,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    for value in values.into_iter().flat_map(expand_metadata_value) {
        if is_empty_value(&value) {
            continue;
        }
        let namespace = value_text(rule, "namespace");
        let key = value_text(rule, "key");
        if namespace.is_empty() || key.is_empty() {
            continue;
        }
        merge_ingestion_counts(
            &mut counts,
            persist_author_metadata_fact(
                job,
                source,
                raw,
                author,
                &namespace,
                &key,
                value,
                &rule_value_type(rule),
            )?,
        );
    }
    Ok(counts)
}

fn expand_metadata_value(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items,
        other => vec![other],
    }
}

fn rule_value_type(rule: &Value) -> String {
    let configured = value_text(rule, "value_type");
    if configured.is_empty() {
        "string".to_string()
    } else {
        configured
    }
}

fn rule_origin(rule: &Value, fallback: &str) -> String {
    let id = value_text(rule, "id");
    if id.is_empty() {
        fallback.to_string()
    } else {
        format!("normalizer.rule.{id}")
    }
}

fn values_for_path(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: Option<&Value>,
    author: Option<&Value>,
    path: &str,
) -> Vec<Value> {
    let path = path.trim();
    if path.is_empty() {
        return Vec::new();
    }
    let Some((root, rest)) = path.split_once('.') else {
        return Vec::new();
    };
    let root_value = match root {
        "job" => job,
        "source" => source,
        "raw" => raw,
        "art" => art.unwrap_or(&Value::Null),
        "author" => author.unwrap_or(&Value::Null),
        _ => return Vec::new(),
    };
    values_at_path(root_value, rest)
}

fn values_for_rule_fields(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: Option<&Value>,
    author: Option<&Value>,
    rule: &Value,
) -> Vec<Value> {
    let fields = rule
        .get("fields")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![value_text(rule, "field")]);
    let mut values = Vec::new();
    for field in fields {
        values.extend(values_for_path(job, source, raw, art, author, &field));
    }
    values
}

fn text_for_rule_fields(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: Option<&Value>,
    author: Option<&Value>,
    rule: &Value,
) -> String {
    values_for_rule_fields(job, source, raw, art, author, rule)
        .into_iter()
        .filter_map(|value| scalar_text(&value))
        .collect::<Vec<_>>()
        .join("\n")
}

fn values_at_path(value: &Value, path: &str) -> Vec<Value> {
    let mut current = vec![value];
    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }
        let mut next = Vec::new();
        for value in current {
            match value {
                Value::Array(items) => {
                    for item in items {
                        if let Some(child) = item.get(segment) {
                            next.push(child);
                        }
                    }
                }
                Value::Object(map) => {
                    if let Some(child) = map.get(segment) {
                        match child {
                            Value::Array(items) => next.extend(items.iter()),
                            Value::Null => {}
                            other => next.push(other),
                        }
                    }
                }
                _ => {}
            }
        }
        current = next;
        if current.is_empty() {
            break;
        }
    }
    current
        .into_iter()
        .flat_map(|value| match value {
            Value::Array(items) => items.clone(),
            Value::Null => Vec::new(),
            other => vec![other.clone()],
        })
        .collect()
}

fn apply_rule_transform(rule: &Value, values: Vec<Value>) -> Vec<Value> {
    match value_text(rule, "transform").as_str() {
        "email_domain" => values
            .into_iter()
            .filter_map(|value| scalar_text(&value))
            .filter_map(|email| {
                email
                    .split_once('@')
                    .map(|(_, domain)| domain.trim().to_lowercase())
            })
            .filter(|domain| !domain.is_empty())
            .map(Value::String)
            .collect(),
        "lower" => values
            .into_iter()
            .filter_map(|value| scalar_text(&value))
            .map(|value| json!(value.to_lowercase()))
            .collect(),
        "component_from_path" => values
            .into_iter()
            .filter_map(|value| scalar_text(&value))
            .filter_map(|path| component_from_path(&path))
            .map(Value::String)
            .collect(),
        _ => values,
    }
}

fn extract_named_values(extractor: &str, text: &str) -> Vec<Value> {
    match extractor {
        "cve" => extract_cves(text).into_iter().map(Value::String).collect(),
        "ghsa" => extract_ghsas(text).into_iter().map(Value::String).collect(),
        "gerrit_change_id" | "change_id" => extract_gerrit_change_ids(text)
            .into_iter()
            .map(Value::String)
            .collect(),
        "issue_reference" => extract_issue_references(text),
        "file_path" => extract_file_paths(text)
            .into_iter()
            .map(Value::String)
            .collect(),
        "component" | "component_from_path" => extract_file_paths(text)
            .into_iter()
            .filter_map(|path| component_from_path(&path))
            .map(Value::String)
            .collect(),
        "security_terms" => extract_security_terms(text)
            .into_iter()
            .map(|(term, category)| json!({ "term": term, "category": category }))
            .collect(),
        "gerrit_vote" | "gerrit_approval" => extract_gerrit_votes(text),
        "path_classification" | "file_role" => extract_path_classifications(text),
        "email_domain" => text
            .split_whitespace()
            .filter_map(|email| {
                email
                    .split_once('@')
                    .map(|(_, domain)| domain.trim().to_lowercase())
            })
            .filter(|domain| !domain.is_empty())
            .map(Value::String)
            .collect(),
        _ => Vec::new(),
    }
}

fn apply_review_concern_rule(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    art: &Value,
    rule: &Value,
) -> Result<IngestionCounts, ApiError> {
    let automated = art
        .get("automated")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| value_text(art, "automated") == "true");
    if automated && !bool_flag(rule, "include_automated", false) {
        return Ok(IngestionCounts::default());
    }

    let text = text_for_rule_fields(job, source, raw, Some(art), Some(author), rule);
    if text.trim().is_empty() {
        return Ok(IngestionCounts::default());
    }
    let lower = text.to_lowercase();
    let concern_matches = review_language_matches(
        rule,
        "concern_terms",
        default_review_concern_terms(),
        &lower,
    );
    let response_matches = review_language_matches(
        rule,
        "response_terms",
        default_review_response_terms(),
        &lower,
    );
    if concern_matches.is_empty() && response_matches.is_empty() {
        return Ok(IngestionCounts::default());
    }

    let concern_types = review_match_types(&concern_matches);
    let response_types = review_match_types(&response_matches);
    let concern_score = review_match_weight_sum(&concern_matches);
    let response_score = review_match_weight_sum(&response_matches);
    let vocabulary_version =
        value_i64(rule.get("vocabulary_version").unwrap_or(&Value::Null)).max(7);
    let patch_set = value_i64(art.get("patch_set").unwrap_or(&Value::Null))
        .max(gerrit_patch_set_from_text(&text));
    let value = json!({
        "rule_id": value_text(rule, "id"),
        "vocabulary_version": vocabulary_version,
        "is_concern": !concern_matches.is_empty(),
        "is_response": !response_matches.is_empty(),
        "concern_terms": concern_matches,
        "concern_types": concern_types,
        "concern_score": concern_score,
        "response_terms": response_matches,
        "response_types": response_types,
        "response_score": response_score,
        "patch_set": patch_set,
        "file_path": value_text(art, "file_path"),
        "author_id": value_text(art, "author_id"),
        "message_kind": value_text(art, "review_message_kind"),
        "automated": automated,
        "created_at": first_non_empty(&[
            value_text(art, "source_created_at"),
            value_text(art, "source_updated_at"),
            value_text(raw, "fetched_at")
        ])
    });
    persist_art_metadata_fact(
        job,
        source,
        raw,
        art,
        rule,
        &first_non_empty(&[value_text(rule, "namespace"), "review.concern".to_string()]),
        &first_non_empty(&[value_text(rule, "key"), "signal".to_string()]),
        value,
        "object",
        &first_non_empty(&[value_text(rule, "relation"), "describes".to_string()]),
        &first_non_empty(&[value_text(rule, "direction"), "metadata_to_art".to_string()]),
    )
}

fn review_language_matches(
    rule: &Value,
    field: &str,
    defaults: &[(&str, &str, i64)],
    lower_text: &str,
) -> Vec<Value> {
    let specs = review_language_specs(rule, field, defaults);
    let mut seen = BTreeSet::<String>::new();
    let mut matches = Vec::new();
    for (term, kind, weight) in specs {
        let normalized = term.to_lowercase();
        if normalized.is_empty() || !lower_text.contains(&normalized) {
            continue;
        }
        let key = format!("{kind}|{normalized}");
        if seen.insert(key) {
            matches.push(json!({
                "term": term,
                "type": kind,
                "weight": weight
            }));
        }
    }
    matches
}

fn review_language_specs(
    rule: &Value,
    field: &str,
    defaults: &[(&str, &str, i64)],
) -> Vec<(String, String, i64)> {
    if let Some(items) = rule.get(field).and_then(Value::as_array) {
        return items
            .iter()
            .filter_map(|item| match item {
                Value::String(term) => Some((term.clone(), "general".to_string(), 1)),
                Value::Object(_) => {
                    let term = value_text(item, "term");
                    if term.is_empty() {
                        return None;
                    }
                    let kind = first_non_empty(&[
                        value_text(item, "type"),
                        value_text(item, "kind"),
                        value_text(item, "category"),
                        "general".to_string(),
                    ]);
                    let weight = value_i64(item.get("weight").unwrap_or(&Value::Null)).max(1);
                    Some((term, kind, weight))
                }
                _ => None,
            })
            .collect();
    }
    defaults
        .iter()
        .map(|(term, kind, weight)| (term.to_string(), kind.to_string(), *weight))
        .collect()
}

fn review_match_types(matches: &[Value]) -> Vec<Value> {
    let mut types = BTreeSet::<String>::new();
    for item in matches {
        let kind = first_non_empty(&[
            value_text(item, "type"),
            value_text(item, "kind"),
            value_text(item, "category"),
        ]);
        if !kind.is_empty() {
            types.insert(kind);
        }
    }
    types.into_iter().map(Value::String).collect()
}

fn review_match_weight_sum(matches: &[Value]) -> i64 {
    matches
        .iter()
        .map(|item| value_i64(item.get("weight").unwrap_or(&Value::Null)).max(1))
        .sum()
}

fn default_review_concern_terms() -> &'static [(&'static str, &'static str, i64)] {
    &[
        ("bug", "bug_fix_issue", 1),
        ("issue", "bug_fix_issue", 1),
        ("fix", "bug_fix_issue", 1),
        ("break", "failure_regression", 1),
        ("broken", "failure_regression", 1),
        ("regress", "failure_regression", 1),
        ("fail", "failure_regression", 1),
        ("failure", "failure_regression", 1),
        ("error", "failure_regression", 1),
        ("exception", "failure_regression", 1),
        ("crash", "failure_regression", 1),
        ("flaky", "failure_regression", 1),
        ("hang", "failure_regression", 1),
        ("lost", "failure_regression", 1),
        ("loss", "failure_regression", 1),
        ("wrong", "correctness", 8),
        ("incorrect", "correctness", 8),
        ("mistake", "correctness", 8),
        ("bogus", "correctness", 8),
        ("misleading", "correctness", 8),
        ("flawed", "correctness", 8),
        ("nonsense", "correctness", 8),
        ("questionable", "correctness", 8),
        ("suspect", "correctness", 8),
        ("suspicious", "correctness", 8),
        ("doubt", "correctness", 8),
        ("concern", "correctness", 8),
        ("problem", "correctness", 8),
        ("unsafe", "security_access", 7),
        ("security", "security_access", 7),
        ("vulnerab", "security_access", 7),
        ("bypass", "security_access", 7),
        ("permission", "security_access", 7),
        ("privilege", "security_access", 7),
        ("leak", "security_access", 7),
        ("credential", "privacy_secrets", 10),
        ("credentials", "privacy_secrets", 10),
        ("encrypted", "privacy_secrets", 10),
        ("ssl", "privacy_secrets", 10),
        ("tls", "privacy_secrets", 10),
        ("signature", "privacy_secrets", 10),
        ("signed", "privacy_secrets", 10),
        ("secret", "privacy_secrets", 10),
        ("token", "privacy_secrets", 10),
        ("password", "privacy_secrets", 10),
        ("private", "privacy_secrets", 10),
        ("key", "privacy_secrets", 10),
        ("weird", "surprise_smell", 7),
        ("odd", "surprise_smell", 7),
        ("strange", "surprise_smell", 7),
        ("worrying", "surprise_smell", 7),
        ("worrisome", "surprise_smell", 7),
        ("dangerous", "surprise_smell", 7),
        ("risky", "surprise_smell", 7),
        ("fishy", "surprise_smell", 7),
        ("sketchy", "surprise_smell", 7),
        ("unexpected", "surprise_smell", 7),
        ("surprising", "surprise_smell", 7),
        ("unclear", "confusion", 6),
        ("confusing", "confusion", 6),
        ("confused", "confusion", 6),
        ("confusion", "confusion", 6),
        ("brittle", "maintainability_refactor", 2),
        ("fragile", "maintainability_refactor", 2),
        ("fragility", "maintainability_refactor", 2),
        ("complicated", "maintainability_refactor", 2),
        ("complex", "maintainability_refactor", 2),
        ("complexity", "maintainability_refactor", 2),
        ("convoluted", "maintainability_refactor", 2),
        ("messy", "maintainability_refactor", 2),
        ("ugly", "maintainability_refactor", 2),
        ("awkward", "maintainability_refactor", 2),
        ("overkill", "maintainability_refactor", 2),
        ("hack", "maintainability_refactor", 2),
        ("hacky", "maintainability_refactor", 2),
        ("workaround", "maintainability_refactor", 2),
        ("kludge", "maintainability_refactor", 2),
        ("duplicate", "maintainability_refactor", 2),
        ("duplication", "maintainability_refactor", 2),
        ("maintain", "maintainability_refactor", 2),
        ("readability", "maintainability_refactor", 2),
        ("readable", "maintainability_refactor", 2),
        ("refactor", "maintainability_refactor", 2),
        ("simplify", "maintainability_refactor", 2),
        ("cleanup", "maintainability_refactor", 2),
        ("inconsisten", "consistency", 6),
    ]
}

fn default_review_response_terms() -> &'static [(&'static str, &'static str, i64)] {
    &[
        ("fix", "fix_response", 2),
        ("fixed", "fix_response", 2),
        ("updated", "update_response", 2),
        ("agree", "agreement", 1),
        ("done", "fix_response", 2),
        ("address", "fix_response", 2),
        ("reworked", "rework_response", 3),
        ("changed", "update_response", 2),
        ("added", "update_response", 1),
        ("removed", "update_response", 1),
        ("explain", "explanation", 1),
        ("because", "explanation", 1),
        ("reason", "explanation", 1),
        ("follow-up", "followup", 1),
        ("follow up", "followup", 1),
        ("will", "planned_change", 1),
        ("rebased", "rebase", 1),
        ("tested", "test_response", 2),
        ("covered", "test_response", 2),
    ]
}

fn persist_author_metadata_fact(
    job: &Value,
    source: &Value,
    raw: &Value,
    author: &Value,
    namespace: &str,
    key: &str,
    value: Value,
    value_type: &str,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let author_id = value_text(author, "id");
    let metadata = persist_metadata_fact(
        job,
        source,
        raw,
        "author",
        &author_id,
        namespace,
        key,
        value,
        value_type,
        first_non_empty(&[
            value_text(author, "first_seen_at"),
            value_text(raw, "fetched_at"),
            now_timestamp(),
        ]),
    )?;
    counts.metadata += 1;
    persist_relationship(
        job,
        source,
        raw,
        "metadata",
        &value_text(&metadata, "id"),
        "about_author",
        "author",
        &author_id,
        "",
        &value_text(&metadata, "id"),
        "normalizer.author_metadata.v1",
    )?;
    counts.relationships += 1;
    Ok(counts)
}

fn persist_art_metadata_fact(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: &Value,
    rule: &Value,
    namespace: &str,
    key: &str,
    value: Value,
    value_type: &str,
    relation: &str,
    direction: &str,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let art_id = value_text(art, "id");
    let metadata_value = value.clone();
    let metadata = persist_metadata_fact(
        job,
        source,
        raw,
        "art",
        &art_id,
        namespace,
        key,
        value,
        value_type,
        first_non_empty(&[
            value_text(art, "source_created_at"),
            value_text(raw, "fetched_at"),
            now_timestamp(),
        ]),
    )?;
    counts.metadata += 1;
    let metadata_id = value_text(&metadata, "id");
    let (from_type, from_id, to_type, to_id) = if direction == "art_to_metadata" {
        ("art", art_id.as_str(), "metadata", metadata_id.as_str())
    } else {
        ("metadata", metadata_id.as_str(), "art", art_id.as_str())
    };
    persist_relationship(
        job,
        source,
        raw,
        from_type,
        from_id,
        relation,
        to_type,
        to_id,
        &art_id,
        &metadata_id,
        "normalizer.art_metadata.v1",
    )?;
    counts.relationships += 1;
    counts.relationships += persist_configured_metadata_author_links(
        job,
        source,
        raw,
        Some(art),
        &metadata_id,
        &metadata_value,
        rule,
    )?;
    merge_ingestion_counts(
        &mut counts,
        persist_configured_metadata_links(
            job,
            source,
            raw,
            Some(art),
            &metadata_id,
            &metadata_value,
            "art",
            &art_id,
            rule,
        )?,
    );
    Ok(counts)
}

fn persist_raw_metadata_fact(
    job: &Value,
    source: &Value,
    raw: &Value,
    rule: &Value,
    namespace: &str,
    key: &str,
    value: Value,
    value_type: &str,
    relation: &str,
    art_index: Option<&NormalizerArtIndex>,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let raw_id = value_text(raw, "id");
    let metadata_value = value.clone();
    let metadata = persist_metadata_fact(
        job,
        source,
        raw,
        "raw_record",
        &raw_id,
        namespace,
        key,
        value,
        value_type,
        first_non_empty(&[value_text(raw, "fetched_at"), now_timestamp()]),
    )?;
    counts.metadata += 1;

    let metadata_id = value_text(&metadata, "id");
    let raw_arts = if let Some(index) = art_index {
        index.by_raw(&raw_id)
    } else {
        arts_for_raw(&raw_id)?
    };
    for art in raw_arts {
        let art_id = value_text(&art, "id");
        if art_id.is_empty() {
            continue;
        }
        persist_relationship(
            job,
            source,
            raw,
            "metadata",
            &metadata_id,
            relation,
            "art",
            &art_id,
            &art_id,
            &metadata_id,
            "normalizer.raw_metadata.v1",
        )?;
        counts.relationships += 1;
    }
    counts.relationships += persist_configured_metadata_author_links(
        job,
        source,
        raw,
        None,
        &metadata_id,
        &metadata_value,
        rule,
    )?;
    merge_ingestion_counts(
        &mut counts,
        persist_configured_metadata_links(
            job,
            source,
            raw,
            None,
            &metadata_id,
            &metadata_value,
            "raw_record",
            &raw_id,
            rule,
        )?,
    );
    Ok(counts)
}

fn apply_gerrit_implementation_risk_rules(
    job: &Value,
    source: &Value,
    raw: &Value,
    art_index: Option<&NormalizerArtIndex>,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    if job_param_bool(job, "skip_implementation_risk", false)
        || job_param_bool(job, "skip_review_risk", false)
    {
        return Ok(counts);
    }
    let Some(normalizer) = resolve_normalizer(job, source)? else {
        return Ok(counts);
    };
    if normalizer_processing_is_current(
        job,
        source,
        raw,
        "gerrit_implementation_risk",
        raw,
        &normalizer,
    )? {
        return Ok(counts);
    }
    if existing_gerrit_implementation_risk_signals(source, raw, &normalizer)? {
        persist_normalizer_processing_marker(
            job,
            source,
            raw,
            "gerrit_implementation_risk",
            raw,
            &normalizer,
        )?;
        return Ok(counts);
    }
    for rule in normalizer_rules(&normalizer, "raw_rules") {
        if value_text(&rule, "primitive") != "gerrit_implementation_risk"
            || !rule_applies_to_raw(&rule, raw)
        {
            continue;
        }
        merge_ingestion_counts(
            &mut counts,
            apply_gerrit_implementation_risk_rule(job, source, raw, &rule, art_index)?,
        );
    }
    if counts.metadata > 0 {
        persist_normalizer_processing_marker(
            job,
            source,
            raw,
            "gerrit_implementation_risk",
            raw,
            &normalizer,
        )?;
    }
    Ok(counts)
}

fn existing_gerrit_implementation_risk_signals(
    source: &Value,
    raw: &Value,
    normalizer: &Value,
) -> Result<bool, ApiError> {
    for rule in normalizer_rules(normalizer, "raw_rules") {
        if value_text(&rule, "primitive") != "gerrit_implementation_risk"
            || !rule_applies_to_raw(&rule, raw)
        {
            continue;
        }
        let namespace = first_non_empty(&[
            value_text(&rule, "namespace"),
            "review.implementation_risk".to_string(),
        ]);
        if current_raw_metadata_fact_exists(source, raw, &namespace, "signals")? {
            return Ok(true);
        }
    }
    Ok(false)
}

struct GerritImplementationRiskMessage {
    author_id: String,
    body: String,
    body_lower: String,
    patch_set: i64,
    file_path: String,
    automated: bool,
    kind: String,
    concern: Option<Value>,
    votes: Vec<Value>,
}

fn apply_gerrit_implementation_risk_rule(
    job: &Value,
    source: &Value,
    raw: &Value,
    rule: &Value,
    art_index: Option<&NormalizerArtIndex>,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    if job_param_bool(job, "skip_implementation_risk", false)
        || job_param_bool(job, "skip_review_risk", false)
    {
        return Ok(counts);
    }
    if value_text(source, "provider") != "gerrit"
        || value_text(raw, "record_type") != "gerrit_change"
    {
        return Ok(counts);
    }

    let change_number = raw
        .pointer("/payload/_number")
        .and_then(scalar_text)
        .unwrap_or_default();
    let raw_arts = gerrit_arts_for_change(raw, art_index)?;
    let messages = gerrit_implementation_risk_messages(raw_arts, art_index)?;
    if messages.is_empty() {
        return Ok(counts);
    }

    let owner_account_id = raw
        .pointer("/payload/owner/_account_id")
        .and_then(scalar_text)
        .unwrap_or_default();
    let owner_author_id =
        find_author_id_for_external_ref(source, "gerrit", &owner_account_id)?.unwrap_or_default();
    let changed_files = gerrit_changed_file_paths(raw);
    let touched_file_count = changed_files.len().max(1);
    let changed_lines =
        raw_payload_i64(raw, "insertions").saturating_add(raw_payload_i64(raw, "deletions"));
    let human_messages: Vec<&GerritImplementationRiskMessage> = messages
        .iter()
        .filter(|message| gerrit_message_is_human_review_signal(message))
        .collect();
    let concern_messages: Vec<&GerritImplementationRiskMessage> = human_messages
        .iter()
        .copied()
        .filter(|message| {
            (owner_author_id.is_empty() || message.author_id != owner_author_id)
                && gerrit_message_is_concern_signal(message)
        })
        .collect();
    let concern_count = concern_messages.len() as i64;
    let implementation_signal_score = concern_messages
        .iter()
        .map(|message| gerrit_message_concern_score(message))
        .sum::<i64>();
    let mut concern_file_counts = BTreeMap::<String, i64>::new();
    for message in &concern_messages {
        if gerrit_review_file_path_is_real(&message.file_path) {
            *concern_file_counts
                .entry(message.file_path.clone())
                .or_default() += 1;
        }
    }
    let repeated_concern_file_count = concern_file_counts
        .values()
        .filter(|count| **count >= 2)
        .count() as i64;
    let security_sensitive_repeated_concern_file_count = concern_file_counts
        .iter()
        .filter(|(path, count)| {
            **count >= 2
                && classify_path_roles(path)
                    .iter()
                    .any(|role| *role == "security_sensitive")
        })
        .count() as i64;
    let concern_density = round_decimal(concern_count as f64 / touched_file_count as f64, 3);
    let max_patch_set = human_messages
        .iter()
        .map(|message| message.patch_set)
        .max()
        .unwrap_or(0);
    let concern_patch_sets = concern_messages
        .iter()
        .map(|message| message.patch_set)
        .filter(|patch_set| *patch_set > 0)
        .collect::<BTreeSet<_>>();
    let first_concern_patch_set = concern_patch_sets.iter().next().copied().unwrap_or(0);
    let last_concern_patch_set = concern_patch_sets.iter().next_back().copied().unwrap_or(0);
    let distinct_concern_patch_sets = concern_patch_sets.len() as i64;
    let concern_span_patch_sets = if first_concern_patch_set > 0 {
        last_concern_patch_set.saturating_sub(first_concern_patch_set)
    } else {
        0
    };
    let first_positive_vote_patch_set = messages
        .iter()
        .filter(|message| !message.automated)
        .filter(|message| gerrit_message_has_positive_vote(message))
        .map(|message| message.patch_set)
        .filter(|patch_set| *patch_set > 0)
        .min()
        .unwrap_or(0);
    let concerns_after_positive_vote = if first_positive_vote_patch_set > 0 {
        concern_messages
            .iter()
            .filter(|message| message.patch_set >= first_positive_vote_patch_set)
            .count() as i64
    } else {
        0
    };
    let mut reviewers_after_first_concern = BTreeSet::<String>::new();
    let mut author_responses_after_concern = 0i64;
    if first_concern_patch_set > 0 {
        for message in &human_messages {
            if message.patch_set < first_concern_patch_set {
                continue;
            }
            if !owner_author_id.is_empty() && message.author_id == owner_author_id {
                if gerrit_message_is_author_response_signal(message) {
                    author_responses_after_concern += 1;
                }
            } else if !message.author_id.is_empty() {
                reviewers_after_first_concern.insert(message.author_id.clone());
            }
        }
    }
    let author_response_ratio = if concern_count > 0 {
        round_decimal(
            author_responses_after_concern as f64 / concern_count as f64,
            3,
        )
    } else {
        0.0
    };
    let reviewer_spread_after_first_concern = reviewers_after_first_concern.len() as i64;
    let patch_sets_after_first_concern = if first_concern_patch_set > 0 {
        max_patch_set.saturating_sub(first_concern_patch_set)
    } else {
        0
    };
    let small_change_high_friction = changed_lines <= 100
        && (concern_count >= 3
            || concern_density >= 1.5
            || (repeated_concern_file_count > 0 && patch_sets_after_first_concern >= 2));

    let namespace = first_non_empty(&[
        value_text(rule, "namespace"),
        "review.implementation_risk".to_string(),
    ]);
    let source_time = first_non_empty(&[value_text(raw, "fetched_at"), now_timestamp()]);
    let summary = json!({
        "rule_id": value_text(rule, "id"),
        "change_number": change_number,
        "human_message_count": human_messages.len() as i64,
        "concern_message_count": concern_count,
        "touched_file_count": touched_file_count as i64,
        "changed_lines": changed_lines,
        "concern_density_per_touched_file": concern_density,
        "repeated_concern_file_count": repeated_concern_file_count,
        "author_responses_after_first_concern": author_responses_after_concern,
        "author_response_ratio": author_response_ratio,
        "reviewer_spread_after_first_concern": reviewer_spread_after_first_concern,
        "first_concern_patch_set": first_concern_patch_set,
        "last_concern_patch_set": last_concern_patch_set,
        "distinct_concern_patch_sets": distinct_concern_patch_sets,
        "concern_span_patch_sets": concern_span_patch_sets,
        "first_positive_vote_patch_set": first_positive_vote_patch_set,
        "concerns_after_positive_vote": concerns_after_positive_vote,
        "max_patch_set": max_patch_set,
        "patch_sets_after_first_concern": patch_sets_after_first_concern,
        "security_sensitive_repeated_concern_file_count": security_sensitive_repeated_concern_file_count,
        "small_change_high_friction": small_change_high_friction,
        "implementation_signal_score": implementation_signal_score,
        "concern_files": concern_file_counts,
        "owner_account_id": owner_account_id,
        "owner_author_id": owner_author_id
    });
    for (key, value, value_type) in [
        ("signals", summary, "object"),
        (
            "concern_density_per_touched_file",
            json!(concern_density),
            "number",
        ),
        ("concern_message_count", json!(concern_count), "number"),
        (
            "repeated_concern_file_count",
            json!(repeated_concern_file_count),
            "number",
        ),
        (
            "author_response_ratio",
            json!(author_response_ratio),
            "number",
        ),
        (
            "reviewer_spread_after_first_concern",
            json!(reviewer_spread_after_first_concern),
            "number",
        ),
        (
            "patch_sets_after_first_concern",
            json!(patch_sets_after_first_concern),
            "number",
        ),
        (
            "distinct_concern_patch_sets",
            json!(distinct_concern_patch_sets),
            "number",
        ),
        (
            "last_concern_patch_set",
            json!(last_concern_patch_set),
            "number",
        ),
        (
            "concern_span_patch_sets",
            json!(concern_span_patch_sets),
            "number",
        ),
        (
            "concerns_after_positive_vote",
            json!(concerns_after_positive_vote),
            "number",
        ),
        (
            "security_sensitive_repeated_concern_file_count",
            json!(security_sensitive_repeated_concern_file_count),
            "number",
        ),
        (
            "small_change_high_friction",
            json!(small_change_high_friction),
            "boolean",
        ),
        (
            "implementation_signal_score",
            json!(implementation_signal_score),
            "number",
        ),
    ] {
        persist_current_raw_metadata_fact(
            job,
            source,
            raw,
            &namespace,
            key,
            value,
            value_type,
            source_time.clone(),
        )?;
        counts.metadata += 1;
    }
    Ok(counts)
}

fn gerrit_implementation_risk_messages(
    arts: Vec<Value>,
    art_index: Option<&NormalizerArtIndex>,
) -> Result<Vec<GerritImplementationRiskMessage>, ApiError> {
    let art_ids = arts
        .iter()
        .map(|art| value_text(art, "id"))
        .filter(|art_id| !art_id.is_empty())
        .collect::<BTreeSet<_>>();
    let owned_signal_index = if art_index.is_none() {
        Some(review_metadata_index_for_art_ids(&art_ids)?)
    } else {
        None
    };
    let signal_index = art_index.or(owned_signal_index.as_ref());
    let mut messages = Vec::new();
    for art in arts {
        if value_text(&art, "type") != "code_review_message" {
            continue;
        }
        let art_id = value_text(&art, "id");
        let body = value_text(&art, "body");
        if body.trim().is_empty() {
            continue;
        }
        let patch_set = value_i64(art.get("patch_set").unwrap_or(&Value::Null))
            .max(gerrit_patch_set_from_text(&body));
        messages.push(GerritImplementationRiskMessage {
            author_id: value_text(&art, "author_id"),
            body_lower: body.to_lowercase(),
            body,
            patch_set,
            file_path: value_text(&art, "file_path"),
            automated: art
                .get("automated")
                .and_then(Value::as_bool)
                .unwrap_or_else(|| value_text(&art, "automated") == "true"),
            kind: value_text(&art, "review_message_kind"),
            concern: signal_index.and_then(|index| index.review_concern(&art_id)),
            votes: signal_index
                .map(|index| index.review_votes(&art_id))
                .unwrap_or_default(),
        });
    }
    Ok(messages)
}

fn review_metadata_index_for_art_ids(
    art_ids: &BTreeSet<String>,
) -> Result<NormalizerArtIndex, ApiError> {
    let mut index = NormalizerArtIndex::default();
    if art_ids.is_empty() {
        return Ok(index);
    }

    let metadata_rows = if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        let ids = art_ids.iter().cloned().collect::<Vec<_>>();
        with_postgres_client(|client| {
            client
                .query(
                    r#"
                    SELECT doc
                    FROM repointel_records
                    WHERE collection = 'metadata'
                      AND doc->>'subject_type' = 'art'
                      AND doc->>'subject_id' = ANY($1)
                    "#,
                    &[&ids],
                )
                .map_err(|err| {
                    ApiError::internal(format!("failed reading art metadata index: {err}"))
                })
        })?
        .into_iter()
        .map(|row| {
            let doc: PgJson<Value> = row.get(0);
            doc.0
        })
        .collect::<Vec<_>>()
    } else {
        read_collection("metadata")?
            .into_iter()
            .filter(|metadata| {
                value_text(metadata, "subject_type") == "art"
                    && art_ids.contains(&value_text(metadata, "subject_id"))
            })
            .collect::<Vec<_>>()
    };

    for metadata in metadata_rows {
        if value_text(&metadata, "subject_type") != "art" {
            continue;
        }
        if art_ids.contains(&value_text(&metadata, "subject_id")) {
            index.add_metadata(metadata);
        }
    }
    Ok(index)
}

fn gerrit_arts_for_change(
    raw: &Value,
    art_index: Option<&NormalizerArtIndex>,
) -> Result<Vec<Value>, ApiError> {
    let raw_id = value_text(raw, "id");
    let source_id = value_text(raw, "source_id");
    let change_number = raw
        .pointer("/payload/_number")
        .and_then(scalar_text)
        .unwrap_or_default();
    let mut seen = BTreeSet::<String>::new();
    let mut arts = Vec::new();
    let mut push_if_match = |art: Value| {
        let art_id = value_text(&art, "id");
        if art_id.is_empty() || !seen.insert(art_id) {
            return;
        }
        let matches_raw = value_text(&art, "raw_record_id") == raw_id;
        let matches_change = !change_number.is_empty()
            && value_text(&art, "type") == "code_review_message"
            && value_text(&art, "context_external_id") == change_number;
        if matches_raw || matches_change {
            arts.push(art);
        }
    };

    if let Some(index) = art_index {
        for art in index.by_raw(&raw_id) {
            push_if_match(art);
        }
        if !change_number.is_empty() {
            for art in index.by_gerrit_change(&change_number) {
                push_if_match(art);
            }
        }
        return Ok(arts);
    }

    let art_rows = if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        with_postgres_client(|client| {
            client
                .query(
                    r#"
                    SELECT doc
                    FROM repointel_records
                    WHERE collection = 'arts'
                      AND (
                        doc->>'raw_record_id' = $1
                        OR (
                          $2 <> ''
                          AND doc->>'source_id' = $3
                          AND doc->>'type' = 'code_review_message'
                          AND doc->>'context_external_id' = $2
                        )
                      )
                    "#,
                    &[&raw_id, &change_number, &source_id],
                )
                .map_err(|err| {
                    ApiError::internal(format!("failed reading gerrit arts for change: {err}"))
                })
        })?
        .into_iter()
        .map(|row| {
            let doc: PgJson<Value> = row.get(0);
            doc.0
        })
        .collect::<Vec<_>>()
    } else {
        read_collection("arts")?
    };

    for art in art_rows {
        push_if_match(art);
    }
    Ok(arts)
}

fn gerrit_message_is_human_review_signal(message: &GerritImplementationRiskMessage) -> bool {
    !message.automated && message.kind != "change_subject" && !message.body.trim().is_empty()
}

fn gerrit_message_is_concern_signal(message: &GerritImplementationRiskMessage) -> bool {
    if let Some(concern) = &message.concern {
        if concern
            .get("is_concern")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return true;
        }
        if value_i64(concern.get("concern_score").unwrap_or(&Value::Null)) > 0 {
            return true;
        }
    }
    gerrit_message_has_concern_signal(&message.body_lower)
}

fn gerrit_message_concern_score(message: &GerritImplementationRiskMessage) -> i64 {
    if let Some(concern) = &message.concern {
        let score = value_i64(concern.get("concern_score").unwrap_or(&Value::Null));
        if score > 0 {
            return score;
        }
    }
    default_review_concern_terms()
        .iter()
        .filter(|(term, _, _)| message.body_lower.contains(term))
        .map(|(_, _, weight)| *weight)
        .sum()
}

fn gerrit_message_is_author_response_signal(message: &GerritImplementationRiskMessage) -> bool {
    if let Some(concern) = &message.concern {
        if concern
            .get("is_response")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return true;
        }
        if value_i64(concern.get("response_score").unwrap_or(&Value::Null)) > 0 {
            return true;
        }
    }
    gerrit_message_has_author_response_signal(&message.body_lower)
}

fn gerrit_message_has_positive_vote(message: &GerritImplementationRiskMessage) -> bool {
    if message.votes.iter().any(gerrit_vote_is_positive) {
        return true;
    }
    extract_gerrit_votes(&message.body)
        .iter()
        .any(gerrit_vote_is_positive)
}

fn gerrit_vote_is_positive(vote: &Value) -> bool {
    value_text(vote, "action") == "vote" && value_i64(vote.get("value").unwrap_or(&Value::Null)) > 0
}

fn gerrit_message_has_concern_signal(body_lower: &str) -> bool {
    default_review_concern_terms()
        .iter()
        .any(|(term, _, _)| body_lower.contains(term))
}

fn gerrit_message_has_author_response_signal(body_lower: &str) -> bool {
    const TERMS: &[&str] = &[
        "fix",
        "fixed",
        "updated",
        "agree",
        "done",
        "address",
        "reworked",
        "changed",
        "added",
        "removed",
        "explain",
        "because",
        "reason",
        "follow-up",
        "follow up",
        "will",
        "should",
        "rebased",
        "tested",
        "covered",
    ];
    TERMS.iter().any(|term| body_lower.contains(term))
}

fn gerrit_patch_set_from_text(text: &str) -> i64 {
    let lower = text.to_lowercase();
    let Some(index) = lower.find("patch set ") else {
        return 0;
    };
    let mut digits = String::new();
    for ch in lower[index + "patch set ".len()..].chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else if !digits.is_empty() {
            break;
        } else if !ch.is_whitespace() {
            break;
        }
    }
    digits.parse::<i64>().unwrap_or(0)
}

fn gerrit_changed_file_paths(raw: &Value) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let payload = raw.get("payload").unwrap_or(&Value::Null);
    if let Some(items) = payload.get("changed_files").and_then(Value::as_array) {
        for item in items {
            if let Some(path) = scalar_text(item) {
                if gerrit_review_file_path_is_real(&path) {
                    paths.insert(path);
                }
            }
        }
    }
    if let Some(items) = payload.get("files").and_then(Value::as_array) {
        for item in items {
            let path = value_text(item, "path");
            if gerrit_review_file_path_is_real(&path) {
                paths.insert(path);
            }
        }
    }
    if let Some(files) = payload.get("files").and_then(Value::as_object) {
        for path in files.keys() {
            if gerrit_review_file_path_is_real(path) {
                paths.insert(path.clone());
            }
        }
    }
    let file_path = value_text(payload, "file_path");
    if gerrit_review_file_path_is_real(&file_path) {
        paths.insert(file_path);
    }
    paths
}

fn gerrit_review_file_path_is_real(path: &str) -> bool {
    !path.trim().is_empty() && path != "/PATCHSET_LEVEL" && path != "/COMMIT_MSG"
}

fn raw_payload_i64(raw: &Value, key: &str) -> i64 {
    raw.get("payload")
        .and_then(|payload| payload.get(key))
        .map(value_i64)
        .unwrap_or(0)
}

fn round_decimal(value: f64, places: i32) -> f64 {
    let factor = 10_f64.powi(places);
    (value * factor).round() / factor
}

fn persist_current_raw_metadata_fact(
    job: &Value,
    source: &Value,
    raw: &Value,
    namespace: &str,
    key: &str,
    value: Value,
    value_type: &str,
    source_time: String,
) -> Result<Value, ApiError> {
    let id = current_raw_metadata_fact_id(source, raw, namespace, key);
    let repository_id = value_text(source, "repository_id");
    let source_id = value_text(source, "id");
    let raw_record_id = value_text(raw, "id");
    upsert_record(
        "metadata",
        &json!({
            "id": id,
            "repository_id": repository_id,
            "source_id": source_id,
            "ingestion_job_id": value_text(job, "id"),
            "raw_record_id": raw_record_id,
            "subject_type": "raw_record",
            "subject_id": raw_record_id,
            "namespace": namespace,
            "key": key,
            "value": value,
            "value_type": value_type,
            "source_created_at": source_time,
            "source_updated_at": now_timestamp()
        }),
    )
}

fn current_raw_metadata_fact_exists(
    source: &Value,
    raw: &Value,
    namespace: &str,
    key: &str,
) -> Result<bool, ApiError> {
    let id = current_raw_metadata_fact_id(source, raw, namespace, key);
    if id.is_empty() {
        return Ok(false);
    }
    Ok(get_record("metadata", &id).is_ok())
}

fn current_raw_metadata_fact_id(source: &Value, raw: &Value, namespace: &str, key: &str) -> String {
    let repository_id = value_text(source, "repository_id");
    let source_id = value_text(source, "id");
    let raw_record_id = value_text(raw, "id");
    if repository_id.is_empty() || source_id.is_empty() || raw_record_id.is_empty() {
        return String::new();
    }
    format!(
        "metadata-{}",
        stable_hash(&format!(
            "{repository_id}|{source_id}|raw_record|{raw_record_id}|{namespace}|{key}|current"
        ))
    )
}

fn persist_configured_metadata_links(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: Option<&Value>,
    metadata_id: &str,
    metadata_value: &Value,
    current_subject_type: &str,
    current_subject_id: &str,
    rule: &Value,
) -> Result<IngestionCounts, ApiError> {
    let mut counts = IngestionCounts::default();
    let Some(links) = rule.get("metadata_links").and_then(Value::as_array) else {
        return Ok(counts);
    };

    for link in links {
        let namespace = value_text(link, "target_namespace");
        let key = value_text(link, "target_key");
        if namespace.is_empty() || key.is_empty() {
            continue;
        }
        let relation = first_non_empty(&[value_text(link, "relation"), "related_to".to_string()]);
        let value_type =
            first_non_empty(&[value_text(link, "target_value_type"), "string".to_string()]);
        let target_subject_type = first_non_empty(&[
            value_text(link, "target_subject_type"),
            if bool_flag(link, "target_canonical", false) {
                "canonical".to_string()
            } else {
                current_subject_type.to_string()
            },
        ]);
        let direction =
            first_non_empty(&[value_text(link, "direction"), "this_to_target".to_string()]);
        let origin = first_non_empty(&[
            value_text(link, "origin"),
            format!("{}.metadata_link", rule_origin(rule, "normalizer.rule")),
        ]);

        for target_value in metadata_link_target_values(job, source, raw, art, metadata_value, link)
        {
            if is_empty_value(&target_value) {
                continue;
            }
            let target_subject_id = metadata_link_subject_id(
                link,
                &target_subject_type,
                current_subject_id,
                &namespace,
                &key,
                &target_value,
            );
            if target_subject_id.is_empty() {
                continue;
            }
            let target = persist_metadata_fact(
                job,
                source,
                raw,
                &target_subject_type,
                &target_subject_id,
                &namespace,
                &key,
                target_value,
                &value_type,
                first_non_empty(&[
                    art.map(|art| value_text(art, "source_created_at"))
                        .unwrap_or_default(),
                    value_text(raw, "fetched_at"),
                    now_timestamp(),
                ]),
            )?;
            counts.metadata += 1;
            let target_id = value_text(&target, "id");
            if target_id.is_empty() || target_id == metadata_id {
                continue;
            }
            let (from_id, to_id) = if direction == "target_to_this" {
                (target_id.as_str(), metadata_id)
            } else {
                (metadata_id, target_id.as_str())
            };
            persist_relationship(
                job,
                source,
                raw,
                "metadata",
                from_id,
                &relation,
                "metadata",
                to_id,
                &art.map(|art| value_text(art, "id")).unwrap_or_default(),
                metadata_id,
                &origin,
            )?;
            counts.relationships += 1;
        }
    }
    Ok(counts)
}

fn metadata_link_target_values(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: Option<&Value>,
    metadata_value: &Value,
    link: &Value,
) -> Vec<Value> {
    let mut values = if has_any_key(link, &["target_field", "target_fields"]) {
        values_for_named_fields(
            job,
            source,
            raw,
            art,
            None,
            link,
            "target_field",
            "target_fields",
        )
    } else if !value_text(link, "target_value_path").is_empty() {
        values_at_path(
            metadata_value,
            &strip_value_prefix(&value_text(link, "target_value_path")),
        )
    } else {
        Vec::new()
    };

    let extractor = value_text(link, "target_extractor");
    if !extractor.is_empty() {
        let text = values
            .into_iter()
            .filter_map(|value| scalar_text(&value))
            .collect::<Vec<_>>()
            .join("\n");
        values = extract_named_values(&extractor, &text);
    }

    let target_value_path = value_text(link, "target_value_path");
    if !target_value_path.is_empty() && has_any_key(link, &["target_field", "target_fields"]) {
        let path = strip_value_prefix(&target_value_path);
        values = values
            .into_iter()
            .flat_map(|value| values_at_path(&value, &path))
            .collect();
    }

    let transform = value_text(link, "target_transform");
    if !transform.is_empty() {
        let mut transform_rule = Map::new();
        transform_rule.insert("transform".to_string(), json!(transform));
        values = apply_rule_transform(&Value::Object(transform_rule), values);
    }

    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .flat_map(expand_metadata_value)
        .filter(|value| !is_empty_value(value))
        .filter(|value| seen.insert(canonical_json(value)))
        .collect()
}

fn values_for_named_fields(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: Option<&Value>,
    author: Option<&Value>,
    config: &Value,
    field_key: &str,
    fields_key: &str,
) -> Vec<Value> {
    let fields = config
        .get(fields_key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![value_text(config, field_key)]);
    let mut values = Vec::new();
    for field in fields {
        values.extend(values_for_path(job, source, raw, art, author, &field));
    }
    values
}

fn strip_value_prefix(path: &str) -> String {
    path.strip_prefix("value.")
        .unwrap_or(path)
        .trim()
        .to_string()
}

fn has_any_key(value: &Value, keys: &[&str]) -> bool {
    keys.iter().any(|key| value.get(*key).is_some())
}

fn metadata_link_subject_id(
    link: &Value,
    subject_type: &str,
    current_subject_id: &str,
    namespace: &str,
    key: &str,
    value: &Value,
) -> String {
    let configured = value_text(link, "target_subject_id");
    if !configured.is_empty() {
        return configured;
    }
    if subject_type == "canonical" {
        format!("{namespace}:{key}:{}", canonical_json(value))
    } else {
        current_subject_id.to_string()
    }
}

fn persist_configured_metadata_author_links(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: Option<&Value>,
    metadata_id: &str,
    metadata_value: &Value,
    rule: &Value,
) -> Result<i64, ApiError> {
    let Some(link) = rule.get("author_link") else {
        return Ok(0);
    };
    if !link.is_object() {
        return Ok(0);
    }

    let relation = first_non_empty(&[value_text(link, "relation"), "about_author".to_string()]);
    let mut count = 0;
    let mut linked_author_ids = BTreeSet::new();

    if bool_flag(link, "from_art_author", false) {
        if let Some(art) = art {
            let author_id = value_text(art, "author_id");
            if !author_id.is_empty() && linked_author_ids.insert(author_id.clone()) {
                persist_metadata_author_relationship(
                    job,
                    source,
                    raw,
                    art,
                    metadata_id,
                    &relation,
                    &author_id,
                )?;
                count += 1;
            }
        }
    }

    let value_path = value_text(link, "value_path");
    if !value_path.is_empty() {
        let provider =
            first_non_empty(&[value_text(link, "provider"), value_text(source, "provider")]);
        for author_ref in values_at_path(metadata_value, &value_path)
            .into_iter()
            .filter_map(|value| scalar_text(&value))
        {
            if let Some(author_id) =
                find_author_id_for_external_ref(source, &provider, &author_ref)?
            {
                if linked_author_ids.insert(author_id.clone()) {
                    persist_metadata_author_relationship(
                        job,
                        source,
                        raw,
                        art.unwrap_or(&Value::Null),
                        metadata_id,
                        &relation,
                        &author_id,
                    )?;
                    count += 1;
                }
            }
        }
    }

    Ok(count)
}

fn persist_metadata_author_relationship(
    job: &Value,
    source: &Value,
    raw: &Value,
    art: &Value,
    metadata_id: &str,
    relation: &str,
    author_id: &str,
) -> Result<Value, ApiError> {
    persist_relationship(
        job,
        source,
        raw,
        "metadata",
        metadata_id,
        relation,
        "author",
        author_id,
        &value_text(art, "id"),
        metadata_id,
        "normalizer.metadata_author_link.v1",
    )
}

fn find_author_id_for_external_ref(
    source: &Value,
    provider: &str,
    author_ref: &str,
) -> Result<Option<String>, ApiError> {
    let Some(external_author_id) = normalized_external_author_id(provider, author_ref) else {
        return Ok(None);
    };
    let source_id = value_text(source, "id");
    let repository_id = value_text(source, "repository_id");
    let index = author_external_index()?;
    if let Some(author_id) = index
        .get(&author_source_external_key(&source_id, &external_author_id))
        .or_else(|| {
            index.get(&author_repo_external_key(
                &repository_id,
                &external_author_id,
            ))
        })
        .or_else(|| index.get(&author_external_key(&external_author_id)))
    {
        return Ok(Some(author_id.clone()));
    }

    Ok(None)
}

fn normalized_external_author_id(provider: &str, author_ref: &str) -> Option<String> {
    let author_ref = author_ref.trim().trim_end_matches('/');
    if author_ref.is_empty() {
        return None;
    }
    if author_ref.contains(':') {
        return Some(author_ref.to_string());
    }
    let provider = provider.trim();
    if provider.is_empty() {
        return None;
    }
    Some(format!("{provider}:{author_ref}"))
}

fn author_external_index_cache() -> &'static Mutex<Option<BTreeMap<String, String>>> {
    static CACHE: OnceLock<Mutex<Option<BTreeMap<String, String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

fn author_external_index() -> Result<BTreeMap<String, String>, ApiError> {
    let mut guard = author_external_index_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(index) = guard.clone() {
        return Ok(index);
    }
    let index = build_author_external_index()?;
    *guard = Some(index.clone());
    Ok(index)
}

fn build_author_external_index() -> Result<BTreeMap<String, String>, ApiError> {
    let mut index = BTreeMap::new();
    for author in read_collection("authors")? {
        insert_author_external_mapping(&mut index, &author);
    }
    Ok(index)
}

fn cache_author_external_mapping(author: &Value) {
    let mut guard = author_external_index_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(index) = guard.as_mut() {
        insert_author_external_mapping(index, author);
    }
}

fn insert_author_external_mapping(index: &mut BTreeMap<String, String>, author: &Value) {
    let author_id = value_text(author, "id");
    if author_id.is_empty() {
        return;
    }
    let source_id = value_text(author, "source_id");
    let repository_id = value_text(author, "repository_id");
    let mut external_ids = Vec::new();
    for external_author_id in [
        value_text(author, "external_author_id"),
        value_text(author, "external_key"),
    ] {
        if !external_author_id.is_empty() {
            external_ids.push(external_author_id);
        }
    }
    let email = value_text(author, "email").trim().to_ascii_lowercase();
    if !email.is_empty() {
        external_ids.push(email.clone());
        external_ids.push(format!("git:{email}"));
    }

    for external_author_id in external_ids {
        insert_author_external_id_mapping(
            index,
            &author_id,
            &source_id,
            &repository_id,
            &external_author_id,
        );
    }
}

fn insert_author_external_id_mapping(
    index: &mut BTreeMap<String, String>,
    author_id: &str,
    source_id: &str,
    repository_id: &str,
    external_author_id: &str,
) {
    if !source_id.is_empty() {
        index.insert(
            author_source_external_key(&source_id, &external_author_id),
            author_id.to_string(),
        );
    }
    if !repository_id.is_empty() {
        index.insert(
            author_repo_external_key(&repository_id, &external_author_id),
            author_id.to_string(),
        );
    }
    index.insert(
        author_external_key(&external_author_id),
        author_id.to_string(),
    );
}

fn author_source_external_key(source_id: &str, external_author_id: &str) -> String {
    format!("source:{source_id}|external:{external_author_id}")
}

fn author_repo_external_key(repository_id: &str, external_author_id: &str) -> String {
    format!("repository:{repository_id}|external:{external_author_id}")
}

fn author_external_key(external_author_id: &str) -> String {
    format!("external:{external_author_id}")
}

#[derive(Default)]
struct NormalizerArtIndex {
    by_raw_record_id: BTreeMap<String, Vec<Value>>,
    by_gerrit_change_number: BTreeMap<String, Vec<Value>>,
    review_concern_by_art_id: BTreeMap<String, Value>,
    review_votes_by_art_id: BTreeMap<String, Vec<Value>>,
}

impl NormalizerArtIndex {
    fn add(&mut self, art: Value) {
        let raw_record_id = value_text(&art, "raw_record_id");
        if !raw_record_id.is_empty() {
            self.by_raw_record_id
                .entry(raw_record_id)
                .or_default()
                .push(art.clone());
        }
        let change_number = value_text(&art, "context_external_id");
        if value_text(&art, "type") == "code_review_message" && !change_number.is_empty() {
            self.by_gerrit_change_number
                .entry(change_number)
                .or_default()
                .push(art);
        }
    }

    fn by_raw(&self, raw_record_id: &str) -> Vec<Value> {
        self.by_raw_record_id
            .get(raw_record_id)
            .cloned()
            .unwrap_or_default()
    }

    fn by_gerrit_change(&self, change_number: &str) -> Vec<Value> {
        self.by_gerrit_change_number
            .get(change_number)
            .cloned()
            .unwrap_or_default()
    }

    fn add_metadata(&mut self, metadata: Value) {
        if value_text(&metadata, "subject_type") != "art" {
            return;
        }
        let art_id = value_text(&metadata, "subject_id");
        if art_id.is_empty() {
            return;
        }
        let namespace = value_text(&metadata, "namespace");
        let key = value_text(&metadata, "key");
        if namespace == "review.concern" && key == "signal" {
            if let Some(value) = metadata.get("value") {
                if value_i64(value.get("vocabulary_version").unwrap_or(&Value::Null)) >= 7 {
                    self.review_concern_by_art_id.insert(art_id, value.clone());
                }
            }
        } else if namespace == "review.approval" && key == "vote" {
            if let Some(value) = metadata.get("value") {
                self.review_votes_by_art_id
                    .entry(art_id)
                    .or_default()
                    .push(value.clone());
            }
        }
    }

    fn review_concern(&self, art_id: &str) -> Option<Value> {
        self.review_concern_by_art_id.get(art_id).cloned()
    }

    fn review_votes(&self, art_id: &str) -> Vec<Value> {
        self.review_votes_by_art_id
            .get(art_id)
            .cloned()
            .unwrap_or_default()
    }
}

fn normalizer_art_index() -> Result<NormalizerArtIndex, ApiError> {
    let mut index = NormalizerArtIndex::default();
    for art in read_collection("arts")? {
        index.add(art);
    }
    for metadata in read_collection("metadata")? {
        index.add_metadata(metadata);
    }
    Ok(index)
}

fn arts_for_raw(raw_record_id: &str) -> Result<Vec<Value>, ApiError> {
    if raw_record_id.is_empty() {
        return Ok(Vec::new());
    }
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        let rows = with_postgres_client(|client| {
            client
                .query(
                    r#"
                    SELECT doc
                    FROM repointel_records
                    WHERE collection = 'arts'
                      AND doc->>'raw_record_id' = $1
                    "#,
                    &[&raw_record_id],
                )
                .map_err(|err| {
                    ApiError::internal(format!("failed reading arts for raw record: {err}"))
                })
        })?;
        return Ok(rows
            .into_iter()
            .map(|row| {
                let doc: PgJson<Value> = row.get(0);
                doc.0
            })
            .collect());
    }
    let mut arts = read_collection("arts")?;
    arts.retain(|art| value_text(art, "raw_record_id") == raw_record_id);
    Ok(arts)
}

fn persist_metadata_fact(
    job: &Value,
    source: &Value,
    raw: &Value,
    subject_type: &str,
    subject_id: &str,
    namespace: &str,
    key: &str,
    value: Value,
    value_type: &str,
    source_time: String,
) -> Result<Value, ApiError> {
    if subject_id.is_empty() || is_empty_value(&value) {
        return Err(ApiError::bad_request(
            "metadata subject_id and value are required",
        ));
    }
    let repository_id = value_text(source, "repository_id");
    let source_id = value_text(source, "id");
    let identity_source_id = if subject_type == "canonical" {
        ""
    } else {
        source_id.as_str()
    };
    let raw_record_id = value_text(raw, "id");
    let canonical = canonical_json(&value);
    let id = format!(
        "metadata-{}",
        stable_hash(&format!(
            "{repository_id}|{identity_source_id}|{subject_type}|{subject_id}|{namespace}|{key}|{canonical}"
        ))
    );
    upsert_record(
        "metadata",
        &json!({
            "id": id,
            "repository_id": repository_id,
            "source_id": source_id,
            "ingestion_job_id": value_text(job, "id"),
            "raw_record_id": raw_record_id,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "namespace": namespace,
            "key": key,
            "value": value,
            "value_type": value_type,
            "source_created_at": source_time,
            "source_updated_at": source_time
        }),
    )
}

fn persist_relationship(
    job: &Value,
    source: &Value,
    raw: &Value,
    from_type: &str,
    from_id: &str,
    relation: &str,
    to_type: &str,
    to_id: &str,
    evidence_art_id: &str,
    evidence_metadata_id: &str,
    origin: &str,
) -> Result<Value, ApiError> {
    if from_id.is_empty() || to_id.is_empty() {
        return Err(ApiError::bad_request("relationship endpoints require ids"));
    }
    let repository_id = value_text(source, "repository_id");
    let source_id = value_text(source, "id");
    let raw_record_id = value_text(raw, "id");
    let id = format!(
        "relationship-{}",
        stable_hash(&format!(
            "{repository_id}|{source_id}|{from_type}|{from_id}|{relation}|{to_type}|{to_id}|{origin}"
        ))
    );
    upsert_record(
        "relationships",
        &json!({
            "id": id,
            "repository_id": repository_id,
            "source_id": source_id,
            "ingestion_job_id": value_text(job, "id"),
            "raw_record_id": raw_record_id,
            "from_type": from_type,
            "from_id": from_id,
            "to_type": to_type,
            "to_id": to_id,
            "relation": relation,
            "direction": "forward",
            "confidence": 1.0,
            "evidence_art_id": evidence_art_id,
            "evidence_metadata_id": evidence_metadata_id,
            "origin": origin
        }),
    )
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_default()
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut ordered = BTreeMap::new();
            for (key, value) in map {
                ordered.insert(key.clone(), canonical_json(value));
            }
            ordered
                .into_iter()
                .map(|(key, value)| format!("{key}:{value}"))
                .collect::<Vec<_>>()
                .join("|")
        }
        Value::Array(items) => items
            .iter()
            .map(canonical_json)
            .collect::<Vec<_>>()
            .join("|"),
        _ => value.to_string(),
    }
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|token| {
            token
                .trim_matches(|ch: char| {
                    matches!(
                        ch,
                        ',' | '.'
                            | ';'
                            | ':'
                            | '!'
                            | '?'
                            | '('
                            | ')'
                            | '['
                            | ']'
                            | '{'
                            | '}'
                            | '<'
                            | '>'
                            | '"'
                            | '\''
                            | '`'
                    )
                })
                .to_string()
        })
        .filter(|token| !token.is_empty())
        .collect()
}

fn extract_cves(text: &str) -> Vec<String> {
    let mut values = BTreeSet::new();
    for token in normalized_tokens(text) {
        let upper = token.to_uppercase();
        let parts = upper.split('-').collect::<Vec<_>>();
        if parts.len() == 3
            && parts[0] == "CVE"
            && parts[1].len() == 4
            && parts[1].chars().all(|ch| ch.is_ascii_digit())
            && (4..=7).contains(&parts[2].len())
            && parts[2].chars().all(|ch| ch.is_ascii_digit())
        {
            values.insert(upper);
        }
    }
    values.into_iter().take(20).collect()
}

fn extract_ghsas(text: &str) -> Vec<String> {
    let mut values = BTreeSet::new();
    for token in normalized_tokens(text) {
        let upper = token.to_uppercase();
        let parts = upper.split('-').collect::<Vec<_>>();
        if parts.len() == 4
            && parts[0] == "GHSA"
            && parts[1..]
                .iter()
                .all(|part| part.len() == 4 && part.chars().all(|ch| ch.is_ascii_alphanumeric()))
        {
            values.insert(upper);
        }
    }
    values.into_iter().take(20).collect()
}

fn extract_gerrit_change_ids(text: &str) -> Vec<String> {
    let mut values = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some((label, value)) = trimmed.split_once(':') else {
            continue;
        };
        if label.eq_ignore_ascii_case("change-id") {
            let change_id = value.trim();
            if change_id.starts_with('I')
                && change_id.len() >= 12
                && change_id[1..].chars().all(|ch| ch.is_ascii_hexdigit())
            {
                values.insert(change_id.to_string());
            }
        }
    }
    values.into_iter().take(20).collect()
}

fn extract_issue_references(text: &str) -> Vec<Value> {
    let lower = text.to_lowercase();
    if ![
        "fixes",
        "closes",
        "related-bug",
        "partial-bug",
        "bug",
        "lp:",
        "story",
        "task",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return Vec::new();
    }
    let mut refs = BTreeSet::new();
    let tokens = normalized_tokens(text);
    for (index, token) in tokens.iter().enumerate() {
        if let Some(number) = token
            .strip_prefix('#')
            .filter(|s| is_reasonable_issue_id(s))
        {
            let verb = index
                .checked_sub(1)
                .and_then(|idx| tokens.get(idx))
                .cloned()
                .unwrap_or_default();
            refs.insert(format!("local|{number}|{verb}"));
        }
        let normalized = token.trim_end_matches(',');
        if is_reasonable_issue_id(normalized)
            && index
                .checked_sub(1)
                .and_then(|idx| tokens.get(idx))
                .map(|previous| {
                    matches!(
                        previous.to_lowercase().as_str(),
                        "bug" | "lp" | "story" | "task" | "fixes" | "closes"
                    )
                })
                .unwrap_or(false)
        {
            let verb = tokens
                .get(index.saturating_sub(1))
                .cloned()
                .unwrap_or_default();
            refs.insert(format!("local|{normalized}|{verb}"));
        }
    }
    refs.into_iter()
        .take(30)
        .map(|raw| {
            let parts = raw.split('|').collect::<Vec<_>>();
            json!({
                "id": parts.get(1).copied().unwrap_or_default(),
                "scheme": parts.first().copied().unwrap_or("local"),
                "verb": parts.get(2).copied().unwrap_or_default()
            })
        })
        .collect()
}

fn extract_gerrit_votes(text: &str) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    for token in normalized_tokens(text) {
        if let Some(value) = gerrit_vote_from_token(&token) {
            let key = value.to_string();
            if seen.insert(key) {
                values.push(value);
            }
        }
    }
    values.into_iter().take(50).collect()
}

fn gerrit_vote_from_token(token: &str) -> Option<Value> {
    let token = token.trim_matches(|ch: char| matches!(ch, '*' | ':' | ',' | ';'));
    if token.is_empty() {
        return None;
    }
    if let Some(label) = token.strip_prefix('-') {
        if matches!(label, "Code-Review" | "Workflow" | "Verified") {
            return Some(json!({
                "label": label,
                "label_key": label.to_lowercase().replace('-', "_"),
                "value": 0,
                "action": "removed",
                "raw": token
            }));
        }
    }
    for label in ["Code-Review", "Workflow", "Verified"] {
        if let Some(suffix) = token.strip_prefix(label) {
            let mut chars = suffix.chars();
            let sign = chars.next()?;
            let digits = chars.as_str();
            if matches!(sign, '+' | '-')
                && !digits.is_empty()
                && digits.chars().all(|ch| ch.is_ascii_digit())
            {
                let magnitude = digits.parse::<i64>().ok()?;
                let value = if sign == '-' { -magnitude } else { magnitude };
                return Some(json!({
                    "label": label,
                    "label_key": label.to_lowercase().replace('-', "_"),
                    "value": value,
                    "action": "vote",
                    "raw": token
                }));
            }
        }
    }
    None
}

fn is_reasonable_issue_id(value: &str) -> bool {
    (2..=10).contains(&value.len()) && value.chars().all(|ch| ch.is_ascii_digit())
}

fn extract_security_terms(text: &str) -> Vec<(&'static str, &'static str)> {
    let lower = text.to_lowercase();
    let terms = [
        ("authorization bypass", "suspected_security_fix"),
        ("authentication bypass", "suspected_security_fix"),
        ("privilege escalation", "suspected_security_fix"),
        ("tenant isolation", "isolation"),
        ("project isolation", "isolation"),
        ("credential exposure", "credential"),
        ("credential", "credential"),
        ("token", "credential"),
        ("secret", "credential"),
        ("password", "credential"),
        ("cve-", "vulnerability_identifier"),
        ("ghsa-", "vulnerability_identifier"),
        ("vulnerability", "vulnerability"),
        ("security fix", "suspected_security_fix"),
        ("security bug", "suspected_security_fix"),
        ("security issue", "suspected_security_fix"),
        ("ssrf", "web_vulnerability"),
        ("xss", "web_vulnerability"),
        ("sql injection", "web_vulnerability"),
        ("path traversal", "web_vulnerability"),
        ("pickle", "unsafe_deserialization"),
        ("unmarshal", "unsafe_deserialization"),
        ("deserialization", "unsafe_deserialization"),
        ("encryption", "crypto"),
        ("decryption", "crypto"),
        ("signature", "crypto"),
        ("permission", "authorization"),
        ("policy", "authorization"),
        ("rbac", "authorization"),
        ("acl", "authorization"),
        ("auth", "authorization"),
    ];
    let mut matches = BTreeSet::new();
    for (term, category) in terms {
        if lower.contains(term) {
            matches.insert((term, category));
        }
    }
    matches.into_iter().take(20).collect()
}

fn extract_file_paths(text: &str) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for token in normalized_tokens(text) {
        let clean = token
            .trim_matches(|ch: char| matches!(ch, ',' | '.' | ':' | ';' | ')' | '(' | '`'))
            .trim_start_matches("a/")
            .trim_start_matches("b/")
            .to_string();
        let lower = clean.to_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            continue;
        }
        if clean.contains('/')
            && [
                ".py", ".yaml", ".yml", ".json", ".rst", ".txt", ".conf", ".ini", ".sh", ".go",
                ".rs", ".js", ".ts",
            ]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
        {
            paths.insert(clean);
        }
    }
    paths.into_iter().take(30).collect()
}

fn component_from_path(path: &str) -> Option<String> {
    let parts = path
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "swift")
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }
    let component = if parts.len() >= 2 {
        format!("{}/{}", parts[0], parts[1])
    } else {
        parts[0].to_string()
    };
    Some(component)
}

fn extract_path_classifications(text: &str) -> Vec<Value> {
    let mut values = BTreeSet::<(String, String)>::new();
    for path in extract_file_paths(text)
        .into_iter()
        .chain(text.lines().map(str::trim).map(str::to_string))
    {
        let path = path
            .trim_matches(|ch: char| matches!(ch, ',' | ';' | ':' | ')' | '(' | '`' | '"'))
            .trim_start_matches("a/")
            .trim_start_matches("b/")
            .to_string();
        if path.is_empty() || !looks_like_path_candidate(&path) {
            continue;
        }
        for role in classify_path_roles(&path) {
            values.insert((path.clone(), role.to_string()));
        }
    }
    values
        .into_iter()
        .map(|(path, role)| json!({ "path": path, "role": role }))
        .collect()
}

fn looks_like_path_candidate(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains('/')
        || matches!(
            lower.as_str(),
            "codeowners"
                | ".zuul.yaml"
                | ".gitlab-ci.yml"
                | ".pre-commit-config.yaml"
                | ".gitreview"
                | "tox.ini"
                | "requirements.txt"
                | "test-requirements.txt"
                | "lower-constraints.txt"
                | "upper-constraints.txt"
                | "setup.py"
                | "setup.cfg"
                | "pyproject.toml"
                | "pipfile"
                | "poetry.lock"
                | "package.json"
                | "package-lock.json"
                | "yarn.lock"
                | "go.mod"
                | "go.sum"
                | "cargo.toml"
                | "cargo.lock"
        )
}

fn classify_path_roles(path: &str) -> Vec<&'static str> {
    let lower = path.to_lowercase();
    let mut roles = Vec::new();
    if lower.contains("/api/")
        || lower.contains("/middleware/")
        || lower.contains("/server")
        || lower.contains("/proxy/")
        || lower.contains("wsgi")
        || lower.contains("router")
        || lower.contains("controller")
        || lower.contains("request")
        || lower.contains("upload")
        || lower.contains("webhook")
        || lower.contains("rpc")
    {
        roles.push("attack_surface");
    }
    if lower.contains("auth")
        || lower.contains("acl")
        || lower.contains("policy")
        || lower.contains("credential")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("crypto")
        || lower.contains("encrypt")
        || lower.contains("decrypt")
        || lower.contains("signature")
        || lower.contains("keymaster")
        || lower.contains("tempurl")
        || lower.contains("s3api")
    {
        roles.push("security_sensitive");
    }
    if lower.contains(".github/workflows/")
        || lower.ends_with(".github/workflows")
        || lower.ends_with(".zuul.yaml")
        || lower.contains("zuul.d/")
        || lower.ends_with(".gitlab-ci.yml")
        || lower.ends_with("tox.ini")
        || lower.contains("/ci/")
    {
        roles.push("cicd_workflow");
    }
    if lower.ends_with("codeowners")
        || lower.contains("/codeowners")
        || lower.contains("branch-protection")
        || lower.contains("dependabot")
        || lower.contains("renovate")
        || lower.ends_with(".pre-commit-config.yaml")
        || lower.ends_with(".gitreview")
    {
        roles.push("repository_control");
    }
    if lower.contains("requirements")
        || lower.contains("constraints")
        || lower.ends_with("setup.py")
        || lower.ends_with("setup.cfg")
        || lower.ends_with("pyproject.toml")
        || lower.ends_with("pipfile")
        || lower.ends_with("poetry.lock")
        || lower.ends_with("package.json")
        || lower.ends_with("package-lock.json")
        || lower.ends_with("yarn.lock")
        || lower.ends_with("go.mod")
        || lower.ends_with("go.sum")
        || lower.ends_with("cargo.toml")
        || lower.ends_with("cargo.lock")
    {
        roles.push("dependency_manifest");
    }
    if lower.contains("releasenotes/")
        || lower.contains("stable/")
        || lower.contains("backport")
        || lower.contains("cherry")
        || lower.contains("branch")
    {
        roles.push("fix_propagation");
    }
    roles.sort_unstable();
    roles.dedup();
    roles
}

fn log_ingestion(
    job: &Value,
    stage: &str,
    level: &str,
    message: &str,
    details: Value,
) -> Result<Value, ApiError> {
    create_record(
        "ingestion-logs",
        &json!({
            "repository_id": value_text(job, "repository_id"),
            "source_id": value_text(job, "source_id"),
            "ingestion_job_id": value_text(job, "id"),
            "stage": stage,
            "level": level,
            "message": message,
            "event_type": stage,
            "details": details
        }),
    )
}

fn fetch_json(url: &str) -> Result<Value, ApiError> {
    let max_attempts = env::var("REPOINTEL_PROVIDER_FETCH_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(5)
        .clamp(1, 10);
    let mut last_error = String::new();
    for attempt in 1..=max_attempts {
        match fetch_json_once(url) {
            Ok(value) => return Ok(value),
            Err(message) => {
                last_error = message;
                if attempt == max_attempts {
                    break;
                }
                let delay_secs = provider_fetch_backoff_secs(attempt);
                thread::sleep(Duration::from_secs(delay_secs));
            }
        }
    }
    Err(ApiError::provider(format!(
        "GET {url} failed after {max_attempts} attempts: {}",
        compact_log_text(&last_error, 500)
    )))
}

fn provider_fetch_backoff_secs(attempt: usize) -> u64 {
    let base = env::var("REPOINTEL_PROVIDER_FETCH_BACKOFF_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(2)
        .clamp(1, 60);
    let factor = 1_u64 << attempt.saturating_sub(1).min(5);
    base.saturating_mul(factor).min(60)
}

fn fetch_json_once(url: &str) -> Result<Value, String> {
    let max_time = env::var("REPOINTEL_PROVIDER_FETCH_MAX_TIME_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(10, 300)
        .to_string();
    let connect_timeout = env::var("REPOINTEL_PROVIDER_FETCH_CONNECT_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(10)
        .clamp(5, 120)
        .to_string();
    let output = Command::new("curl")
        .arg("-fsSL")
        .arg("--max-time")
        .arg(max_time)
        .arg("--connect-timeout")
        .arg(connect_timeout)
        .arg("-A")
        .arg("repointel-frontplane-ingester/0.1")
        .arg(url)
        .output()
        .map_err(|err| format!("failed to start curl: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(compact_log_text(&stderr, 500));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|err| format!("reading response failed: {err}"))?;
    let trimmed = text.trim_start();
    let json_text = if trimmed.starts_with(")]}'") {
        trimmed.split_once('\n').map(|(_, tail)| tail).unwrap_or("")
    } else {
        trimmed
    };
    serde_json::from_str(json_text).map_err(|err| format!("parsing JSON failed: {err}"))
}

fn git_commit_limit(source: &Value) -> usize {
    source
        .get("ingestion_policy")
        .and_then(|policy| policy.get("limit"))
        .and_then(Value::as_u64)
        .or_else(|| {
            env::var("REPOINTEL_GIT_COMMIT_LIMIT")
                .ok()?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(1000)
        .clamp(1, 100_000) as usize
}

fn git_commit_file_metadata(numstat: &str) -> GitCommitFileMetadata {
    let mut metadata = GitCommitFileMetadata::default();
    let mut seen_paths = BTreeSet::new();
    for line in numstat.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, '\t');
        let added = parts.next().unwrap_or("").trim();
        let deleted = parts.next().unwrap_or("").trim();
        let Some(path) = parts.next().map(normalize_git_numstat_path) else {
            continue;
        };
        if path.is_empty() || !seen_paths.insert(path.clone()) {
            continue;
        }
        let insertions = added.parse::<i64>().ok();
        let deletions = deleted.parse::<i64>().ok();
        let binary = insertions.is_none() || deletions.is_none();
        metadata.insertions += insertions.unwrap_or(0);
        metadata.deletions += deletions.unwrap_or(0);
        if binary {
            metadata.binary_files += 1;
        }
        metadata.changed_files.push(path.clone());
        metadata.files.push(json!({
            "path": path,
            "extension": file_extension(&metadata.changed_files.last().cloned().unwrap_or_default()),
            "insertions": insertions,
            "deletions": deletions,
            "binary": binary
        }));
    }
    metadata
}

fn normalize_git_numstat_path(path: &str) -> String {
    let mut path = path.trim().trim_matches('"').replace("\\t", "\t");
    if let Some((_, new_path)) = path.rsplit_once(" => ") {
        path = new_path.to_string();
    }
    path.trim_start_matches("a/")
        .trim_start_matches("b/")
        .trim_matches(|ch: char| matches!(ch, ',' | ';' | ':' | ')' | '(' | '`' | '"'))
        .to_string()
}

fn file_extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_lowercase()
}

fn git_repo_path(source: &Value) -> Result<String, ApiError> {
    let policy_path = source
        .get("ingestion_policy")
        .and_then(|policy| policy.get("local_path"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let filter_path = source
        .get("ingestion_filters")
        .and_then(|filters| filters.get("local_path"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let env_path = env::var("REPOINTEL_GIT_REPO_PATH").unwrap_or_default();
    let path = [policy_path, filter_path, env_path.as_str()]
        .into_iter()
        .find(|candidate| !candidate.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string();
    if path.is_empty() {
        return Err(ApiError::bad_request(
            "git source requires ingestion_policy.local_path".to_string(),
        ));
    }
    let git_dir = PathBuf::from(&path).join(".git");
    if !git_dir.exists() {
        return Err(ApiError::bad_request(format!(
            "git source local_path {path} does not contain a .git directory"
        )));
    }
    Ok(path)
}

fn git_commit_url(source: &Value, sha: &str) -> String {
    let base = value_text(source, "base_url");
    if base.starts_with("http://") || base.starts_with("https://") {
        format!("{}/commit/{sha}", base.trim_end_matches('/'))
    } else {
        String::new()
    }
}

fn launchpad_bug_limit(source: &Value) -> usize {
    source
        .get("ingestion_policy")
        .and_then(|policy| policy.get("limit"))
        .and_then(Value::as_u64)
        .or_else(|| env::var("REPOINTEL_INGEST_LIMIT").ok()?.parse::<u64>().ok())
        .unwrap_or(1000)
        .clamp(1, 10_000) as usize
}

fn launchpad_search_tasks_url(target: &str, offset: usize, newest_updated_order: bool) -> String {
    let order_by = if newest_updated_order {
        "-date_last_updated"
    } else {
        "-datecreated"
    };
    format!(
        "{}?ws.op=searchTasks&orderby={order_by}&ws.size=100&ws.start={offset}",
        target.trim_end_matches('/'),
    )
}

fn launchpad_updated_at(task: &Value, bug: &Value) -> String {
    for (value, key) in [
        (task, "date_last_updated"),
        (bug, "date_last_updated"),
        (task, "date_updated"),
        (bug, "date_updated"),
        (task, "date_last_message"),
        (bug, "date_last_message"),
        (task, "date_created"),
        (bug, "date_created"),
    ] {
        let timestamp = value_text(value, key);
        if !timestamp.is_empty() {
            return timestamp;
        }
    }
    String::new()
}

fn launchpad_next_collection_link(page: &Value) -> Option<String> {
    for key in ["next_collection_link", "next_link", "next"] {
        let link = value_text(page, key);
        if !link.is_empty() {
            return Some(link);
        }
    }
    None
}

fn launchpad_messages_collection_url(link: &str) -> Option<String> {
    let link = link.trim();
    if link.is_empty() {
        return None;
    }
    if link.contains('?') {
        Some(format!("{link}&ws.size=100"))
    } else {
        Some(format!("{link}?ws.size=100"))
    }
}

fn gerrit_review_limit(job: &Value, source: &Value) -> usize {
    job.get("params")
        .and_then(|params| params.get("review_limit").or_else(|| params.get("limit")))
        .and_then(Value::as_u64)
        .or_else(|| {
            source
                .get("ingestion_policy")
                .and_then(|policy| policy.get("review_limit").or_else(|| policy.get("limit")))
                .and_then(Value::as_u64)
        })
        .or_else(|| {
            env::var("REPOINTEL_GERRIT_REVIEW_LIMIT")
                .ok()?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(1000)
        .clamp(1, 1000) as usize
}

fn gerrit_reviews_per_minute(job: &Value, source: &Value) -> usize {
    job.get("params")
        .and_then(|params| params.get("reviews_per_minute"))
        .and_then(Value::as_u64)
        .or_else(|| {
            source
                .get("ingestion_policy")
                .and_then(|policy| policy.get("reviews_per_minute"))
                .and_then(Value::as_u64)
        })
        .or_else(|| {
            env::var("REPOINTEL_GERRIT_REVIEWS_PER_MINUTE")
                .ok()?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0)
        .min(600) as usize
}

fn gerrit_page_size(job: &Value, source: &Value, reviews_per_minute: usize) -> usize {
    job.get("params")
        .and_then(|params| params.get("page_size"))
        .and_then(Value::as_u64)
        .or_else(|| {
            source
                .get("ingestion_policy")
                .and_then(|policy| policy.get("page_size"))
                .and_then(Value::as_u64)
        })
        .map(|value| value.clamp(1, 100) as usize)
        .unwrap_or_else(|| {
            if reviews_per_minute == 0 {
                100
            } else {
                reviews_per_minute.min(100).max(1)
            }
        })
}

fn gerrit_comments_per_change(job: &Value, source: &Value) -> usize {
    job.get("params")
        .and_then(|params| params.get("comments_per_change"))
        .and_then(Value::as_u64)
        .or_else(|| {
            source
                .get("ingestion_policy")
                .and_then(|policy| policy.get("comments_per_change"))
                .and_then(Value::as_u64)
        })
        .unwrap_or(1000)
        .clamp(0, 10_000) as usize
}

fn gerrit_include_automated_messages(source: &Value) -> bool {
    source
        .get("ingestion_policy")
        .and_then(|policy| policy.get("include_automated_messages"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn is_gerrit_automated_message(message: &Value, body: &str) -> bool {
    let tag = value_text(message, "tag");
    if tag.starts_with("autogenerated:") {
        return true;
    }

    let first_line = body.lines().next().unwrap_or("").trim();
    if first_line.starts_with("Uploaded patch set ")
        || first_line.starts_with("Topic set to ")
        || first_line.starts_with("Change has been successfully")
        || (first_line.starts_with("Patch Set ")
            && (first_line.contains("Workflow") || first_line.contains("Verified")))
    {
        return true;
    }

    let body_lower = body.to_lowercase();
    if body_lower.contains("zuul.opendev.org")
        || body_lower.contains("build succeeded")
        || body_lower.contains("build failed")
        || body_lower.contains("build started")
        || body_lower.contains("buildset")
    {
        return true;
    }

    let author = message.get("author").unwrap_or(&Value::Null);
    let author_name = value_text(author, "name").to_lowercase();
    let author_username = value_text(author, "username").to_lowercase();
    matches!(
        author_name.as_str(),
        "zuul" | "jenkins" | "openstack proposal bot" | "openstack release bot"
    ) || matches!(
        author_username.as_str(),
        "zuul" | "jenkins" | "proposal-bot" | "release-bot"
    )
}

fn is_gerrit_review_summary_only(body: &str) -> bool {
    let lines: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() > 2 {
        return false;
    }
    let Some(first) = lines.first() else {
        return false;
    };
    if !first.starts_with("Patch Set ") {
        return false;
    }
    lines.iter().skip(1).all(|line| {
        (line.starts_with('(') && line.ends_with("comment)"))
            || (line.starts_with('(') && line.ends_with("comments)"))
    })
}

fn throttle_gerrit_review(processed_reviews: i64, reviews_per_minute: usize) {
    if processed_reviews <= 0 || reviews_per_minute == 0 {
        return;
    }
    let delay_ms = (60_000_u64 / reviews_per_minute as u64).max(1);
    thread::sleep(Duration::from_millis(delay_ms));
}

fn url_query_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            b' ' => vec!['+'],
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn list_records(collection: &str, input: &Value) -> Result<Value, ApiError> {
    let mut records = read_collection(collection)?;
    records.sort_by_key(record_sort_key);
    records.retain(|record| record_matches_filter(record, input));
    Ok(page(records, input))
}

fn search_records(collection: &str, input: &Value) -> Result<Value, ApiError> {
    let mut records = read_collection(collection)?;
    let query = text_field(input, "query").to_lowercase();
    records.sort_by_key(record_sort_key);
    records.retain(|record| {
        record_matches_filter(record, input)
            && (query.is_empty() || record.to_string().to_lowercase().contains(&query))
    });
    Ok(page(records, input))
}

fn create_record(collection: &str, input: &Value) -> Result<Value, ApiError> {
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        return create_record_postgres(collection, input);
    }
    let _guard = store_write_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut records = read_collection(collection)?;
    let mut record = object_from(input);
    apply_create_defaults(collection, &mut record);
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

fn update_record(collection: &str, id_key: &str, input: &Value) -> Result<Value, ApiError> {
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        return update_record_postgres(collection, id_key, input);
    }
    let _guard = store_write_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        if key == id_key || key == "id" || value.is_null() {
            continue;
        }
        record.insert(key, value);
    }
    if collection == "relationships" {
        ensure_valid_relationship(&Value::Object(record.clone()))?;
    }
    stamp_update(collection, &mut record);
    records[index] = Value::Object(record.clone());
    write_collection(collection, &records)?;
    Ok(Value::Object(record))
}

fn delete_record(collection: &str, id_key: &str, input: &Value) -> Result<Value, ApiError> {
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        return delete_record_postgres(collection, id_key, input);
    }
    let _guard = store_write_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let id = id_from_input(input, id_key)?;
    let mut records = read_collection(collection)?;
    let before = records.len();
    records.retain(|record| value_text(record, "id") != id);
    if records.len() == before {
        return Err(ApiError::not_found(format!(
            "{collection} record {id} was not found"
        )));
    }
    write_collection(collection, &records)?;
    Ok(json!({ "deleted": true, "id": id }))
}

fn upsert_record(collection: &str, input: &Value) -> Result<Value, ApiError> {
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        return upsert_record_postgres(collection, input);
    }
    let _guard = store_write_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut record = object_from(input);
    apply_create_defaults(collection, &mut record);
    let id = ensure_id(collection, &mut record);
    let mut records = read_collection(collection)?;
    if let Some(index) = records
        .iter()
        .position(|existing| value_text(existing, "id") == id)
    {
        let mut existing = object_from(&records[index]);
        for (key, value) in record {
            if is_empty_value(&value) {
                continue;
            }
            existing.insert(key, value);
        }
        stamp_update(collection, &mut existing);
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

fn create_record_postgres(collection: &str, input: &Value) -> Result<Value, ApiError> {
    let mut record = object_from(input);
    apply_create_defaults(collection, &mut record);
    let id = ensure_id(collection, &mut record);
    let value = Value::Object(record);
    if collection == "relationships" {
        ensure_valid_relationship(&value)?;
    }
    let doc = PgJson(&value);
    let affected = with_postgres_client(|client| {
        client
            .execute(
                r#"
            INSERT INTO repointel_records (collection, id, doc, created_at, updated_at)
            VALUES ($1, $2, $3, now(), now())
            ON CONFLICT (collection, id) DO NOTHING
            "#,
                &[&collection, &id, &doc],
            )
            .map_err(|err| ApiError::internal(format!("failed creating {collection} {id}: {err}")))
    })?;
    if affected == 0 {
        return Err(ApiError::conflict(format!(
            "{collection} record {id} already exists"
        )));
    }
    Ok(value)
}

fn update_record_postgres(
    collection: &str,
    id_key: &str,
    input: &Value,
) -> Result<Value, ApiError> {
    let id = id_from_input(input, id_key)?;
    with_postgres_client(|client| {
        let existing = postgres_get_record(client, collection, &id)?.ok_or_else(|| {
            ApiError::not_found(format!("{collection} record {id} was not found"))
        })?;
        let patch = object_from(input);
        let mut record = object_from(&existing);
        for (key, value) in patch {
            if key == id_key || key == "id" || value.is_null() {
                continue;
            }
            record.insert(key, value);
        }
        if collection == "relationships" {
            ensure_valid_relationship(&Value::Object(record.clone()))?;
        }
        stamp_update(collection, &mut record);
        let value = Value::Object(record);
        let doc = PgJson(&value);
        client
            .execute(
                r#"
                UPDATE repointel_records
                SET doc = $3, updated_at = now()
                WHERE collection = $1 AND id = $2
                "#,
                &[&collection, &id, &doc],
            )
            .map_err(|err| {
                ApiError::internal(format!("failed updating {collection} {id}: {err}"))
            })?;
        Ok(value)
    })
}

fn delete_record_postgres(
    collection: &str,
    id_key: &str,
    input: &Value,
) -> Result<Value, ApiError> {
    let id = id_from_input(input, id_key)?;
    let affected = with_postgres_client(|client| {
        client
            .execute(
                "DELETE FROM repointel_records WHERE collection = $1 AND id = $2",
                &[&collection, &id],
            )
            .map_err(|err| ApiError::internal(format!("failed deleting {collection} {id}: {err}")))
    })?;
    if affected == 0 {
        return Err(ApiError::not_found(format!(
            "{collection} record {id} was not found"
        )));
    }
    Ok(json!({ "deleted": true, "id": id }))
}

fn upsert_record_postgres(collection: &str, input: &Value) -> Result<Value, ApiError> {
    let mut record = object_from(input);
    apply_create_defaults(collection, &mut record);
    let id = ensure_id(collection, &mut record);
    if collection == "relationships" {
        ensure_valid_relationship(&Value::Object(record.clone()))?;
    }
    stamp_update(collection, &mut record);
    let value = Value::Object(record);
    let doc = PgJson(&value);
    let value = with_postgres_client(|client| {
        let row = client
            .query_one(
                r#"
            INSERT INTO repointel_records (collection, id, doc, created_at, updated_at)
            VALUES ($1, $2, $3, now(), now())
            ON CONFLICT (collection, id) DO UPDATE
            SET doc = repointel_records.doc || EXCLUDED.doc,
                updated_at = now()
            RETURNING doc
            "#,
                &[&collection, &id, &doc],
            )
            .map_err(|err| {
                ApiError::internal(format!("failed upserting {collection} {id}: {err}"))
            })?;
        let value: PgJson<Value> = row.get(0);
        Ok(value.0)
    })?;
    Ok(value)
}

fn status_update(
    collection: &str,
    id_key: &str,
    input: &Value,
    status: &str,
) -> Result<Value, ApiError> {
    let mut patch = object_from(input);
    patch.insert("status".to_string(), json!(status));
    if matches!(status, "cancelled" | "complete" | "failed") {
        patch.insert("finished_at".to_string(), json!(now_timestamp()));
    }
    update_record(collection, id_key, &Value::Object(patch))
}

fn queue_ingestion_job(input: &Value) -> Result<Value, ApiError> {
    let mut patch = object_from(input);
    patch.insert("status".to_string(), json!("queued"));
    patch.insert("finished_at".to_string(), json!(""));
    patch.insert("error".to_string(), json!(""));
    let updated = update_record("ingestion-jobs", "ingestion_job_id", &Value::Object(patch))?;
    start_ingestion_worker(value_text(&updated, "id"));
    Ok(updated)
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

fn member_page(
    collection: &str,
    field: &str,
    id_field: &str,
    mode: &str,
    input: &Value,
) -> Result<Value, ApiError> {
    let id = id_from_input(input, id_field)?;
    let mut records = if mode == "relationship_endpoint" {
        relationship_records_for_endpoint(field, &id)?
    } else if mode == "subject_or_relationship_metadata" {
        metadata_for_subject(field, &id)?
    } else {
        let mut items = read_collection(collection)?;
        items.retain(|record| value_text(record, field) == id);
        items
    };
    records.sort_by_key(record_sort_key);
    Ok(page(records, input))
}

fn referenced_record(
    owner_collection: &str,
    owner_id_key: &str,
    input: &Value,
    ref_field: &str,
    target_collection: &str,
) -> Result<Value, ApiError> {
    let owner_id = id_from_input(input, owner_id_key)?;
    let owner = get_record(owner_collection, &owner_id)?;
    let ref_id = value_text(&owner, ref_field);
    if ref_id.is_empty() {
        return Err(ApiError::not_found(format!(
            "{owner_collection} record {owner_id} has no {ref_field}"
        )));
    }
    get_record(target_collection, &ref_id)
}

fn merge_author(input: &Value) -> Result<Value, ApiError> {
    let primary_id = id_from_input(input, "primary_author_id")?;
    let secondary_ids = input
        .get("secondary_author_ids")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut records = read_collection("authors")?;
    for secondary in secondary_ids.iter().filter_map(Value::as_str) {
        if let Some(index) = records
            .iter()
            .position(|record| value_text(record, "id") == secondary)
        {
            let mut author = object_from(&records[index]);
            author.insert("merged_into_author_id".to_string(), json!(primary_id));
            author.insert(
                "merge_reason".to_string(),
                input.get("reason").cloned().unwrap_or(Value::Null),
            );
            stamp_update("authors", &mut author);
            records[index] = Value::Object(author);
        }
    }
    write_collection("authors", &records)?;
    get_record("authors", &primary_id)
}

fn split_author(input: &Value) -> Result<Value, ApiError> {
    let author_id = id_from_input(input, "author_id")?;
    let author = get_record("authors", &author_id)?;
    Ok(page(vec![author], input))
}

fn metadata_subject(input: &Value) -> Result<Value, ApiError> {
    let metadata_id = id_from_input(input, "metadata_id")?;
    let metadata = get_record("metadata", &metadata_id)?;
    let subject_type = value_text(&metadata, "subject_type");
    let subject_id = value_text(&metadata, "subject_id");
    let mut result = Map::new();
    result.insert(
        "subject".to_string(),
        json!({ "type": subject_type, "id": subject_id }),
    );
    if !subject_type.is_empty() && !subject_id.is_empty() {
        if let Some(collection) = collection_for_endpoint(&subject_type) {
            if let Ok(value) = get_record(collection, &subject_id) {
                result.insert(subject_type.clone(), value);
            }
        }
    }
    hydrate_provenance(&metadata, &mut result);
    Ok(Value::Object(result))
}

fn relationship_endpoint(input: &Value, from: bool) -> Result<Value, ApiError> {
    let relationship_id = id_from_input(input, "relationship_id")?;
    let relationship = get_record("relationships", &relationship_id)?;
    let prefix = if from { "from" } else { "to" };
    let endpoint_type = value_text(&relationship, &format!("{prefix}_type"));
    let endpoint_id = value_text(&relationship, &format!("{prefix}_id"));
    let mut result = Map::new();
    result.insert(
        "endpoint".to_string(),
        json!({ "type": endpoint_type, "id": endpoint_id }),
    );
    if let Some(collection) = collection_for_endpoint(&endpoint_type) {
        if let Ok(value) = get_record(collection, &endpoint_id) {
            result.insert(endpoint_type, value);
        }
    }
    Ok(Value::Object(result))
}

fn relationship_evidence(input: &Value) -> Result<Value, ApiError> {
    let relationship_id = id_from_input(input, "relationship_id")?;
    let relationship = get_record("relationships", &relationship_id)?;
    let mut result = Map::new();
    if let Some(value) = maybe_record("arts", &value_text(&relationship, "evidence_art_id")) {
        result.insert("evidence_art".to_string(), value);
    }
    if let Some(value) = maybe_record(
        "metadata",
        &value_text(&relationship, "evidence_metadata_id"),
    ) {
        result.insert("evidence_metadata".to_string(), value);
    }
    if let Some(value) = maybe_record("raw-records", &value_text(&relationship, "raw_record_id")) {
        result.insert("raw_record".to_string(), value);
    }
    result.insert("relationship".to_string(), relationship);
    Ok(Value::Object(result))
}

fn relationship_neighborhood(input: &Value) -> Result<Value, ApiError> {
    let endpoint_type = text_field(input, "endpoint_type");
    let endpoint_id = text_field(input, "endpoint_id");
    let repository_id = text_field(input, "repository_id");
    let relation = text_field(input, "relation");
    let limit = limit(input);
    let mut outgoing = Vec::new();
    let mut incoming = Vec::new();
    for relationship in read_collection("relationships")? {
        if !repository_id.is_empty() && value_text(&relationship, "repository_id") != repository_id
        {
            continue;
        }
        if !relation.is_empty() && value_text(&relationship, "relation") != relation {
            continue;
        }
        if value_text(&relationship, "from_type") == endpoint_type
            && value_text(&relationship, "from_id") == endpoint_id
            && outgoing.len() < limit
        {
            outgoing.push(relationship.clone());
        }
        if value_text(&relationship, "to_type") == endpoint_type
            && value_text(&relationship, "to_id") == endpoint_id
            && incoming.len() < limit
        {
            incoming.push(relationship);
        }
    }
    let mut metadata_ids = BTreeSet::new();
    let mut art_ids = BTreeSet::new();
    let mut author_ids = BTreeSet::new();
    collect_endpoint(
        &endpoint_type,
        &endpoint_id,
        &mut metadata_ids,
        &mut art_ids,
        &mut author_ids,
    );
    for relationship in outgoing.iter().chain(incoming.iter()) {
        collect_endpoint(
            &value_text(relationship, "from_type"),
            &value_text(relationship, "from_id"),
            &mut metadata_ids,
            &mut art_ids,
            &mut author_ids,
        );
        collect_endpoint(
            &value_text(relationship, "to_type"),
            &value_text(relationship, "to_id"),
            &mut metadata_ids,
            &mut art_ids,
            &mut author_ids,
        );
    }
    Ok(json!({
        "center": { "type": endpoint_type, "id": endpoint_id },
        "outgoing": outgoing,
        "incoming": incoming,
        "metadata": if bool_flag(input, "include_metadata", true) { records_by_ids("metadata", &metadata_ids)? } else { Vec::new() },
        "arts": if bool_flag(input, "include_arts", true) { records_by_ids("arts", &art_ids)? } else { Vec::new() },
        "authors": if bool_flag(input, "include_authors", true) { records_by_ids("authors", &author_ids)? } else { Vec::new() }
    }))
}

fn search_relationships(input: &Value) -> Result<Value, ApiError> {
    let mut records = read_collection("relationships")?;
    let include_reverse = bool_flag(input, "include_reverse", false);
    records.retain(|record| relationship_matches_search(record, input, include_reverse));
    records.sort_by_key(record_sort_key);
    Ok(page(records, input))
}

fn relationship_matches_search(record: &Value, input: &Value, include_reverse: bool) -> bool {
    for key in ["repository_id", "source_id", "relation"] {
        let expected = text_field(input, key);
        if !expected.is_empty() && value_text(record, key) != expected {
            return false;
        }
    }
    let endpoint_type = text_field(input, "endpoint_type");
    let endpoint_id = text_field(input, "endpoint_id");
    if !endpoint_type.is_empty() || !endpoint_id.is_empty() {
        let endpoint_match = value_text(record, "from_type") == endpoint_type
            && value_text(record, "from_id") == endpoint_id
            || value_text(record, "to_type") == endpoint_type
                && value_text(record, "to_id") == endpoint_id;
        if !endpoint_match {
            return false;
        }
    }
    let from_type = text_field(input, "from_type");
    let from_id = text_field(input, "from_id");
    let to_type = text_field(input, "to_type");
    let to_id = text_field(input, "to_id");
    if from_type.is_empty() && from_id.is_empty() && to_type.is_empty() && to_id.is_empty() {
        return true;
    }
    let forward = field_matches(record, "from_type", &from_type)
        && field_matches(record, "from_id", &from_id)
        && field_matches(record, "to_type", &to_type)
        && field_matches(record, "to_id", &to_id);
    let reverse = include_reverse
        && field_matches(record, "from_type", &to_type)
        && field_matches(record, "from_id", &to_id)
        && field_matches(record, "to_type", &from_type)
        && field_matches(record, "to_id", &from_id);
    forward || reverse
}

fn field_matches(record: &Value, field: &str, expected: &str) -> bool {
    expected.is_empty() || value_text(record, field) == expected
}

fn relationship_records_for_endpoint(
    endpoint_type: &str,
    endpoint_id: &str,
) -> Result<Vec<Value>, ApiError> {
    let mut records = read_collection("relationships")?;
    records.retain(|record| {
        (value_text(record, "from_type") == endpoint_type
            && value_text(record, "from_id") == endpoint_id)
            || (value_text(record, "to_type") == endpoint_type
                && value_text(record, "to_id") == endpoint_id)
    });
    Ok(records)
}

fn metadata_for_subject(subject_type: &str, subject_id: &str) -> Result<Vec<Value>, ApiError> {
    let mut ids = BTreeSet::new();
    let mut direct = read_collection("metadata")?;
    direct.retain(|record| {
        value_text(record, "subject_type") == subject_type
            && value_text(record, "subject_id") == subject_id
    });
    for item in &direct {
        ids.insert(value_text(item, "id"));
    }
    for relationship in relationship_records_for_endpoint(subject_type, subject_id)? {
        if value_text(&relationship, "from_type") == "metadata" {
            ids.insert(value_text(&relationship, "from_id"));
        }
        if value_text(&relationship, "to_type") == "metadata" {
            ids.insert(value_text(&relationship, "to_id"));
        }
    }
    records_by_ids("metadata", &ids)
}

fn hydrate_provenance(record: &Value, result: &mut Map<String, Value>) {
    if let Some(value) = maybe_record("raw-records", &value_text(record, "raw_record_id")) {
        result.insert("raw_record".to_string(), value);
    }
    if let Some(value) = maybe_record("sources", &value_text(record, "source_id")) {
        result.insert("source".to_string(), value);
    }
    if let Some(repository) = maybe_record("repositories", &value_text(record, "repository_id")) {
        if let Some(group) = maybe_record(
            "repository-groups",
            &value_text(&repository, "repository_group_id"),
        ) {
            result.insert("repository_group".to_string(), group);
        }
        result.insert("repository".to_string(), repository);
    }
    if let Some(value) = maybe_record("ingestion-jobs", &value_text(record, "ingestion_job_id")) {
        result.insert("ingestion_job".to_string(), value);
    }
}

fn maybe_record(collection: &str, id: &str) -> Option<Value> {
    if id.is_empty() {
        return None;
    }
    get_record(collection, id).ok()
}

fn records_by_ids(collection: &str, ids: &BTreeSet<String>) -> Result<Vec<Value>, ApiError> {
    let mut records = read_collection(collection)?;
    records.retain(|record| ids.contains(&value_text(record, "id")));
    records.sort_by_key(record_sort_key);
    Ok(records)
}

fn collect_endpoint(
    endpoint_type: &str,
    endpoint_id: &str,
    metadata_ids: &mut BTreeSet<String>,
    art_ids: &mut BTreeSet<String>,
    author_ids: &mut BTreeSet<String>,
) {
    if endpoint_id.is_empty() {
        return;
    }
    match endpoint_type {
        "metadata" => {
            metadata_ids.insert(endpoint_id.to_string());
        }
        "art" => {
            art_ids.insert(endpoint_id.to_string());
        }
        "author" => {
            author_ids.insert(endpoint_id.to_string());
        }
        _ => {}
    }
}

fn ensure_valid_relationship(input: &Value) -> Result<(), ApiError> {
    let validation = validate_relationship_value(input);
    if validation.get("valid").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        let message = validation
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("invalid relationship");
        Err(ApiError::bad_request(message))
    }
}

fn read_collection(collection: &str) -> Result<Vec<Value>, ApiError> {
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        return read_collection_postgres(collection);
    }
    let path = collection_path(collection)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path)
        .map_err(|err| ApiError::internal(format!("failed reading {}: {err}", path.display())))?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<Value>>(&text)
        .map_err(|err| ApiError::internal(format!("failed parsing {}: {err}", path.display())))
}

fn write_collection(collection: &str, records: &[Value]) -> Result<(), ApiError> {
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        return write_collection_postgres(collection, records);
    }
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

fn read_collection_postgres(collection: &str) -> Result<Vec<Value>, ApiError> {
    if COLLECTIONS.iter().all(|meta| meta.collection != collection) {
        return Err(ApiError::internal(format!(
            "unknown collection {collection}"
        )));
    }
    let query = format!("/* read_collection:{collection} */ SELECT doc FROM repointel_records WHERE collection = $1");
    let rows = with_postgres_client(|client| {
        client
            .query(&query, &[&collection])
            .map_err(|err| ApiError::internal(format!("failed reading {collection}: {err}")))
    })?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let doc: PgJson<Value> = row.get(0);
            doc.0
        })
        .collect())
}

fn write_collection_postgres(collection: &str, records: &[Value]) -> Result<(), ApiError> {
    if COLLECTIONS.iter().all(|meta| meta.collection != collection) {
        return Err(ApiError::internal(format!(
            "unknown collection {collection}"
        )));
    }
    with_postgres_client(|client| {
        let mut transaction = client.transaction().map_err(|err| {
            ApiError::internal(format!(
                "failed starting {collection} replace transaction: {err}"
            ))
        })?;
        transaction
            .execute(
                "DELETE FROM repointel_records WHERE collection = $1",
                &[&collection],
            )
            .map_err(|err| ApiError::internal(format!("failed clearing {collection}: {err}")))?;
        for record in records {
            let id = value_text(record, "id");
            if id.is_empty() {
                continue;
            }
            let doc = PgJson(record);
            transaction
                .execute(
                    r#"
                    INSERT INTO repointel_records (collection, id, doc, created_at, updated_at)
                    VALUES ($1, $2, $3, now(), now())
                    "#,
                    &[&collection, &id, &doc],
                )
                .map_err(|err| {
                    ApiError::internal(format!("failed replacing {collection} record {id}: {err}"))
                })?;
        }
        transaction.commit().map_err(|err| {
            ApiError::internal(format!(
                "failed committing {collection} replace transaction: {err}"
            ))
        })
    })
}

fn postgres_get_record(
    client: &mut Client,
    collection: &str,
    id: &str,
) -> Result<Option<Value>, ApiError> {
    let row = client
        .query_opt(
            "SELECT doc FROM repointel_records WHERE collection = $1 AND id = $2",
            &[&collection, &id],
        )
        .map_err(|err| ApiError::internal(format!("failed reading {collection} {id}: {err}")))?;
    Ok(row.map(|row| {
        let doc: PgJson<Value> = row.get(0);
        doc.0
    }))
}

fn collection_path(collection: &str) -> Result<PathBuf, ApiError> {
    if COLLECTIONS.iter().all(|meta| meta.collection != collection) {
        return Err(ApiError::internal(format!(
            "unknown collection {collection}"
        )));
    }
    let root = env::var("REPOINTEL_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".repointel-data"));
    Ok(root.join(format!("{collection}.json")))
}

fn collection_for_stem(stem: &str) -> Result<CollectionMeta, ApiError> {
    let normalized = stem.replace('-', "_");
    COLLECTIONS
        .iter()
        .copied()
        .find(|meta| {
            normalized == meta.singular
                || normalized == meta.collection.replace('-', "_")
                || normalized == pluralize(meta.singular)
        })
        .ok_or_else(|| ApiError::internal(format!("unknown operation collection stem {stem}")))
}

fn collection_for_endpoint(endpoint_type: &str) -> Option<&'static str> {
    match endpoint_type {
        "metadata" => Some("metadata"),
        "art" => Some("arts"),
        "author" => Some("authors"),
        _ => None,
    }
}

fn pluralize(value: &str) -> String {
    match value {
        "metadata" => "metadata".to_string(),
        "repository_group" => "repository_groups".to_string(),
        "ingestion_job" => "ingestion_jobs".to_string(),
        "ingestion_log" => "ingestion_logs".to_string(),
        "raw_record" => "raw_records".to_string(),
        other => format!("{other}s"),
    }
}

fn member_page_operation(
    op: &str,
) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    match op {
        "get_repository_group_repositories" => Some((
            "repositories",
            "repository_group_id",
            "repository_group_id",
            "field",
        )),
        "get_repository_sources" => Some(("sources", "repository_id", "repository_id", "field")),
        "get_source_ingestion_jobs" => Some(("ingestion-jobs", "source_id", "source_id", "field")),
        "get_source_raw_records" => Some(("raw-records", "source_id", "source_id", "field")),
        "get_source_arts" => Some(("arts", "source_id", "source_id", "field")),
        "get_source_metadata" => Some(("metadata", "source_id", "source_id", "field")),
        "get_source_relationships" => Some(("relationships", "source_id", "source_id", "field")),
        "get_ingestion_job_logs" => Some((
            "ingestion-logs",
            "ingestion_job_id",
            "ingestion_job_id",
            "field",
        )),
        "get_ingestion_job_raw_records" => Some((
            "raw-records",
            "ingestion_job_id",
            "ingestion_job_id",
            "field",
        )),
        "get_ingestion_job_arts" => Some(("arts", "ingestion_job_id", "ingestion_job_id", "field")),
        "get_ingestion_job_metadata" => {
            Some(("metadata", "ingestion_job_id", "ingestion_job_id", "field"))
        }
        "get_ingestion_job_relationships" => Some((
            "relationships",
            "ingestion_job_id",
            "ingestion_job_id",
            "field",
        )),
        "get_author_arts" => Some(("arts", "author_id", "author_id", "field")),
        "get_author_metadata" => Some((
            "metadata",
            "author",
            "author_id",
            "subject_or_relationship_metadata",
        )),
        "get_author_relationships" => Some((
            "relationships",
            "author",
            "author_id",
            "relationship_endpoint",
        )),
        "get_art_metadata" => Some((
            "metadata",
            "art",
            "art_id",
            "subject_or_relationship_metadata",
        )),
        "get_art_relationships" => {
            Some(("relationships", "art", "art_id", "relationship_endpoint"))
        }
        "get_metadata_relationships" => Some((
            "relationships",
            "metadata",
            "metadata_id",
            "relationship_endpoint",
        )),
        _ => None,
    }
}

fn apply_create_defaults(collection: &str, record: &mut Map<String, Value>) {
    let now = now_timestamp();
    for value in record.values_mut() {
        if value.as_str() == Some("") {
            *value = Value::Null;
        }
    }
    match collection {
        "repository-groups" | "repositories" | "sources" | "normalizers" | "relationships" => {
            record
                .entry("created_at".to_string())
                .or_insert_with(|| json!(now));
            record
                .entry("updated_at".to_string())
                .or_insert_with(|| json!(now));
        }
        "authors" => {
            record
                .entry("first_seen_at".to_string())
                .or_insert_with(|| json!(now));
            record
                .entry("last_seen_at".to_string())
                .or_insert_with(|| json!(now));
            record
                .entry("created_at".to_string())
                .or_insert_with(|| json!(now));
            record
                .entry("updated_at".to_string())
                .or_insert_with(|| json!(now));
        }
        "arts" => {
            if !record.contains_key("body_hash") {
                let body = record
                    .get("body")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                record.insert("body_hash".to_string(), json!(stable_hash(&body)));
            }
            record
                .entry("imported_at".to_string())
                .or_insert_with(|| json!(now));
            record
                .entry("last_seen_at".to_string())
                .or_insert_with(|| json!(now));
        }
        "metadata" => {
            record
                .entry("imported_at".to_string())
                .or_insert_with(|| json!(now));
            record
                .entry("last_seen_at".to_string())
                .or_insert_with(|| json!(now));
        }
        "raw-records" => {
            if !record.contains_key("payload_hash") {
                record.insert(
                    "payload_hash".to_string(),
                    json!(stable_hash(
                        &record
                            .get("payload")
                            .cloned()
                            .unwrap_or(Value::Null)
                            .to_string()
                    )),
                );
            }
            record
                .entry("fetched_at".to_string())
                .or_insert_with(|| json!(now));
            record
                .entry("created_at".to_string())
                .or_insert_with(|| json!(now));
        }
        "ingestion-jobs" => {
            record
                .entry("status".to_string())
                .or_insert_with(|| json!("queued"));
            record
                .entry("created_at".to_string())
                .or_insert_with(|| json!(now));
            for field in [
                "raw_records_count",
                "arts_count",
                "authors_count",
                "metadata_count",
                "relationships_count",
            ] {
                record.entry(field.to_string()).or_insert_with(|| json!(0));
            }
        }
        "ingestion-logs" => {
            record
                .entry("created_at".to_string())
                .or_insert_with(|| json!(now));
        }
        _ => {}
    }
}

fn stamp_update(collection: &str, record: &mut Map<String, Value>) {
    let now = now_timestamp();
    if matches!(
        collection,
        "repository-groups"
            | "repositories"
            | "sources"
            | "normalizers"
            | "authors"
            | "relationships"
    ) {
        record.insert("updated_at".to_string(), json!(now));
    }
    if matches!(collection, "arts" | "metadata") {
        record.insert("last_seen_at".to_string(), json!(now));
    }
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
        .copied()
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
    let basis = natural_key(collection, record);
    let id = format!("{}-{}", meta.prefix, stable_hash(&basis));
    record.insert("id".to_string(), json!(id.clone()));
    id
}

fn natural_key(collection: &str, record: &Map<String, Value>) -> String {
    let fields: &[&str] = match collection {
        "repository-groups" => &["slug", "name"],
        "repositories" => &["repository_group_id", "slug", "canonical_url"],
        "sources" => &[
            "repository_id",
            "type",
            "provider",
            "name",
            "external_key",
            "base_url",
        ],
        "normalizers" => &["name", "version", "source_type", "provider"],
        "ingestion-jobs" => &[
            "repository_id",
            "source_id",
            "normalizer_id",
            "mode",
            "cursor",
            "watermark",
            "requested_by",
            "created_at",
        ],
        "ingestion-logs" => &[
            "ingestion_job_id",
            "stage",
            "level",
            "message",
            "created_at",
        ],
        "raw-records" => &[
            "repository_id",
            "source_id",
            "external_id",
            "external_key",
            "record_type",
            "payload_hash",
        ],
        "authors" => &[
            "repository_id",
            "source_id",
            "external_author_id",
            "email",
            "username",
        ],
        "arts" => &[
            "repository_id",
            "source_id",
            "type",
            "external_id",
            "external_key",
            "body_hash",
        ],
        "metadata" => &[
            "repository_id",
            "source_id",
            "subject_type",
            "subject_id",
            "namespace",
            "key",
            "value_type",
            "value",
        ],
        "relationships" => &[
            "repository_id",
            "source_id",
            "from_type",
            "from_id",
            "relation",
            "to_type",
            "to_id",
            "origin",
        ],
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
        "page": {
            "next_cursor": next_cursor,
            "total": total
        },
        "next_cursor": next_cursor,
        "total": total
    })
}

fn record_matches_filter(record: &Value, input: &Value) -> bool {
    let Some(input_obj) = input.as_object() else {
        return true;
    };
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
    for (key, expected) in input_obj {
        if matches!(
            key.as_str(),
            "query"
                | "filters"
                | "cursor"
                | "limit"
                | "include_reverse"
                | "include_metadata"
                | "include_arts"
                | "include_authors"
                | "depth"
        ) || is_empty_value(expected)
        {
            continue;
        }
        if record.get(key) != Some(expected) {
            return false;
        }
    }
    true
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

fn get_record(collection: &str, id: &str) -> Result<Value, ApiError> {
    if matches!(storage_backend()?, StorageBackend::Postgres(_)) {
        return with_postgres_client(|client| {
            postgres_get_record(client, collection, id)?.ok_or_else(|| {
                ApiError::not_found(format!("{collection} record {id} was not found"))
            })
        });
    }
    read_collection(collection)?
        .into_iter()
        .find(|record| value_text(record, "id") == id)
        .ok_or_else(|| ApiError::not_found(format!("{collection} record {id} was not found")))
}

fn source_provider(input: &Value) -> Option<String> {
    let source_id = text_field(input, "source_id");
    if source_id.is_empty() {
        return None;
    }
    get_record("sources", &source_id)
        .ok()
        .map(|source| value_text(&source, "provider"))
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

fn value_i64(value: &Value) -> i64 {
    value
        .as_i64()
        .or_else(|| scalar_text(value).and_then(|text| text.parse::<i64>().ok()))
        .unwrap_or(0)
}

fn bool_flag(input: &Value, key: &str, default: bool) -> bool {
    input.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn job_param_bool(job: &Value, key: &str, default: bool) -> bool {
    job.get("params")
        .and_then(|params| params.get(key))
        .and_then(Value::as_bool)
        .or_else(|| job.get(key).and_then(Value::as_bool))
        .unwrap_or(default)
}

fn job_param_i64(job: &Value, key: &str, default: i64) -> i64 {
    job.get("params")
        .and_then(|params| params.get(key))
        .and_then(scalar_text)
        .or_else(|| job.get(key).and_then(scalar_text))
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
}

fn job_param_text(job: &Value, key: &str) -> String {
    job.get("params")
        .and_then(|params| params.get(key))
        .and_then(scalar_text)
        .or_else(|| job.get(key).and_then(scalar_text))
        .unwrap_or_default()
}

fn use_source_watermarks(job: &Value) -> bool {
    if job_param_bool(job, "ignore_watermark", false) {
        return false;
    }
    !matches!(value_text(job, "mode").as_str(), "full" | "backfill")
}

fn source_watermark_replay_days(job: &Value, source: &Value) -> i64 {
    job.get("params")
        .and_then(|params| params.get("watermark_replay_days"))
        .and_then(scalar_text)
        .or_else(|| {
            source
                .get("ingestion_policy")
                .and_then(|policy| policy.get("watermark_replay_days"))
                .and_then(scalar_text)
        })
        .or_else(|| env::var("REPOINTEL_WATERMARK_REPLAY_DAYS").ok())
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(2)
        .clamp(0, 30)
}

fn source_policy_text(source: &Value, key: &str) -> String {
    source
        .get("ingestion_policy")
        .and_then(|policy| policy.get(key))
        .and_then(scalar_text)
        .unwrap_or_default()
}

fn source_policy_bool(source: &Value, key: &str, default: bool) -> bool {
    source
        .get("ingestion_policy")
        .and_then(|policy| policy.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(default)
}

fn source_policy_i64(source: &Value, key: &str, default: i64) -> i64 {
    source
        .get("ingestion_policy")
        .and_then(|policy| policy.get(key))
        .and_then(scalar_text)
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
}

fn source_policy_usize(source: &Value, key: &str) -> usize {
    source_policy_text(source, key)
        .parse::<usize>()
        .unwrap_or(0)
}

fn update_source_ingestion_policy(
    source: &Value,
    updates: Vec<(&str, Value)>,
) -> Result<(), ApiError> {
    let source_id = value_text(source, "id");
    if source_id.is_empty() {
        return Ok(());
    }
    let current = get_record("sources", &source_id).unwrap_or_else(|_| source.clone());
    let mut policy = current
        .get("ingestion_policy")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (key, value) in updates {
        if value.is_null() {
            policy.remove(key);
        } else {
            policy.insert(key.to_string(), value);
        }
    }
    let _ = update_record(
        "sources",
        "source_id",
        &json!({
            "source_id": source_id,
            "ingestion_policy": policy
        }),
    )?;
    Ok(())
}

fn timestamp_key(value: &str) -> String {
    value
        .trim()
        .trim_end_matches('Z')
        .replace('T', " ")
        .chars()
        .take(19)
        .collect()
}

fn timestamp_after(candidate: &str, watermark: &str) -> bool {
    if watermark.trim().is_empty() {
        return true;
    }
    let candidate = timestamp_key(candidate);
    !candidate.is_empty() && candidate > timestamp_key(watermark)
}

fn replay_watermark_for(watermark: &str, days: i64) -> String {
    if days <= 0 || watermark.trim().is_empty() {
        return watermark.to_string();
    }
    subtract_timestamp_days(watermark, days).unwrap_or_else(|| watermark.to_string())
}

fn subtract_timestamp_days(value: &str, days: i64) -> Option<String> {
    let key = timestamp_key(value);
    if key.len() < 10 {
        return None;
    }
    let year = key.get(0..4)?.parse::<i64>().ok()?;
    let month = key.get(5..7)?.parse::<u32>().ok()?;
    let day = key.get(8..10)?.parse::<u32>().ok()?;
    if key.as_bytes().get(4) != Some(&b'-')
        || key.as_bytes().get(7) != Some(&b'-')
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }
    let time = if key.len() >= 19 {
        key.get(10..19).unwrap_or(" 00:00:00")
    } else {
        " 00:00:00"
    };
    let shifted_days = days_from_civil(year, month, day) - days;
    let (year, month, day) = civil_from_days(shifted_days);
    Some(format!("{year:04}-{month:02}-{day:02}{time}"))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month as i64 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

fn max_timestamp(current: &str, candidate: &str) -> String {
    if candidate.trim().is_empty() {
        return current.to_string();
    }
    if current.trim().is_empty() || timestamp_key(candidate) > timestamp_key(current) {
        return candidate.to_string();
    }
    current.to_string()
}

fn gerrit_after_date(watermark: &str) -> String {
    timestamp_key(watermark)
        .chars()
        .take(10)
        .collect::<String>()
}

fn cursor(input: &Value) -> usize {
    text_field(input, "cursor").parse::<usize>().unwrap_or(0)
}

fn limit(input: &Value) -> usize {
    input
        .get("limit")
        .and_then(Value::as_u64)
        .or_else(|| {
            input
                .get("limit")
                .and_then(Value::as_str)?
                .parse::<u64>()
                .ok()
        })
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
        value_text(value, "imported_at"),
        value_text(value, "source_created_at"),
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

fn now_timestamp() -> String {
    format!("unix:{}", now_unix_seconds())
}

fn now_unix_seconds() -> i64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    duration.as_secs().min(i64::MAX as u64) as i64
}

fn roles_from_token(token: &str) -> Vec<String> {
    let raw = token
        .strip_prefix("roles=")
        .or_else(|| token.strip_prefix("role="))
        .unwrap_or(token);
    let mut roles = BTreeSet::new();
    for part in raw.split(|ch| matches!(ch, ',' | ';' | '|' | ' ' | ':')) {
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
    roles.into_iter().collect()
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

    fn run_git_test(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_test_stdout(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    #[test]
    fn rejects_infrastructure_relationship_endpoint() {
        let validation = validate_relationship_value(&json!({
            "from_type": "repository",
            "from_id": "repo-1",
            "to_type": "metadata",
            "to_id": "md-1",
            "relation": "describes"
        }));
        assert_eq!(validation["valid"], false);
        assert_eq!(validation["code"], "invalid_from_type");
    }

    #[test]
    fn accepts_metadata_art_and_art_author_edges() {
        assert_eq!(
            validate_relationship_value(&json!({
                "from_type": "metadata",
                "from_id": "md-1",
                "to_type": "art",
                "to_id": "art-1",
                "relation": "describes"
            }))["valid"],
            true
        );
        assert_eq!(
            validate_relationship_value(&json!({
                "from_type": "art",
                "from_id": "art-1",
                "to_type": "author",
                "to_id": "author-1",
                "relation": "authored_by"
            }))["valid"],
            true
        );
    }

    #[test]
    fn rejects_non_authorship_art_author_edge() {
        let validation = validate_relationship_value(&json!({
            "from_type": "art",
            "from_id": "art-1",
            "to_type": "author",
            "to_id": "author-1",
            "relation": "mentions"
        }));
        assert_eq!(validation["valid"], false);
        assert_eq!(validation["code"], "invalid_relation");
    }

    #[test]
    fn bulk_validation_reports_first_invalid_edge() {
        let ctx = context(json!({
            "relationships": [
                {
                    "from_type": "metadata",
                    "from_id": "md-1",
                    "to_type": "art",
                    "to_id": "art-1",
                    "relation": "describes"
                },
                {
                    "from_type": "raw_record",
                    "from_id": "raw-1",
                    "to_type": "metadata",
                    "to_id": "md-1",
                    "relation": "describes"
                }
            ]
        }));
        let validation = validate_bulk_metadata_edges(&["input".to_string()], &ctx);
        assert_eq!(validation["valid"], false);
        assert_eq!(validation["details"]["index"], 1);
    }

    #[test]
    fn neighborhood_validation_requires_supported_endpoint_and_id() {
        let ctx = context(json!({ "endpoint_type": "external_ref", "endpoint_id": "x" }));
        assert_eq!(
            validate_neighborhood_request(&["input".to_string()], &ctx)["code"],
            "invalid_endpoint_type"
        );
        let ctx = context(json!({ "endpoint_type": "metadata" }));
        assert_eq!(
            validate_neighborhood_request(&["input".to_string()], &ctx)["code"],
            "missing_endpoint_id"
        );
    }

    #[test]
    fn launchpad_limit_allows_1000_and_messages_use_collection_paging() {
        let source = json!({ "ingestion_policy": { "limit": 1000 } });
        assert_eq!(launchpad_bug_limit(&source), 1000);
        assert_eq!(
            launchpad_next_collection_link(&json!({
                "next_collection_link": "https://api.launchpad.test/next"
            }))
            .as_deref(),
            Some("https://api.launchpad.test/next")
        );
        assert_eq!(
            launchpad_messages_collection_url("https://api.launchpad.test/bug/1/messages")
                .as_deref(),
            Some("https://api.launchpad.test/bug/1/messages?ws.size=100")
        );
        assert_eq!(
            launchpad_messages_collection_url("https://api.launchpad.test/bug/1/messages?memo=1")
                .as_deref(),
            Some("https://api.launchpad.test/bug/1/messages?memo=1&ws.size=100")
        );
    }

    #[test]
    fn watermark_replay_subtracts_days_and_preserves_cutoff_time() {
        let replay = replay_watermark_for("2026-06-21T12:34:56Z", 2);
        assert_eq!(replay, "2026-06-19 12:34:56");
        assert_eq!(gerrit_after_date(&replay), "2026-06-19");
        assert!(timestamp_after("2026-06-19T12:34:57Z", &replay));
        assert!(!timestamp_after("2026-06-19T12:34:56Z", &replay));
        assert_eq!(
            replay_watermark_for("2024-03-01T00:00:00Z", 1),
            "2024-02-29 00:00:00"
        );
        assert_eq!(
            replay_watermark_for("2026-06-21T12:34:56Z", 0),
            "2026-06-21T12:34:56Z"
        );
    }

    #[test]
    fn watermark_replay_days_are_configurable_and_clamped() {
        let source = json!({ "ingestion_policy": { "watermark_replay_days": 4 } });
        assert_eq!(
            source_watermark_replay_days(&json!({ "params": {} }), &source),
            4
        );
        assert_eq!(
            source_watermark_replay_days(
                &json!({ "params": { "watermark_replay_days": 3 } }),
                &source
            ),
            3
        );
        assert_eq!(
            source_watermark_replay_days(
                &json!({ "params": { "watermark_replay_days": 100 } }),
                &json!({})
            ),
            30
        );
    }

    #[test]
    fn running_progress_does_not_overwrite_cancelled_job() {
        let _guard = TEST_LOCK.lock().unwrap();
        let root = env::temp_dir().join(format!(
            "repointel-runtime-cancel-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let previous_storage = env::var("REPOINTEL_STORAGE").ok();
        let previous_data_dir = env::var("REPOINTEL_DATA_DIR").ok();
        env::set_var("REPOINTEL_DATA_DIR", &root);
        env::set_var("REPOINTEL_STORAGE", "json");
        let _ = fs::remove_dir_all(&root);

        create_record(
            "ingestion-jobs",
            &json!({
                "id": "job-cancelled",
                "status": "cancelled",
                "source_id": "source-1"
            }),
        )
        .unwrap();
        let updated = update_ingestion_job_counts(
            "job-cancelled",
            "running",
            &IngestionCounts {
                raw_records: 1,
                arts: 1,
                authors: 1,
                metadata: 1,
                relationships: 1,
            },
            json!({}),
        )
        .unwrap();
        assert_eq!(value_text(&updated, "status"), "cancelled");
        let completed = update_ingestion_job_counts(
            "job-cancelled",
            "completed",
            &IngestionCounts {
                raw_records: 2,
                arts: 2,
                authors: 2,
                metadata: 2,
                relationships: 2,
            },
            json!({ "finished_at": now_timestamp() }),
        )
        .unwrap();
        assert_eq!(value_text(&completed, "status"), "cancelled");

        let _ = fs::remove_dir_all(&root);
        if let Some(value) = previous_storage {
            env::set_var("REPOINTEL_STORAGE", value);
        } else {
            env::remove_var("REPOINTEL_STORAGE");
        }
        if let Some(value) = previous_data_dir {
            env::set_var("REPOINTEL_DATA_DIR", value);
        } else {
            env::remove_var("REPOINTEL_DATA_DIR");
        }
    }

    #[test]
    fn hydrates_launchpad_and_gerrit_authors() {
        let _guard = TEST_LOCK.lock().unwrap();
        let root = env::temp_dir().join(format!(
            "repointel-runtime-author-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let previous_storage = env::var("REPOINTEL_STORAGE").ok();
        let previous_data_dir = env::var("REPOINTEL_DATA_DIR").ok();
        env::set_var("REPOINTEL_DATA_DIR", &root);
        env::set_var("REPOINTEL_STORAGE", "json");
        let _ = fs::remove_dir_all(&root);

        let job = json!({ "id": "job-author" });
        let source = json!({
            "id": "source-author",
            "repository_id": "repo-1"
        });
        let raw = json!({ "id": "raw-author" });

        let owner_link = "https://api.launchpad.test/~tester";
        launchpad_person_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                owner_link.to_string(),
                json!({
                    "self_link": owner_link,
                    "name": "tester",
                    "display_name": "Tester Person",
                    "web_link": "https://launchpad.test/~tester"
                }),
            );
        let launchpad_author = persist_launchpad_author(&job, &source, &raw, owner_link).unwrap();
        assert_eq!(value_text(&launchpad_author, "username"), "tester");
        assert_eq!(
            value_text(&launchpad_author, "display_name"),
            "Tester Person"
        );
        assert_eq!(
            value_text(&launchpad_author, "profile_url"),
            "https://launchpad.test/~tester"
        );

        let gerrit_author = persist_gerrit_author(
            &job,
            &source,
            &raw,
            "https://review.opendev.org",
            &json!({
                "_account_id": 123,
                "username": "reviewer",
                "name": "Review Person",
                "email": "reviewer@example.org"
            }),
        )
        .unwrap();
        assert_eq!(value_text(&gerrit_author, "username"), "reviewer");
        assert_eq!(value_text(&gerrit_author, "display_name"), "Review Person");
        assert_eq!(value_text(&gerrit_author, "email"), "reviewer@example.org");
        assert_eq!(
            value_text(&gerrit_author, "profile_url"),
            "https://review.opendev.org/q/owner:123"
        );
        let unnamed_gerrit_author = persist_gerrit_author(
            &job,
            &source,
            &raw,
            "https://review.opendev.org",
            &json!({
                "_account_id": 456,
                "username": "noname"
            }),
        )
        .unwrap();
        assert_eq!(value_text(&unnamed_gerrit_author, "display_name"), "noname");

        let _ = fs::remove_dir_all(&root);
        if let Some(value) = previous_storage {
            env::set_var("REPOINTEL_STORAGE", value);
        } else {
            env::remove_var("REPOINTEL_STORAGE");
        }
        if let Some(value) = previous_data_dir {
            env::set_var("REPOINTEL_DATA_DIR", value);
        } else {
            env::remove_var("REPOINTEL_DATA_DIR");
        }
    }

    #[test]
    fn persists_gerrit_child_payload_raw_records() {
        let _guard = TEST_LOCK.lock().unwrap();
        let root = env::temp_dir().join(format!(
            "repointel-runtime-gerrit-child-raw-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let previous_storage = env::var("REPOINTEL_STORAGE").ok();
        let previous_data_dir = env::var("REPOINTEL_DATA_DIR").ok();
        env::set_var("REPOINTEL_DATA_DIR", &root);
        env::set_var("REPOINTEL_STORAGE", "json");
        let _ = fs::remove_dir_all(&root);

        let job = json!({
            "id": "job-gerrit-child-raw",
            "repository_id": "repo-1",
            "source_id": "source-gerrit"
        });
        let source = json!({
            "id": "source-gerrit",
            "repository_id": "repo-1",
            "provider": "gerrit"
        });
        let mut counts = IngestionCounts::default();

        persist_gerrit_art_from_raw_payload(
            &mut counts,
            &job,
            &source,
            "https://review.opendev.org",
            "gerrit-change-99-comment-c1",
            "gerrit_inline_comment",
            "https://review.opendev.org/c/openstack/swift/+/99",
            json!({
                "change_number": "99",
                "file_path": "swift/proxy/server.py",
                "comment": {
                    "id": "c1",
                    "message": "Please check this auth path",
                    "updated": "2026-01-04T00:00:00Z"
                }
            }),
            "2026-01-04T00:00:00Z".to_string(),
            json!({
                "_account_id": 123,
                "username": "reviewer",
                "name": "Review Person",
                "email": "reviewer@example.org"
            }),
            "code_review_message",
            "gerrit-change-99-comment-c1",
            "Please check this auth path",
            "2026-01-04T00:00:00Z".to_string(),
            json!({
                "context_type": "gerrit_change",
                "context_external_id": "99",
                "review_message_kind": "inline_comment",
                "file_path": "swift/proxy/server.py",
                "automated": false
            }),
        )
        .unwrap();

        assert_eq!(counts.raw_records, 1);
        assert_eq!(counts.arts, 1);
        assert_eq!(counts.authors, 1);

        let raw_records = read_collection("raw-records").unwrap();
        let raw = raw_records
            .iter()
            .find(|item| value_text(item, "external_id") == "gerrit-change-99-comment-c1")
            .expect("gerrit inline comment raw should be persisted");
        assert_eq!(value_text(raw, "record_type"), "gerrit_inline_comment");

        let arts = read_collection("arts").unwrap();
        let art = arts
            .iter()
            .find(|item| value_text(item, "external_id") == "gerrit-change-99-comment-c1")
            .expect("gerrit inline comment art should be persisted");
        assert_eq!(value_text(art, "raw_record_id"), value_text(raw, "id"));

        let _ = fs::remove_dir_all(&root);
        if let Some(value) = previous_storage {
            env::set_var("REPOINTEL_STORAGE", value);
        } else {
            env::remove_var("REPOINTEL_STORAGE");
        }
        if let Some(value) = previous_data_dir {
            env::set_var("REPOINTEL_DATA_DIR", value);
        } else {
            env::remove_var("REPOINTEL_DATA_DIR");
        }
    }

    #[test]
    fn git_line_survival_normalizer_persists_author_overwrite_metadata() {
        let _guard = TEST_LOCK.lock().unwrap();
        let root = env::temp_dir().join(format!(
            "repointel-runtime-line-survival-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let repo = root.join("repo");
        let previous_storage = env::var("REPOINTEL_STORAGE").ok();
        let previous_data_dir = env::var("REPOINTEL_DATA_DIR").ok();
        env::set_var("REPOINTEL_DATA_DIR", &root);
        env::set_var("REPOINTEL_STORAGE", "json");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&repo).unwrap();

        run_git_test(&repo, &["init"]);
        run_git_test(&repo, &["checkout", "-B", "master"]);
        run_git_test(&repo, &["config", "user.name", "Alice"]);
        run_git_test(&repo, &["config", "user.email", "alice@example.org"]);
        fs::create_dir_all(repo.join("swift/proxy")).unwrap();
        fs::write(
            repo.join("swift/proxy/server.py"),
            "def check():\n    return 'alice'\n",
        )
        .unwrap();
        run_git_test(&repo, &["add", "."]);
        run_git_test(&repo, &["commit", "-m", "initial auth path"]);
        let alice_sha = git_test_stdout(&repo, &["rev-parse", "HEAD"]);

        run_git_test(&repo, &["config", "user.name", "Bob"]);
        run_git_test(&repo, &["config", "user.email", "bob@example.org"]);
        fs::write(
            repo.join("swift/proxy/server.py"),
            "def check():\n    return 'bob'\n",
        )
        .unwrap();
        run_git_test(&repo, &["add", "."]);
        run_git_test(&repo, &["commit", "-m", "replace auth path"]);
        let bob_sha = git_test_stdout(&repo, &["rev-parse", "HEAD"]);

        create_record(
            "repositories",
            &json!({
                "id": "repo-line-survival",
                "default_branch": "master"
            }),
        )
        .unwrap();
        let source = create_record(
            "sources",
            &json!({
                "id": "source-line-survival",
                "repository_id": "repo-line-survival",
                "provider": "git",
                "ingestion_policy": {
                    "line_survival_enabled": true,
                    "line_survival_branch": "master",
                    "line_survival_commit_limit": 100
                }
            }),
        )
        .unwrap();
        let job = create_record(
            "ingestion-jobs",
            &json!({
                "id": "job-line-survival",
                "repository_id": "repo-line-survival",
                "source_id": "source-line-survival",
                "params": { "force_line_survival": true }
            }),
        )
        .unwrap();
        let raw_alice = create_record(
            "raw-records",
            &json!({
                "id": raw_record_id_for(&source, &format!("git-commit-{alice_sha}")),
                "repository_id": "repo-line-survival",
                "source_id": "source-line-survival",
                "external_id": format!("git-commit-{alice_sha}"),
                "record_type": "git_commit",
                "payload": { "sha": alice_sha },
                "fetched_at": "2026-01-01T00:00:00Z"
            }),
        )
        .unwrap();
        let raw_bob = create_record(
            "raw-records",
            &json!({
                "id": raw_record_id_for(&source, &format!("git-commit-{bob_sha}")),
                "repository_id": "repo-line-survival",
                "source_id": "source-line-survival",
                "external_id": format!("git-commit-{bob_sha}"),
                "record_type": "git_commit",
                "payload": { "sha": bob_sha },
                "fetched_at": "2026-01-02T00:00:00Z"
            }),
        )
        .unwrap();
        let alice_author = persist_author(
            &job,
            &source,
            &raw_alice,
            "git",
            "alice@example.org",
            "alice@example.org",
            "Alice",
            "alice@example.org",
            "",
        )
        .unwrap();
        persist_author(
            &job,
            &source,
            &raw_bob,
            "git",
            "bob@example.org",
            "bob@example.org",
            "Bob",
            "bob@example.org",
            "",
        )
        .unwrap();

        let counts =
            persist_git_line_survival_metadata(&job, &source, repo.to_str().unwrap()).unwrap();
        assert!(counts.metadata >= 3);

        let metadata = read_collection("metadata").unwrap();
        let alice_summary = metadata
            .iter()
            .find(|item| {
                value_text(item, "subject_type") == "author"
                    && value_text(item, "subject_id") == value_text(&alice_author, "id")
                    && value_text(item, "namespace") == "git.line_survival"
                    && value_text(item, "key") == "summary"
            })
            .expect("Alice line survival summary metadata should be persisted");
        assert_eq!(
            alice_summary["value"]["cross_author_overwritten_lines"].as_i64(),
            Some(1)
        );

        let alice_commit_fact = metadata
            .iter()
            .find(|item| {
                value_text(item, "subject_type") == "raw_record"
                    && value_text(item, "subject_id") == value_text(&raw_alice, "id")
                    && value_text(item, "namespace") == "git.line_survival"
                    && value_text(item, "key") == "commit"
            })
            .expect("Alice commit line survival metadata should be persisted");
        assert_eq!(
            alice_commit_fact["value"]["cross_author_overwritten_lines"].as_i64(),
            Some(1)
        );

        let _ = fs::remove_dir_all(&root);
        if let Some(value) = previous_storage {
            env::set_var("REPOINTEL_STORAGE", value);
        } else {
            env::remove_var("REPOINTEL_STORAGE");
        }
        if let Some(value) = previous_data_dir {
            env::set_var("REPOINTEL_DATA_DIR", value);
        } else {
            env::remove_var("REPOINTEL_DATA_DIR");
        }
    }

    #[test]
    fn approval_line_survival_normalizer_persists_reviewer_metadata() {
        let _guard = TEST_LOCK.lock().unwrap();
        let root = env::temp_dir().join(format!(
            "repointel-runtime-approval-line-survival-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let repo = root.join("repo");
        let previous_storage = env::var("REPOINTEL_STORAGE").ok();
        let previous_data_dir = env::var("REPOINTEL_DATA_DIR").ok();
        env::set_var("REPOINTEL_DATA_DIR", &root);
        env::set_var("REPOINTEL_STORAGE", "json");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&repo).unwrap();

        run_git_test(&repo, &["init"]);
        run_git_test(&repo, &["checkout", "-B", "master"]);
        run_git_test(&repo, &["config", "user.name", "Patch Author"]);
        run_git_test(&repo, &["config", "user.email", "patch@example.org"]);
        fs::create_dir_all(repo.join("swift/common")).unwrap();
        fs::write(
            repo.join("swift/common/utils.py"),
            "def approved():\n    return True\n",
        )
        .unwrap();
        run_git_test(&repo, &["add", "."]);
        run_git_test(&repo, &["commit", "-m", "approved small change"]);
        let approved_sha = git_test_stdout(&repo, &["rev-parse", "HEAD"]);

        create_record(
            "repositories",
            &json!({
                "id": "repo-approval-line-survival",
                "default_branch": "master"
            }),
        )
        .unwrap();
        let git_source = create_record(
            "sources",
            &json!({
                "id": "source-approval-git",
                "repository_id": "repo-approval-line-survival",
                "provider": "git",
                "ingestion_policy": {
                    "local_path": repo.to_str().unwrap(),
                    "line_survival_branch": "master",
                    "line_survival_commit_limit": 100,
                    "approval_line_survival_enabled": true,
                    "approval_line_survival_max_review_changed_lines": 200
                }
            }),
        )
        .unwrap();
        let gerrit_source = create_record(
            "sources",
            &json!({
                "id": "source-approval-gerrit",
                "repository_id": "repo-approval-line-survival",
                "provider": "gerrit",
                "base_url": "https://review.opendev.org"
            }),
        )
        .unwrap();
        let job = create_record(
            "ingestion-jobs",
            &json!({
                "id": "job-approval-line-survival",
                "repository_id": "repo-approval-line-survival",
                "source_id": "source-approval-git",
                "params": { "force_approval_line_survival": true }
            }),
        )
        .unwrap();
        let raw_review = create_record(
            "raw-records",
            &json!({
                "id": "raw-review-approval-line-survival",
                "repository_id": "repo-approval-line-survival",
                "source_id": "source-approval-gerrit",
                "external_id": "gerrit-change-42",
                "record_type": "gerrit_change",
                "payload": {
                    "_number": 42,
                    "change_id": "Iapproval42",
                    "status": "MERGED",
                    "current_revision": approved_sha,
                    "insertions": 200,
                    "deletions": 0,
                    "updated": "2026-01-05T00:00:00Z",
                    "submit_records": [{
                        "labels": [{
                            "label": "Code-Review",
                            "applied_by": { "_account_id": 123 }
                        }]
                    }],
                    "messages": [{
                        "id": "m1",
                        "author": { "_account_id": 123 },
                        "message": "Patch Set 1: Code-Review+2",
                        "date": "2026-01-05T00:00:00Z"
                    }]
                },
                "fetched_at": "2026-01-05T00:00:00Z"
            }),
        )
        .unwrap();
        let reviewer = persist_gerrit_author(
            &job,
            &gerrit_source,
            &raw_review,
            "https://review.opendev.org",
            &json!({
                "_account_id": 123,
                "username": "reviewer",
                "name": "Review Person",
                "email": "reviewer@example.org"
            }),
        )
        .unwrap();

        let counts = persist_gerrit_approval_line_survival_metadata(
            &job,
            &git_source,
            repo.to_str().unwrap(),
        )
        .unwrap();
        assert!(counts.metadata >= 2);
        assert!(counts.relationships >= 2);

        let metadata = read_collection("metadata").unwrap();
        let summary = metadata
            .iter()
            .find(|item| {
                value_text(item, "subject_type") == "author"
                    && value_text(item, "subject_id") == value_text(&reviewer, "id")
                    && value_text(item, "namespace") == "review.approval_line_survival"
                    && value_text(item, "key") == "summary"
            })
            .expect("reviewer approval line survival summary should be persisted");
        assert_eq!(summary["value"]["reviewed_changes_count"].as_u64(), Some(1));
        assert_eq!(summary["value"]["approved_commits_count"].as_u64(), Some(1));
        assert_eq!(summary["value"]["line_survival_rate"].as_f64(), Some(1.0));

        let change_fact = metadata
            .iter()
            .find(|item| {
                value_text(item, "subject_type") == "raw_record"
                    && value_text(item, "subject_id") == value_text(&raw_review, "id")
                    && value_text(item, "namespace") == "review.approval_line_survival"
                    && value_text(item, "key") == "change"
            })
            .expect("per-review approval line survival metadata should be persisted");
        assert_eq!(change_fact["value"]["change_number"].as_str(), Some("42"));

        let repo_job = create_record(
            "ingestion-jobs",
            &json!({
                "id": "job-approval-line-survival-repository-sync",
                "repository_id": "repo-approval-line-survival",
                "params": { "force_approval_line_survival": true }
            }),
        )
        .unwrap();
        let repo_counts = run_repository_approval_line_survival_after_sources(
            &repo_job,
            &[gerrit_source.clone(), git_source.clone()],
        )
        .unwrap();
        assert!(repo_counts.metadata >= 2);

        let _ = fs::remove_dir_all(&root);
        if let Some(value) = previous_storage {
            env::set_var("REPOINTEL_STORAGE", value);
        } else {
            env::remove_var("REPOINTEL_STORAGE");
        }
        if let Some(value) = previous_data_dir {
            env::set_var("REPOINTEL_DATA_DIR", value);
        } else {
            env::remove_var("REPOINTEL_DATA_DIR");
        }
    }

    #[test]
    fn create_metadata_art_relationship_and_neighborhood_flow() {
        let _guard = TEST_LOCK.lock().unwrap();
        let root = env::temp_dir().join(format!(
            "repointel-runtime-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let previous_storage = env::var("REPOINTEL_STORAGE").ok();
        env::set_var("REPOINTEL_DATA_DIR", &root);
        env::set_var("REPOINTEL_STORAGE", "json");
        let _ = fs::remove_dir_all(&root);

        let metadata = create_record(
            "metadata",
            &json!({
                "repository_id": "repo-1",
                "namespace": "scanner",
                "key": "security-sensitive",
                "value_type": "boolean",
                "value": { "flag": true }
            }),
        )
        .unwrap();
        let art = create_record(
            "arts",
            &json!({
                "repository_id": "repo-1",
                "type": "issue_comment",
                "body": "authorization bypass in project isolation",
                "body_format": "text"
            }),
        )
        .unwrap();
        let relationship = create_record(
            "relationships",
            &json!({
                "repository_id": "repo-1",
                "from_type": "metadata",
                "from_id": metadata["id"],
                "to_type": "art",
                "to_id": art["id"],
                "relation": "describes"
            }),
        )
        .unwrap();
        assert_eq!(relationship["relation"], "describes");

        let neighborhood = relationship_neighborhood(&json!({
            "endpoint_type": "metadata",
            "endpoint_id": metadata["id"],
            "include_metadata": true,
            "include_arts": true,
            "include_authors": true
        }))
        .unwrap();
        assert_eq!(neighborhood["outgoing"].as_array().unwrap().len(), 1);
        assert_eq!(neighborhood["metadata"].as_array().unwrap().len(), 1);
        assert_eq!(neighborhood["arts"].as_array().unwrap().len(), 1);

        let _ = fs::remove_dir_all(&root);
        if let Some(value) = previous_storage {
            env::set_var("REPOINTEL_STORAGE", value);
        } else {
            env::remove_var("REPOINTEL_STORAGE");
        }
    }

    #[test]
    fn extracts_metadata_for_supported_art_types_and_author() {
        let _guard = TEST_LOCK.lock().unwrap();
        let root = env::temp_dir().join(format!(
            "repointel-runtime-extract-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let previous_storage = env::var("REPOINTEL_STORAGE").ok();
        let previous_data_dir = env::var("REPOINTEL_DATA_DIR").ok();
        env::set_var("REPOINTEL_DATA_DIR", &root);
        env::set_var("REPOINTEL_STORAGE", "json");
        let _ = fs::remove_dir_all(&root);

        let rules = json!({
            "art_rules": [
                { "id": "authored_by", "primitive": "relationship", "relation": "authored_by" },
                { "id": "art_type", "primitive": "field_map", "field": "art.type", "namespace": "art", "key": "type", "value_type": "string", "relation": "classifies" },
                { "id": "source_provider", "primitive": "field_map", "field": "source.provider", "namespace": "source", "key": "provider", "value_type": "string", "relation": "describes" },
                { "id": "text_stats", "primitive": "text_stats", "namespace": "text", "key": "stats", "value_type": "object", "relation": "describes" },
                { "id": "context_external_id", "primitive": "field_map", "field": "art.context_external_id", "namespace": "art.context", "key": "external_id", "value_type": "string", "relation": "describes" },
                { "id": "commit_sha", "primitive": "field_map", "art_types": ["commit_message"], "field": "art.commit_sha", "namespace": "git.commit", "key": "sha", "value_type": "string", "relation": "describes", "metadata_links": [{ "target_fields": ["art.body"], "target_extractor": "issue_reference", "target_value_path": "id", "target_namespace": "issue.launchpad", "target_key": "bug_id", "target_value_type": "string", "target_canonical": true, "relation": "related_to", "origin": "normalizer.metadata_link.commit_bug" }] },
                { "id": "gerrit_change_id", "primitive": "named_extractor", "art_types": ["commit_message"], "extractor": "gerrit_change_id", "field": "art.body", "namespace": "gerrit.change", "key": "change_id", "value_type": "string", "relation": "mentions", "direction": "art_to_metadata" },
                { "id": "launchpad_bug_id", "primitive": "field_map", "art_types": ["bug_message"], "field": "art.context_external_id", "namespace": "issue.launchpad", "key": "bug_id", "value_type": "string", "relation": "describes" },
                { "id": "review_change_number", "primitive": "field_map", "art_types": ["code_review_message"], "field": "art.context_external_id", "namespace": "code_review.gerrit", "key": "change_number", "value_type": "string", "relation": "describes", "metadata_links": [{ "target_field": "art.file_path", "target_namespace": "code.file", "target_key": "path", "target_value_type": "string", "target_canonical": true, "relation": "contains", "origin": "normalizer.metadata_link.gerrit_change_file" }, { "target_field": "art.file_path", "target_transform": "component_from_path", "target_namespace": "code.component", "target_key": "name", "target_value_type": "string", "target_canonical": true, "relation": "contains", "origin": "normalizer.metadata_link.gerrit_change_component" }] },
                { "id": "review_kind", "primitive": "field_map", "art_types": ["code_review_message"], "field": "art.review_message_kind", "namespace": "code_review", "key": "message_kind", "value_type": "string", "relation": "classifies" },
                { "id": "review_patch_set", "primitive": "field_map", "art_types": ["code_review_message"], "field": "art.patch_set", "namespace": "code_review", "key": "patch_set", "value_type": "number", "relation": "describes" },
                { "id": "review_line", "primitive": "field_map", "art_types": ["code_review_message"], "field": "art.line", "namespace": "code_review", "key": "line", "value_type": "number", "relation": "describes" },
                { "id": "review_automated", "primitive": "field_map", "art_types": ["code_review_message"], "field": "art.automated", "namespace": "code_review", "key": "automated", "value_type": "boolean", "relation": "classifies" },
                { "id": "review_concern_signal", "primitive": "review_concern", "art_types": ["code_review_message"], "fields": ["art.body"], "namespace": "review.concern", "key": "signal", "value_type": "object", "relation": "describes" },
                { "id": "review_vote_from_message", "primitive": "named_extractor", "art_types": ["code_review_message"], "extractor": "gerrit_vote", "field": "art.body", "namespace": "review.approval", "key": "vote", "value_type": "object", "relation": "mentions", "direction": "art_to_metadata", "author_link": { "from_art_author": true, "relation": "about_author" }, "metadata_links": [{ "target_field": "art.context_external_id", "target_namespace": "code_review.gerrit", "target_key": "change_number", "target_value_type": "string", "target_canonical": true, "relation": "related_to", "origin": "normalizer.metadata_link.approval_change" }] },
                { "id": "review_file_path", "primitive": "field_map", "art_types": ["code_review_message"], "field": "art.file_path", "namespace": "code.file", "key": "path", "value_type": "string", "relation": "describes", "metadata_links": [{ "target_field": "art.context_external_id", "target_namespace": "code_review.gerrit", "target_key": "change_number", "target_value_type": "string", "target_canonical": true, "direction": "target_to_this", "relation": "contains", "origin": "normalizer.metadata_link.gerrit_change_file" }] },
                { "id": "review_component", "primitive": "field_map", "art_types": ["code_review_message"], "field": "art.file_path", "transform": "component_from_path", "namespace": "code.component", "key": "name", "value_type": "string", "relation": "classifies", "metadata_links": [{ "target_field": "art.context_external_id", "target_namespace": "code_review.gerrit", "target_key": "change_number", "target_value_type": "string", "target_canonical": true, "direction": "target_to_this", "relation": "contains", "origin": "normalizer.metadata_link.gerrit_change_component" }] },
                { "id": "cve", "primitive": "named_extractor", "extractor": "cve", "field": "art.body", "namespace": "security.identifier", "key": "cve", "value_type": "string", "relation": "mentions", "direction": "art_to_metadata" },
                { "id": "ghsa", "primitive": "named_extractor", "extractor": "ghsa", "field": "art.body", "namespace": "security.identifier", "key": "ghsa", "value_type": "string", "relation": "mentions", "direction": "art_to_metadata" },
                { "id": "issue_reference", "primitive": "named_extractor", "extractor": "issue_reference", "field": "art.body", "namespace": "issue.reference", "key": "local_id", "value_type": "object", "relation": "mentions", "direction": "art_to_metadata" },
                { "id": "file_path_mentions", "primitive": "named_extractor", "extractor": "file_path", "field": "art.body", "namespace": "code.file", "key": "path", "value_type": "string", "relation": "mentions", "direction": "art_to_metadata" },
                {
                    "id": "security_terms",
                    "primitive": "dictionary",
                    "field": "art.body",
                    "namespace": "security.signal",
                    "value_type": "object",
                    "relation": "mentions",
                    "direction": "art_to_metadata",
                    "terms": [
                        { "term": "security fix", "key": "suspected_security_fix" },
                        { "term": "authorization bypass", "key": "suspected_security_fix" },
                        { "term": "token", "key": "credential" },
                        { "term": "credential", "key": "credential" },
                        { "term": "pickle", "key": "unsafe_deserialization" },
                        { "term": "deserialization", "key": "unsafe_deserialization" }
                    ]
                }
            ],
            "author_rules": [
                { "id": "author_external_id", "primitive": "field_map", "field": "author.external_author_id", "namespace": "author.identity", "key": "external_id", "value_type": "string" },
                { "id": "author_provider", "primitive": "field_map", "field": "source.provider", "namespace": "author.identity", "key": "provider", "value_type": "string" },
                { "id": "author_username", "primitive": "field_map", "field": "author.username", "namespace": "author.identity", "key": "username", "value_type": "string" },
                { "id": "author_display_name", "primitive": "field_map", "field": "author.display_name", "namespace": "author.identity", "key": "display_name", "value_type": "string" },
                { "id": "author_email_domain", "primitive": "field_map", "field": "author.email", "transform": "email_domain", "namespace": "author.identity", "key": "email_domain", "value_type": "string" }
            ],
            "raw_rules": [
                { "id": "raw_gerrit_implementation_risk", "primitive": "gerrit_implementation_risk", "record_types": ["gerrit_change"], "namespace": "review.implementation_risk" },
                { "id": "raw_path_roles", "primitive": "named_extractor", "extractor": "path_classification", "fields": ["raw.payload.file_path", "raw.payload.changed_files", "raw.payload.files.path", "raw.payload.message", "raw.payload.description", "raw.payload.comment.message", "raw.payload.subject", "raw.payload.current_revision_commit_message"], "namespace": "code.file_role", "key": "role", "value_type": "object", "relation": "classifies" },
                { "id": "raw_attack_surface_terms", "primitive": "dictionary", "fields": ["raw.payload.changed_files", "raw.payload.files.path", "raw.payload.title", "raw.payload.description", "raw.payload.message", "raw.payload.comment.message", "raw.payload.subject", "raw.payload.current_revision_commit_message"], "namespace": "security.scenario", "key": "attack_surface_delta", "value_type": "object", "relation": "evidenced_by", "terms": [{ "term": "public api", "value": { "scenario": "attack_surface_delta", "term": "public api" } }, { "term": "route", "value": { "scenario": "attack_surface_delta", "term": "route" } }, { "term": "request path", "value": { "scenario": "attack_surface_delta", "term": "request path" } }, { "term": "middleware", "value": { "scenario": "attack_surface_delta", "term": "middleware" } }, { "term": "s3api", "value": { "scenario": "attack_surface_delta", "term": "s3api" } }] },
                { "id": "raw_security_signal_terms", "primitive": "dictionary", "fields": ["raw.payload.title", "raw.payload.description", "raw.payload.message", "raw.payload.comment.message", "raw.payload.subject", "raw.payload.current_revision_subject", "raw.payload.current_revision_commit_message", "raw.payload.changed_files", "raw.payload.files.path"], "namespace": "security.signal", "value_type": "object", "relation": "evidenced_by", "terms": [
                    { "term": "security", "key": "security_keyword", "value": { "term": "security", "category": "explicit_security" } },
                    { "term": "vulnerability", "key": "vulnerability", "value": { "term": "vulnerability", "category": "explicit_security" } },
                    { "term": "CVE-", "key": "vulnerability_identifier", "value": { "term": "CVE-", "category": "vulnerability_identifier" } },
                    { "term": "GHSA-", "key": "vulnerability_identifier", "value": { "term": "GHSA-", "category": "vulnerability_identifier" } },
                    { "term": "auth", "key": "authorization", "value": { "term": "auth", "category": "authorization" } },
                    { "term": "permission", "key": "authorization", "value": { "term": "permission", "category": "authorization" } },
                    { "term": "credential", "key": "credential", "value": { "term": "credential", "category": "credential" } },
                    { "term": "secret", "key": "credential", "value": { "term": "secret", "category": "credential" } },
                    { "term": "token", "key": "credential", "value": { "term": "token", "category": "credential" } },
                    { "term": "signature", "key": "crypto_integrity", "value": { "term": "signature", "category": "crypto_integrity" } },
                    { "term": "checksum", "key": "data_integrity", "value": { "term": "checksum", "category": "data_integrity" } },
                    { "term": "etag", "key": "data_integrity", "value": { "term": "etag", "category": "data_integrity" } },
                    { "term": "hash", "key": "data_integrity", "value": { "term": "hash", "category": "data_integrity" } },
                    { "term": "corrupt", "key": "data_integrity", "value": { "term": "corrupt", "category": "data_integrity" } },
                    { "term": "quarantine", "key": "data_integrity", "value": { "term": "quarantine", "category": "data_integrity" } },
                    { "term": "pickle", "key": "unsafe_deserialization", "value": { "term": "pickle", "category": "unsafe_deserialization" } },
                    { "term": "unmarshal", "key": "unsafe_deserialization", "value": { "term": "unmarshal", "category": "unsafe_deserialization" } },
                    { "term": "validation", "key": "input_validation", "value": { "term": "validation", "category": "input_validation" } },
                    { "term": "validate", "key": "input_validation", "value": { "term": "validate", "category": "input_validation" } },
                    { "term": "truncated", "key": "input_validation", "value": { "term": "truncated", "category": "input_validation" } },
                    { "term": "oversized", "key": "input_validation", "value": { "term": "oversized", "category": "input_validation" } },
                    { "term": "xml", "key": "parser_input", "value": { "term": "xml", "category": "parser_input" } },
                    { "term": "chunked", "key": "request_body", "value": { "term": "chunked", "category": "request_body" } },
                    { "term": "workflow", "key": "cicd_workflow", "value": { "term": "workflow", "category": "cicd_workflow" } },
                    { "term": "eventlet", "key": "runtime_dependency", "value": { "term": "eventlet", "category": "runtime_dependency" } },
                    { "term": "gunicorn", "key": "runtime_dependency", "value": { "term": "gunicorn", "category": "runtime_dependency" } }
                ] },
                { "id": "raw_fix_propagation_terms", "primitive": "dictionary", "fields": ["raw.payload.changed_files", "raw.payload.files.path", "raw.payload.message", "raw.payload.branch", "raw.payload.subject", "raw.payload.current_revision_commit_message"], "namespace": "security.scenario", "key": "fix_propagation", "value_type": "object", "relation": "evidenced_by", "terms": [{ "term": "stable", "value": { "scenario": "fix_propagation", "term": "stable" } }, { "term": "cherry-pick", "value": { "scenario": "fix_propagation", "term": "cherry-pick" } }] },
                { "id": "raw_launchpad_duplicate_count", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.number_of_duplicates", "namespace": "issue.launchpad", "key": "duplicate_count", "value_type": "number", "relation": "describes" },
                { "id": "raw_launchpad_date_created", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.date_created", "namespace": "issue.launchpad", "key": "date_created", "value_type": "timestamp", "relation": "describes" },
                { "id": "raw_launchpad_date_last_updated", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.date_last_updated", "namespace": "issue.launchpad", "key": "date_last_updated", "value_type": "timestamp", "relation": "describes" },
                { "id": "raw_launchpad_date_last_message", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.date_last_message", "namespace": "issue.launchpad", "key": "date_last_message", "value_type": "timestamp", "relation": "describes" },
                { "id": "raw_launchpad_message_count", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.message_count", "namespace": "issue.launchpad", "key": "message_count", "value_type": "number", "relation": "describes" },
                { "id": "raw_launchpad_users_affected_count", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.users_affected_count", "namespace": "issue.launchpad", "key": "users_affected_count", "value_type": "number", "relation": "describes" },
                { "id": "raw_launchpad_heat", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.heat", "namespace": "issue.launchpad", "key": "heat", "value_type": "number", "relation": "describes" },
                { "id": "raw_launchpad_security_related", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.security_related", "namespace": "issue.launchpad", "key": "security_related", "value_type": "boolean", "relation": "describes" },
                { "id": "raw_launchpad_information_type", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.information_type", "namespace": "issue.launchpad", "key": "information_type", "value_type": "string", "relation": "describes" },
                { "id": "raw_launchpad_private", "primitive": "field_map", "record_types": ["launchpad_bug"], "field": "raw.payload.private", "namespace": "issue.launchpad", "key": "private", "value_type": "boolean", "relation": "describes" },
                { "id": "raw_gerrit_branch", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.branch", "namespace": "code_review.gerrit", "key": "branch", "value_type": "string", "relation": "describes" },
                { "id": "raw_gerrit_change_number", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload._number", "namespace": "code_review.gerrit", "key": "change_number", "value_type": "string", "relation": "describes", "metadata_links": [{ "target_field": "raw.payload.change_id", "target_namespace": "gerrit.change", "target_key": "change_id", "target_value_type": "string", "target_canonical": true, "relation": "related_to", "origin": "normalizer.metadata_link.gerrit_change_identity" }, { "target_field": "raw.payload.current_revision", "target_namespace": "git.commit", "target_key": "sha", "target_value_type": "string", "target_canonical": true, "relation": "related_to", "origin": "normalizer.metadata_link.gerrit_change_commit" }] },
                { "id": "raw_gerrit_subject", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.subject", "namespace": "code_review.gerrit", "key": "subject", "value_type": "string", "relation": "describes" },
                { "id": "raw_gerrit_current_revision_message", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.current_revision_commit_message", "namespace": "git.commit", "key": "message", "value_type": "string", "relation": "describes" },
                { "id": "raw_gerrit_change_id", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.change_id", "namespace": "gerrit.change", "key": "change_id", "value_type": "string", "relation": "describes", "metadata_links": [{ "target_field": "raw.payload.current_revision", "target_namespace": "git.commit", "target_key": "sha", "target_value_type": "string", "target_canonical": true, "relation": "related_to", "origin": "normalizer.metadata_link.gerrit_change_commit" }] },
                { "id": "raw_gerrit_current_revision", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.current_revision", "namespace": "git.commit", "key": "sha", "value_type": "string", "relation": "describes" },
                { "id": "raw_gerrit_changed_file_path", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.changed_files", "namespace": "code.file", "key": "path", "value_type": "string", "relation": "describes", "metadata_links": [{ "target_field": "raw.payload._number", "target_namespace": "code_review.gerrit", "target_key": "change_number", "target_value_type": "string", "target_canonical": true, "direction": "target_to_this", "relation": "contains", "origin": "normalizer.metadata_link.gerrit_change_file" }] },
                { "id": "raw_gerrit_component", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.changed_files", "transform": "component_from_path", "namespace": "code.component", "key": "name", "value_type": "string", "relation": "classifies", "metadata_links": [{ "target_field": "raw.payload._number", "target_namespace": "code_review.gerrit", "target_key": "change_number", "target_value_type": "string", "target_canonical": true, "direction": "target_to_this", "relation": "contains", "origin": "normalizer.metadata_link.gerrit_change_component" }] },
                { "id": "raw_gerrit_status", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.status", "namespace": "code_review.gerrit", "key": "status", "value_type": "string", "relation": "describes" },
                { "id": "raw_gerrit_submit_type", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.submit_type", "namespace": "code_review.gerrit", "key": "submit_type", "value_type": "string", "relation": "describes" },
                { "id": "raw_gerrit_total_comment_count", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.total_comment_count", "namespace": "code_review.gerrit", "key": "total_comment_count", "value_type": "number", "relation": "describes" },
                { "id": "raw_gerrit_unresolved_comment_count", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.unresolved_comment_count", "namespace": "code_review.gerrit", "key": "unresolved_comment_count", "value_type": "number", "relation": "describes" },
                { "id": "raw_gerrit_insertions", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.insertions", "namespace": "code_review.gerrit", "key": "insertions", "value_type": "number", "relation": "describes" },
                { "id": "raw_gerrit_deletions", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.deletions", "namespace": "code_review.gerrit", "key": "deletions", "value_type": "number", "relation": "describes" },
                { "id": "raw_gerrit_submit_record_label", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.submit_records.labels", "namespace": "review.approval", "key": "submit_record_label", "value_type": "object", "relation": "describes", "author_link": { "provider": "gerrit", "value_path": "applied_by._account_id", "relation": "about_author" }, "metadata_links": [{ "target_field": "raw.payload._number", "target_namespace": "code_review.gerrit", "target_key": "change_number", "target_value_type": "string", "target_canonical": true, "relation": "related_to", "origin": "normalizer.metadata_link.approval_change" }] },
                { "id": "raw_gerrit_message_event", "primitive": "field_map", "record_types": ["gerrit_change"], "field": "raw.payload.messages", "namespace": "review.gerrit", "key": "message_event", "value_type": "object", "relation": "describes", "author_link": { "provider": "gerrit", "value_path": "author._account_id", "relation": "about_author" }, "metadata_links": [{ "target_field": "raw.payload._number", "target_namespace": "code_review.gerrit", "target_key": "change_number", "target_value_type": "string", "target_canonical": true, "relation": "related_to", "origin": "normalizer.metadata_link.message_change" }] },
                { "id": "raw_gerrit_vote_from_messages", "primitive": "named_extractor", "record_types": ["gerrit_change", "gerrit_change_message"], "extractor": "gerrit_vote", "fields": ["raw.payload.messages.message", "raw.payload.message"], "namespace": "review.approval", "key": "vote", "value_type": "object", "relation": "describes", "metadata_links": [{ "target_field": "raw.payload._number", "target_namespace": "code_review.gerrit", "target_key": "change_number", "target_value_type": "string", "target_canonical": true, "relation": "related_to", "origin": "normalizer.metadata_link.approval_change" }] },
                { "id": "raw_gerrit_inline_change_number", "primitive": "field_map", "record_types": ["gerrit_inline_comment"], "field": "raw.payload.change_number", "namespace": "code_review.gerrit", "key": "change_number", "value_type": "string", "relation": "describes", "metadata_links": [{ "target_field": "raw.payload.file_path", "target_namespace": "code.file", "target_key": "path", "target_value_type": "string", "target_canonical": true, "relation": "contains", "origin": "normalizer.metadata_link.gerrit_change_file" }, { "target_field": "raw.payload.file_path", "target_transform": "component_from_path", "target_namespace": "code.component", "target_key": "name", "target_value_type": "string", "target_canonical": true, "relation": "contains", "origin": "normalizer.metadata_link.gerrit_change_component" }] },
                { "id": "raw_gerrit_inline_file_path", "primitive": "field_map", "record_types": ["gerrit_inline_comment"], "field": "raw.payload.file_path", "namespace": "code.file", "key": "path", "value_type": "string", "relation": "describes" },
                { "id": "raw_git_changed_file_path", "primitive": "field_map", "record_types": ["git_commit"], "field": "raw.payload.changed_files", "namespace": "code.file", "key": "path", "value_type": "string", "relation": "describes" },
                { "id": "raw_git_file_extension", "primitive": "field_map", "record_types": ["git_commit"], "field": "raw.payload.files.extension", "namespace": "code.file", "key": "extension", "value_type": "string", "relation": "classifies" },
                { "id": "raw_git_changed_file_count", "primitive": "field_map", "record_types": ["git_commit"], "field": "raw.payload.changed_file_count", "namespace": "git.commit", "key": "changed_file_count", "value_type": "number", "relation": "describes" },
                { "id": "raw_git_insertions", "primitive": "field_map", "record_types": ["git_commit"], "field": "raw.payload.insertions", "namespace": "git.commit", "key": "insertions", "value_type": "number", "relation": "describes" },
                { "id": "raw_git_deletions", "primitive": "field_map", "record_types": ["git_commit"], "field": "raw.payload.deletions", "namespace": "git.commit", "key": "deletions", "value_type": "number", "relation": "describes" },
                { "id": "raw_git_binary_file_count", "primitive": "field_map", "record_types": ["git_commit"], "field": "raw.payload.binary_file_count", "namespace": "git.commit", "key": "binary_file_count", "value_type": "number", "relation": "describes" }
            ]
        });
        create_record(
            "normalizers",
            &json!({
                "id": "normalizer-test",
                "name": "test metadata normalizer",
                "version": "3",
                "language": "rules",
                "source_type": "messages",
                "provider": "mixed",
                "enabled": true,
                "rules": rules
            }),
        )
        .unwrap();
        let source_git = json!({
            "id": "source-git",
            "repository_id": "repo-1",
            "provider": "git",
            "normalizer_id": "normalizer-test"
        });
        let source_launchpad = json!({
            "id": "source-launchpad",
            "repository_id": "repo-1",
            "provider": "launchpad",
            "normalizer_id": "normalizer-test"
        });
        let source_gerrit = json!({
            "id": "source-gerrit",
            "repository_id": "repo-1",
            "provider": "gerrit",
            "normalizer_id": "normalizer-test"
        });
        let job = json!({
            "id": "job-1",
            "repository_id": "repo-1",
            "source_id": "source-git"
        });
        let raw = create_record(
            "raw-records",
            &json!({
                "id": "raw-1",
                "repository_id": "repo-1",
                "source_id": "source-git",
                "record_type": "git_commit",
                "payload": {
                    "security_related": true,
                    "private": false,
                    "information_type": "Public Security",
                    "tags": ["security", "crypto"],
                    "message": "Cherry-pick dependency update for stable branch",
                    "changed_file_count": 2,
                    "insertions": 4,
                    "deletions": 1,
                    "binary_file_count": 0,
                    "changed_files": ["requirements.txt", "swift/common/middleware/auth.py"],
                    "files": [
                        { "path": "tox.ini", "extension": "ini", "insertions": 1, "deletions": 0 },
                        { "path": "swift/common/middleware/auth.py", "extension": "py", "insertions": 3, "deletions": 1 }
                    ]
                }
            }),
        )
        .unwrap();
        let author = persist_author(
            &job,
            &source_git,
            &raw,
            "git",
            "dev@example.org",
            "dev@example.org",
            "Example Dev",
            "dev@example.org",
            "https://example.org/dev",
        )
        .unwrap();
        assert_eq!(value_text(&author, "username"), "dev@example.org");
        assert_eq!(value_text(&author, "display_name"), "Example Dev");
        assert_eq!(
            value_text(&author, "profile_url"),
            "https://example.org/dev"
        );
        let author_counts = persist_author_metadata(&job, &source_git, &raw, &author).unwrap();
        assert!(author_counts.metadata >= 4);

        let commit_counts = persist_art(
            &job,
            &source_git,
            &raw,
            &author,
            "commit_message",
            "commit-1-message",
            "https://opendev.org/openstack/swift/commit/abc123",
            "Fixes #123\n\nSecurity fix for CVE-2025-12345 and GHSA-abcd-efgh-ijkl\n\nChange-Id: Iabcdef1234567890",
            "2026-01-01T00:00:00Z".to_string(),
            json!({
                "context_type": "git_commit",
                "context_external_id": "abc123",
                "commit_sha": "abc123"
            }),
        )
        .unwrap();
        assert!(commit_counts.metadata >= 8);
        let raw_git_counts = persist_raw_metadata(&job, &source_git, &raw).unwrap();
        assert!(raw_git_counts.metadata >= 5);
        assert!(raw_git_counts.relationships >= 1);

        persist_art(
            &job,
            &source_launchpad,
            &raw,
            &author,
            "bug_message",
            "bug-42-description",
            "https://bugs.launchpad.net/bugs/42",
            "Authorization bypass in token handling exposes credential material",
            "2026-01-02T00:00:00Z".to_string(),
            json!({
                "context_type": "launchpad_bug",
                "context_external_id": "42"
            }),
        )
        .unwrap();

        persist_art(
            &job,
            &source_gerrit,
            &raw,
            &author,
            "code_review_message",
            "change-99-comment-1",
            "https://review.opendev.org/c/openstack/swift/+/99",
            "swift/common/middleware/crypto/decrypter.py should reject unsafe pickle deserialization",
            "2026-01-03T00:00:00Z".to_string(),
            json!({
                "context_type": "gerrit_change",
                "context_external_id": "99",
                "review_message_kind": "inline_comment",
                "file_path": "swift/common/middleware/crypto/decrypter.py",
                "patch_set": 2,
                "line": 41,
                "automated": false
            }),
        )
        .unwrap();

        let raw_launchpad = create_record(
            "raw-records",
            &json!({
                "id": "raw-launchpad",
                "repository_id": "repo-1",
                "source_id": "source-launchpad",
                "record_type": "launchpad_bug",
                "payload": {
                    "title": "Public API route mishandles authorization",
                    "description": "New route can expose request data",
                    "number_of_duplicates": 3,
                    "date_created": "2026-01-04T00:00:00Z",
                    "date_last_updated": "2026-01-04T01:00:00Z",
                    "date_last_message": "2026-01-04T02:00:00Z",
                    "message_count": 4,
                    "users_affected_count": 7,
                    "heat": 12,
                    "security_related": true,
                    "information_type": "Public Security",
                    "private": false
                },
                "fetched_at": "2026-01-04T00:00:00Z"
            }),
        )
        .unwrap();
        let raw_launchpad_counts =
            persist_raw_metadata(&job, &source_launchpad, &raw_launchpad).unwrap();
        assert!(raw_launchpad_counts.metadata >= 2);

        let raw_gerrit = create_record(
            "raw-records",
            &json!({
                "id": "raw-gerrit",
                "repository_id": "repo-1",
                "source_id": "source-gerrit",
                "record_type": "gerrit_change",
                "payload": {
                    "_number": 100,
                    "change_id": "Iabcdef100",
                    "current_revision": "def456",
                    "branch": "stable/2026.1",
                    "status": "MERGED",
                    "owner": { "_account_id": 77 },
                    "submit_type": "MERGE_IF_NECESSARY",
                    "total_comment_count": 9,
                    "unresolved_comment_count": 2,
                    "insertions": 11,
                    "deletions": 4,
                    "message": "Cherry-pick dependency fix from master",
                    "file_path": "requirements.txt",
                    "submit_records": [{
                        "status": "OK",
                        "labels": [{
                            "label": "Code-Review",
                            "status": "MAY",
                            "applied_by": { "_account_id": 42 }
                        }]
                    }],
                    "messages": [{
                        "id": "message-1",
                        "author": { "_account_id": 42 },
                        "date": "2026-01-05 00:00:00.000000000",
                        "message": "Patch Set 1: Code-Review+2 Workflow+1"
                    }]
                },
                "fetched_at": "2026-01-05T00:00:00Z"
            }),
        )
        .unwrap();
        let gerrit_reviewer = persist_gerrit_author(
            &job,
            &source_gerrit,
            &raw_gerrit,
            "https://review.opendev.org",
            &json!({
                "_account_id": 42,
                "username": "reviewer42",
                "name": "Reviewer 42"
            }),
        )
        .unwrap();
        let gerrit_reviewer_two = persist_gerrit_author(
            &job,
            &source_gerrit,
            &raw_gerrit,
            "https://review.opendev.org",
            &json!({
                "_account_id": 43,
                "username": "reviewer43",
                "name": "Reviewer 43"
            }),
        )
        .unwrap();
        let gerrit_reviewer_three = persist_gerrit_author(
            &job,
            &source_gerrit,
            &raw_gerrit,
            "https://review.opendev.org",
            &json!({
                "_account_id": 44,
                "username": "reviewer44",
                "name": "Reviewer 44"
            }),
        )
        .unwrap();
        let gerrit_owner = persist_gerrit_author(
            &job,
            &source_gerrit,
            &raw_gerrit,
            "https://review.opendev.org",
            &json!({
                "_account_id": 77,
                "username": "owner77",
                "name": "Owner 77"
            }),
        )
        .unwrap();
        persist_art(
            &job,
            &source_gerrit,
            &raw_gerrit,
            &gerrit_owner,
            "code_review_message",
            "change-100-subject",
            "https://review.opendev.org/c/openstack/swift/+/100",
            "Patch Set 1: Code-Review+2 Cherry-pick dependency fix from master",
            "2026-01-05T00:00:00Z".to_string(),
            json!({
                "context_type": "gerrit_change",
                "context_external_id": "100",
                "review_message_kind": "change_subject",
                "automated": false
            }),
        )
        .unwrap();
        persist_art(
            &job,
            &source_gerrit,
            &raw_gerrit,
            &gerrit_reviewer,
            "code_review_message",
            "change-100-inline-1",
            "https://review.opendev.org/c/openstack/swift/+/100",
            "Patch Set 1: this bug could break auth handling here",
            "2026-01-05T00:01:00Z".to_string(),
            json!({
                "context_type": "gerrit_change",
                "context_external_id": "100",
                "review_message_kind": "inline_comment",
                "automated": false,
                "file_path": "swift/common/ring/builder.py",
                "patch_set": 1
            }),
        )
        .unwrap();
        persist_art(
            &job,
            &source_gerrit,
            &raw_gerrit,
            &gerrit_reviewer_two,
            "code_review_message",
            "change-100-inline-2",
            "https://review.opendev.org/c/openstack/swift/+/100",
            "Patch Set 2: this looks wrong and inconsistent for fragments",
            "2026-01-05T00:02:00Z".to_string(),
            json!({
                "context_type": "gerrit_change",
                "context_external_id": "100",
                "review_message_kind": "inline_comment",
                "automated": false,
                "file_path": "swift/common/ring/builder.py",
                "patch_set": 2
            }),
        )
        .unwrap();
        persist_art(
            &job,
            &source_gerrit,
            &raw_gerrit,
            &gerrit_reviewer_three,
            "code_review_message",
            "change-100-inline-3",
            "https://review.opendev.org/c/openstack/swift/+/100",
            "Patch Set 4: this auth path is confusing and complicated",
            "2026-01-05T00:03:00Z".to_string(),
            json!({
                "context_type": "gerrit_change",
                "context_external_id": "100",
                "review_message_kind": "inline_comment",
                "automated": false,
                "file_path": "swift/common/middleware/auth.py",
                "patch_set": 4
            }),
        )
        .unwrap();
        persist_art(
            &job,
            &source_gerrit,
            &raw_gerrit,
            &gerrit_owner,
            "code_review_message",
            "change-100-owner-response",
            "https://review.opendev.org/c/openstack/swift/+/100",
            "Patch Set 4: fixed and updated the validation path",
            "2026-01-05T00:04:00Z".to_string(),
            json!({
                "context_type": "gerrit_change",
                "context_external_id": "100",
                "review_message_kind": "change_message",
                "automated": false,
                "patch_set": 4
            }),
        )
        .unwrap();
        let raw_gerrit_counts = persist_raw_metadata(&job, &source_gerrit, &raw_gerrit).unwrap();
        assert!(raw_gerrit_counts.metadata >= 3);
        assert!(raw_gerrit_counts.relationships >= 1);

        let raw_gerrit_inline = create_record(
            "raw-records",
            &json!({
                "id": "raw-gerrit-inline",
                "repository_id": "repo-1",
                "source_id": "source-gerrit",
                "record_type": "gerrit_inline_comment",
                "payload": {
                    "change_number": "100",
                    "change_id": "openstack%2Fswift~100",
                    "file_path": "swift/common/ring/builder.py",
                    "comment": { "message": "Please check validation here." }
                },
                "fetched_at": "2026-01-05T00:00:00Z"
            }),
        )
        .unwrap();
        let raw_gerrit_inline_counts =
            persist_raw_metadata(&job, &source_gerrit, &raw_gerrit_inline).unwrap();
        assert!(raw_gerrit_inline_counts.metadata >= 2);
        assert!(raw_gerrit_inline_counts.relationships >= 1);

        let metadata = read_collection("metadata").unwrap();
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "security.identifier"
                && value_text(item, "key") == "cve"
                && item.get("value").and_then(Value::as_str) == Some("CVE-2025-12345")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "security.identifier"
                && value_text(item, "key") == "ghsa"
                && item.get("value").and_then(Value::as_str) == Some("GHSA-ABCD-EFGH-IJKL")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "gerrit.change"
                && value_text(item, "key") == "change_id"
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "issue.launchpad"
                && value_text(item, "key") == "bug_id"
                && item.get("value").and_then(Value::as_str) == Some("42")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code.file"
                && value_text(item, "key") == "path"
                && item.get("value").and_then(Value::as_str)
                    == Some("swift/common/middleware/crypto/decrypter.py")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "author.identity"
                && value_text(item, "key") == "email_domain"
                && item.get("value").and_then(Value::as_str) == Some("example.org")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code.file"
                && value_text(item, "key") == "path"
                && item.get("value").and_then(Value::as_str) == Some("requirements.txt")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code.file"
                && value_text(item, "key") == "extension"
                && item.get("value").and_then(Value::as_str) == Some("ini")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "security.scenario"
                && value_text(item, "key") == "attack_surface_delta"
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "security.scenario"
                && value_text(item, "key") == "fix_propagation"
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code.file_role"
                && value_text(item, "key") == "role"
                && item
                    .get("value")
                    .and_then(|value| value.get("role"))
                    .and_then(Value::as_str)
                    == Some("dependency_manifest")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "issue.launchpad"
                && value_text(item, "key") == "duplicate_count"
                && item.get("value").and_then(Value::as_i64) == Some(3)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "issue.launchpad"
                && value_text(item, "key") == "date_created"
                && item.get("value").and_then(Value::as_str) == Some("2026-01-04T00:00:00Z")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "issue.launchpad"
                && value_text(item, "key") == "date_last_message"
                && item.get("value").and_then(Value::as_str) == Some("2026-01-04T02:00:00Z")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "issue.launchpad"
                && value_text(item, "key") == "users_affected_count"
                && item.get("value").and_then(Value::as_i64) == Some(7)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "issue.launchpad"
                && value_text(item, "key") == "heat"
                && item.get("value").and_then(Value::as_i64) == Some(12)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "issue.launchpad"
                && value_text(item, "key") == "security_related"
                && item.get("value").and_then(Value::as_bool) == Some(true)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "issue.launchpad"
                && value_text(item, "key") == "information_type"
                && item.get("value").and_then(Value::as_str) == Some("Public Security")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code_review.gerrit"
                && value_text(item, "key") == "branch"
                && item.get("value").and_then(Value::as_str) == Some("stable/2026.1")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code_review.gerrit"
                && value_text(item, "key") == "change_number"
                && item.get("value").and_then(Value::as_str) == Some("100")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "git.commit"
                && value_text(item, "key") == "sha"
                && item.get("value").and_then(Value::as_str) == Some("def456")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "git.commit"
                && value_text(item, "key") == "changed_file_count"
                && item.get("value").and_then(Value::as_i64) == Some(2)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "git.commit"
                && value_text(item, "key") == "insertions"
                && item.get("value").and_then(Value::as_i64) == Some(4)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "git.commit"
                && value_text(item, "key") == "deletions"
                && item.get("value").and_then(Value::as_i64) == Some(1)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "git.commit"
                && value_text(item, "key") == "binary_file_count"
                && item.get("value").and_then(Value::as_i64) == Some(0)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code_review.gerrit"
                && value_text(item, "key") == "status"
                && item.get("value").and_then(Value::as_str) == Some("MERGED")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code_review.gerrit"
                && value_text(item, "key") == "submit_type"
                && item.get("value").and_then(Value::as_str) == Some("MERGE_IF_NECESSARY")
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code_review.gerrit"
                && value_text(item, "key") == "total_comment_count"
                && item.get("value").and_then(Value::as_i64) == Some(9)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code_review.gerrit"
                && value_text(item, "key") == "unresolved_comment_count"
                && item.get("value").and_then(Value::as_i64) == Some(2)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code_review.gerrit"
                && value_text(item, "key") == "insertions"
                && item.get("value").and_then(Value::as_i64) == Some(11)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "code_review.gerrit"
                && value_text(item, "key") == "deletions"
                && item.get("value").and_then(Value::as_i64) == Some(4)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "review.approval"
                && value_text(item, "key") == "vote"
                && item
                    .get("value")
                    .and_then(|value| value.get("label"))
                    .and_then(Value::as_str)
                    == Some("Code-Review")
                && item
                    .get("value")
                    .and_then(|value| value.get("value"))
                    .and_then(Value::as_i64)
                    == Some(2)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "subject_type") == "art"
                && value_text(item, "namespace") == "review.concern"
                && value_text(item, "key") == "signal"
                && item
                    .get("value")
                    .and_then(|value| value.get("is_concern"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && item
                    .get("value")
                    .and_then(|value| value.get("concern_types"))
                    .and_then(Value::as_array)
                    .map(|types| {
                        types
                            .iter()
                            .any(|value| value.as_str() == Some("bug_fix_issue"))
                    })
                    .unwrap_or(false)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "review.approval"
                && value_text(item, "key") == "submit_record_label"
                && item
                    .get("value")
                    .and_then(|value| value.get("applied_by"))
                    .and_then(|value| value.get("_account_id"))
                    .and_then(Value::as_i64)
                    == Some(42)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "namespace") == "review.gerrit"
                && value_text(item, "key") == "message_event"
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "subject_type") == "raw_record"
                && value_text(item, "subject_id") == value_text(&raw_gerrit, "id")
                && value_text(item, "namespace") == "review.implementation_risk"
                && value_text(item, "key") == "concern_message_count"
                && item.get("value").and_then(Value::as_i64) == Some(3)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "subject_type") == "raw_record"
                && value_text(item, "subject_id") == value_text(&raw_gerrit, "id")
                && value_text(item, "namespace") == "review.implementation_risk"
                && value_text(item, "key") == "repeated_concern_file_count"
                && item.get("value").and_then(Value::as_i64) == Some(1)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "subject_type") == "raw_record"
                && value_text(item, "subject_id") == value_text(&raw_gerrit, "id")
                && value_text(item, "namespace") == "review.implementation_risk"
                && value_text(item, "key") == "distinct_concern_patch_sets"
                && item.get("value").and_then(Value::as_i64) == Some(3)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "subject_type") == "raw_record"
                && value_text(item, "subject_id") == value_text(&raw_gerrit, "id")
                && value_text(item, "namespace") == "review.implementation_risk"
                && value_text(item, "key") == "concern_span_patch_sets"
                && item.get("value").and_then(Value::as_i64) == Some(3)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "subject_type") == "raw_record"
                && value_text(item, "subject_id") == value_text(&raw_gerrit, "id")
                && value_text(item, "namespace") == "review.implementation_risk"
                && value_text(item, "key") == "concerns_after_positive_vote"
                && item.get("value").and_then(Value::as_i64) == Some(3)
        }));
        assert!(metadata.iter().any(|item| {
            value_text(item, "subject_type") == "raw_record"
                && value_text(item, "subject_id") == value_text(&raw_gerrit, "id")
                && value_text(item, "namespace") == "review.implementation_risk"
                && value_text(item, "key") == "implementation_signal_score"
                && item.get("value").and_then(Value::as_i64).unwrap_or(0) >= 5
        }));

        let relationships = read_collection("relationships").unwrap();
        assert!(relationships.iter().any(|edge| {
            value_text(edge, "from_type") == "art"
                && value_text(edge, "relation") == "authored_by"
                && value_text(edge, "to_type") == "author"
        }));
        assert!(relationships.iter().any(|edge| {
            value_text(edge, "from_type") == "metadata"
                && value_text(edge, "relation") == "about_author"
                && value_text(edge, "to_type") == "author"
                && value_text(edge, "to_id") == value_text(&gerrit_reviewer, "id")
                && value_text(edge, "origin") == "normalizer.metadata_author_link.v1"
        }));
        assert!(relationships.iter().any(|edge| {
            value_text(edge, "from_type") == "metadata"
                && value_text(edge, "to_type") == "metadata"
                && value_text(edge, "origin") == "normalizer.metadata_link.commit_bug"
        }));
        assert!(relationships.iter().any(|edge| {
            value_text(edge, "from_type") == "metadata"
                && value_text(edge, "to_type") == "metadata"
                && value_text(edge, "origin") == "normalizer.metadata_link.gerrit_change_commit"
        }));
        assert!(relationships.iter().any(|edge| {
            value_text(edge, "from_type") == "metadata"
                && value_text(edge, "to_type") == "metadata"
                && value_text(edge, "origin") == "normalizer.metadata_link.approval_change"
        }));
        assert!(relationships.iter().any(|edge| {
            value_text(edge, "from_type") == "metadata"
                && value_text(edge, "relation") == "contains"
                && value_text(edge, "to_type") == "metadata"
                && value_text(edge, "origin") == "normalizer.metadata_link.gerrit_change_file"
        }));
        assert!(relationships.iter().all(|edge| {
            matches!(
                value_text(edge, "from_type").as_str(),
                "metadata" | "art" | "author"
            ) && matches!(
                value_text(edge, "to_type").as_str(),
                "metadata" | "art" | "author"
            )
        }));

        let _ = fs::remove_dir_all(&root);
        if let Some(value) = previous_storage {
            env::set_var("REPOINTEL_STORAGE", value);
        } else {
            env::remove_var("REPOINTEL_STORAGE");
        }
        if let Some(value) = previous_data_dir {
            env::set_var("REPOINTEL_DATA_DIR", value);
        } else {
            env::remove_var("REPOINTEL_DATA_DIR");
        }
    }
}
