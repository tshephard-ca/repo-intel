#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

const databaseUrl =
  process.env.REPOINTEL_DATABASE_URL ||
  process.env.DATABASE_URL ||
  "postgres://repointel:repointel@127.0.0.1:15432/repointel";

const options = parseArgs(process.argv.slice(2));
const repositoryId = options.repositoryId || process.env.REPOINTEL_REPOSITORY_ID || "";
const dryRun = Boolean(options.dryRun);
const skipNormalizer = Boolean(options.skipNormalizer);
const skipBackfill = Boolean(options.skipBackfill);
const limit = integerOption(options.limit, process.env.REPOINTEL_BACKFILL_LIMIT, 0);

const reviewRevisionRules = [
  {
    id: "raw_gerrit_current_revision_sha_review",
    key: "current_revision_sha",
    field: "raw.payload.current_revision",
    relation: "describes",
    namespace: "code_review.gerrit",
    primitive: "field_map",
    value_type: "string",
    record_types: ["gerrit_change"],
  },
  {
    id: "raw_gerrit_current_revision_number_review",
    key: "current_revision_number",
    field: "raw.payload.current_revision_number",
    relation: "describes",
    namespace: "code_review.gerrit",
    primitive: "field_map",
    value_type: "number",
    record_types: ["gerrit_change"],
  },
];

const summary = {
  dry_run: dryRun,
  repository_id: repositoryId || null,
  limit: limit || null,
  normalizer: null,
  raw_merged_changes: 0,
  metadata_docs_prepared: 0,
  existing_current_revision_sha_rows: 0,
  existing_current_revision_number_rows: 0,
  missing_current_revision_sha_before: 0,
  missing_current_revision_number_before: 0,
  missing_current_revision_sha_after: 0,
  missing_current_revision_number_after: 0,
};

if (!skipNormalizer) {
  summary.normalizer = ensureSharedNormalizerRules();
}

if (!skipBackfill) {
  const before = countReviewRevisionMetadata();
  summary.existing_current_revision_sha_rows = before.currentRevisionShaRows;
  summary.existing_current_revision_number_rows = before.currentRevisionNumberRows;
  summary.missing_current_revision_sha_before = before.missingCurrentRevisionSha;
  summary.missing_current_revision_number_before = before.missingCurrentRevisionNumber;

  const changeCounts = countMergedGerritChanges();
  summary.raw_merged_changes = changeCounts.rawMergedChanges;
  summary.metadata_docs_prepared = changeCounts.rawMergedChanges + changeCounts.currentRevisionNumberValues;
  if (!dryRun) {
    summary.backfill = backfillMergedReviewRevisionMetadata();
  }

  const after = countReviewRevisionMetadata();
  summary.missing_current_revision_sha_after = after.missingCurrentRevisionSha;
  summary.missing_current_revision_number_after = after.missingCurrentRevisionNumber;
}

console.log(JSON.stringify(summary, null, 2));

function ensureSharedNormalizerRules() {
  const normalizers = queryJson(`
    select coalesce(jsonb_agg(jsonb_build_object('id', id, 'doc', doc) order by id), '[]'::jsonb)::text
    from repointel_records
    where collection = 'normalizers';
  `);
  const normalizer = normalizers.find((row) => Array.isArray(row?.doc?.metadata_rules)) || normalizers[0];
  if (!normalizer?.id || !normalizer?.doc) {
    fail("no normalizer record found");
  }

  const doc = structuredClone(normalizer.doc);
  const rules = Array.isArray(doc.metadata_rules) ? [...doc.metadata_rules] : [];
  let addedRules = 0;
  let updatedRules = 0;

  for (const desiredRule of reviewRevisionRules) {
    const index = rules.findIndex((rule) => rule?.id === desiredRule.id);
    if (index === -1) {
      rules.push(desiredRule);
      addedRules += 1;
      continue;
    }
    const existingRule = rules[index];
    if (JSON.stringify(existingRule) !== JSON.stringify({ ...existingRule, ...desiredRule })) {
      rules[index] = { ...existingRule, ...desiredRule };
      updatedRules += 1;
    }
  }

  doc.metadata_rules = rules;
  doc.version = nextVersion(doc.version, addedRules + updatedRules);
  doc.updated_at = new Date().toISOString();

  if (!dryRun && (addedRules || updatedRules)) {
    runPsql(`
      update repointel_records
      set doc = ${sqlJson(doc)},
          updated_at = now()
      where collection = 'normalizers'
        and id = ${sqlLiteral(normalizer.id)};
    `);
  }

  return {
    id: normalizer.id,
    added_rules: addedRules,
    updated_rules: updatedRules,
    old_version: stringValue(normalizer.doc.version),
    new_version: stringValue(doc.version),
  };
}

function countMergedGerritChanges() {
  const repositoryFilter = repositoryId ? `and doc->>'repository_id' = ${sqlLiteral(repositoryId)}` : "";
  const limitClause = limit > 0 ? `limit ${limit}` : "";
  return queryJson(`
    with changes as (
      select
        id as raw_record_id,
        doc->>'repository_id' as repository_id,
        coalesce(doc->>'source_id', '') as source_id,
        coalesce(doc->>'ingestion_job_id', '') as ingestion_job_id,
        coalesce(doc->'payload'->>'_number', '') as change_number,
        coalesce(doc->'payload'->>'change_id', '') as change_id,
        coalesce(doc->'payload'->>'project', '') as project,
        coalesce(doc->'payload'->>'branch', '') as branch,
        coalesce(doc->'payload'->>'status', '') as status,
        coalesce(doc->'payload'->>'current_revision', '') as current_revision_sha,
        coalesce(nullif(doc->'payload'->>'current_revision_number', ''), '0')::int as current_revision_number,
        coalesce(doc->'payload'->>'created', '') as source_created_at,
        coalesce(doc->'payload'->>'updated', '') as source_updated_at
      from repointel_records
      where collection = 'raw-records'
        and doc->>'record_type' = 'gerrit_change'
        and upper(coalesce(doc->'payload'->>'status', '')) = 'MERGED'
        and coalesce(doc->'payload'->>'current_revision', '') <> ''
        ${repositoryFilter}
      order by coalesce(nullif(doc->'payload'->>'_number', ''), '0')::bigint
      ${limitClause}
    )
    select jsonb_build_object(
      'rawMergedChanges', count(*),
      'currentRevisionNumberValues', count(*) filter (where current_revision_number > 0)
    )::text
    from changes;
  `);
}

function backfillMergedReviewRevisionMetadata() {
  const deletedRows = deleteExistingReviewRevisionRows();
  const upsertedRows = insertReviewRevisionRows();
  return { deleted_rows: deletedRows, upserted_rows: upsertedRows };
}

function deleteExistingReviewRevisionRows() {
  const repositoryFilter = repositoryId ? `and r.doc->>'repository_id' = ${sqlLiteral(repositoryId)}` : "";
  const limitClause = limit > 0 ? `limit ${limit}` : "";
  const result = queryJson(`
    with changes as (
      select id as raw_record_id
      from repointel_records r
      where r.collection = 'raw-records'
        and r.doc->>'record_type' = 'gerrit_change'
        and upper(coalesce(r.doc->'payload'->>'status', '')) = 'MERGED'
        and coalesce(r.doc->'payload'->>'current_revision', '') <> ''
        ${repositoryFilter}
      order by coalesce(nullif(r.doc->'payload'->>'_number', ''), '0')::bigint
      ${limitClause}
    ),
    deleted as (
      delete from repointel_records m
      using changes c
      where m.collection = 'metadata'
        and m.doc->>'origin' = 'normalizer.raw_gerrit_review_revision.v1'
        and m.doc->>'raw_record_id' = c.raw_record_id
      returning 1
    )
    select jsonb_build_object('count', count(*))::text
    from deleted;
  `);
  return numberValue(result.count);
}

function insertReviewRevisionRows() {
  const repositoryFilter = repositoryId ? `and r.doc->>'repository_id' = ${sqlLiteral(repositoryId)}` : "";
  const limitClause = limit > 0 ? `limit ${limit}` : "";
  const result = queryJson(`
    with changes as (
      select
        r.id as raw_record_id,
        r.doc->>'repository_id' as repository_id,
        coalesce(r.doc->>'source_id', '') as source_id,
        coalesce(r.doc->>'ingestion_job_id', '') as ingestion_job_id,
        coalesce(r.doc->'payload'->>'_number', '') as change_number,
        coalesce(r.doc->'payload'->>'change_id', '') as change_id,
        coalesce(r.doc->'payload'->>'project', '') as project,
        coalesce(r.doc->'payload'->>'branch', '') as branch,
        coalesce(r.doc->'payload'->>'status', '') as status,
        coalesce(r.doc->'payload'->>'current_revision', '') as current_revision_sha,
        coalesce(nullif(r.doc->'payload'->>'current_revision_number', ''), '0')::int as current_revision_number,
        coalesce(r.doc->'payload'->>'created', '') as source_created_at,
        coalesce(r.doc->'payload'->>'updated', '') as source_updated_at
      from repointel_records r
      where r.collection = 'raw-records'
        and r.doc->>'record_type' = 'gerrit_change'
        and upper(coalesce(r.doc->'payload'->>'status', '')) = 'MERGED'
        and coalesce(r.doc->'payload'->>'current_revision', '') <> ''
        ${repositoryFilter}
      order by coalesce(nullif(r.doc->'payload'->>'_number', ''), '0')::bigint
      ${limitClause}
    ),
    revision_values as (
      select
        *,
        'current_revision_sha'::text as key,
        'string'::text as value_type,
        to_jsonb(current_revision_sha) as value
      from changes
      union all
      select
        *,
        'current_revision_number'::text as key,
        'number'::text as value_type,
        to_jsonb(current_revision_number) as value
      from changes
      where current_revision_number > 0
    ),
    upserted as (
      insert into repointel_records(collection, id, doc, created_at, updated_at)
      select
        'metadata',
        'metadata-' || substr(md5('code_review.gerrit.review_revision|' || key || '|' || raw_record_id), 1, 16),
        jsonb_build_object(
          'id', 'metadata-' || substr(md5('code_review.gerrit.review_revision|' || key || '|' || raw_record_id), 1, 16),
          'repository_id', repository_id,
          'source_id', source_id,
          'ingestion_job_id', ingestion_job_id,
          'raw_record_id', raw_record_id,
          'subject_type', 'raw_record',
          'subject_id', raw_record_id,
          'namespace', 'code_review.gerrit',
          'key', key,
          'value', value,
          'value_type', value_type,
          'relation', 'describes',
          'role', 'extracted_fact',
          'origin', 'normalizer.raw_gerrit_review_revision.v1',
          'value_context', jsonb_build_object(
            'status', status,
            'change_number', change_number,
            'change_id', change_id,
            'project', project,
            'branch', branch
          ),
          'source_created_at', source_created_at,
          'source_updated_at', source_updated_at,
          'imported_at', now(),
          'last_seen_at', now()
        ),
        now(),
        now()
      from revision_values
      returning 1
    )
    select jsonb_build_object('count', count(*))::text
    from upserted;
  `);
  return numberValue(result.count);
}

function countReviewRevisionMetadata() {
  const repositoryFilter = repositoryId ? `and r.doc->>'repository_id' = ${sqlLiteral(repositoryId)}` : "";
  return queryJson(`
    with merged as (
      select id as raw_record_id
      from repointel_records r
      where r.collection = 'raw-records'
        and r.doc->>'record_type' = 'gerrit_change'
        and upper(coalesce(r.doc->'payload'->>'status', '')) = 'MERGED'
        and coalesce(r.doc->'payload'->>'current_revision', '') <> ''
        ${repositoryFilter}
    ),
    metadata_flags as (
      select
        m.doc->>'raw_record_id' as raw_record_id,
        bool_or(m.doc->>'key' = 'current_revision_sha') as has_current_revision_sha,
        bool_or(m.doc->>'key' = 'current_revision_number') as has_current_revision_number,
        count(*) filter (where m.doc->>'key' = 'current_revision_sha') as current_revision_sha_rows,
        count(*) filter (where m.doc->>'key' = 'current_revision_number') as current_revision_number_rows
      from repointel_records m
      join merged on merged.raw_record_id = m.doc->>'raw_record_id'
      where m.collection = 'metadata'
        and m.doc->>'namespace' = 'code_review.gerrit'
        and m.doc->>'key' in ('current_revision_sha', 'current_revision_number')
      group by m.doc->>'raw_record_id'
    )
    select jsonb_build_object(
      'currentRevisionShaRows', coalesce(sum(metadata_flags.current_revision_sha_rows), 0),
      'currentRevisionNumberRows', coalesce(sum(metadata_flags.current_revision_number_rows), 0),
      'missingCurrentRevisionSha', count(*) filter (where coalesce(metadata_flags.has_current_revision_sha, false) = false),
      'missingCurrentRevisionNumber', count(*) filter (where coalesce(metadata_flags.has_current_revision_number, false) = false)
    )::text
    from merged
    left join metadata_flags on metadata_flags.raw_record_id = merged.raw_record_id;
  `);
}

function queryJson(sql) {
  const text = runPsql(sql, ["-t", "-A"]).trim();
  return text ? JSON.parse(text) : [];
}

function runPsql(sql, extraArgs = []) {
  const result = spawnSync("psql", ["-X", "-v", "ON_ERROR_STOP=1", "-q", ...extraArgs, databaseUrl], {
    input: sql,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 256,
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || `psql exited with ${result.status}`);
  }
  return result.stdout || "";
}

function parseArgs(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--dry-run") {
      parsed.dryRun = true;
      continue;
    }
    if (arg === "--skip-normalizer") {
      parsed.skipNormalizer = true;
      continue;
    }
    if (arg === "--skip-backfill") {
      parsed.skipBackfill = true;
      continue;
    }
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    parsed[key] = args[index + 1];
    index += 1;
  }
  return parsed;
}

function nextVersion(value, changedCount) {
  if (!changedCount) return value;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? String(parsed + 1) : String(value || "1");
}

function integerOption(...values) {
  for (const value of values) {
    if (value === undefined || value === null || value === "") continue;
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function numberValue(value) {
  if (value === null || value === undefined || value === "") return 0;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function stringValue(value) {
  if (value === null || value === undefined) return "";
  return String(value);
}

function stableHash(text) {
  return createHash("sha256").update(String(text)).digest("hex").slice(0, 16);
}

function sqlLiteral(value) {
  return `'${String(value ?? "").replace(/'/g, "''")}'`;
}

function sqlJson(value) {
  const text = JSON.stringify(value);
  const tag = `$repointel_json_${stableHash(text)}$`;
  return `${tag}${text}${tag}::jsonb`;
}

function fail(message) {
  console.error(message);
  process.exit(2);
}
