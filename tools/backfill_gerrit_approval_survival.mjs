#!/usr/bin/env node

import fs from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

const databaseUrl =
  process.env.REPOINTEL_DATABASE_URL ||
  process.env.DATABASE_URL ||
  "postgres://repointel:repointel@127.0.0.1:15432/repointel";

const options = parseArgs(process.argv.slice(2));
const repositoryId = options.repositoryId || process.env.REPOINTEL_REPOSITORY_ID || "";
const lineSurvivalPath = options.lineSurvivalJson || process.env.LINE_SURVIVAL_JSON || "";
const maxReviewChangedLines = integerOption(options.maxReviewChangedLines, process.env.MAX_REVIEW_CHANGED_LINES, 200);
const dryRun = Boolean(options.dryRun);
const replaceExisting = !Boolean(options.noReplaceExisting);

if (!repositoryId) {
  fail("missing --repository-id");
}
if (!lineSurvivalPath) {
  fail("missing --line-survival-json");
}
if (!fs.existsSync(lineSurvivalPath)) {
  fail(`line survival JSON not found: ${lineSurvivalPath}`);
}

const lineSurvival = JSON.parse(fs.readFileSync(lineSurvivalPath, "utf8"));
const commitStatsBySha = new Map((lineSurvival.commits || [])
  .filter((commit) => commit?.sha)
  .map((commit) => [String(commit.sha), commit]));
const branch = String(lineSurvival.branch || "");
const headSha = String(lineSurvival.head_sha || lineSurvival.head || "");
const maxChangedLines = numberValue(lineSurvival.max_changed_lines);

const rawChanges = queryJson(`
  select coalesce(jsonb_agg(jsonb_build_object(
    'raw_record_id', id,
    'repository_id', doc->>'repository_id',
    'source_id', coalesce(doc->>'source_id', ''),
    'ingestion_job_id', coalesce(doc->>'ingestion_job_id', ''),
    'change_number', doc->'payload'->>'_number',
    'change_id', coalesce(doc->'payload'->>'change_id', ''),
    'project', coalesce(doc->'payload'->>'project', ''),
    'branch', coalesce(doc->'payload'->>'branch', ''),
    'status', coalesce(doc->'payload'->>'status', ''),
    'subject', coalesce(doc->'payload'->>'subject', ''),
    'current_revision', coalesce(doc->'payload'->>'current_revision', ''),
    'created_at', left(coalesce(doc->'payload'->>'created', ''), 26),
    'updated_at', left(coalesce(doc->'payload'->>'updated', ''), 26),
    'insertions', coalesce(nullif(doc->'payload'->>'insertions', ''), '0')::int,
    'deletions', coalesce(nullif(doc->'payload'->>'deletions', ''), '0')::int,
    'owner_account_id', coalesce(doc->'payload'->'owner'->>'_account_id', ''),
    'messages', coalesce((
      select jsonb_agg(message)
      from jsonb_array_elements(coalesce(doc->'payload'->'messages', '[]'::jsonb)) message
      where coalesce(message->>'message', '') ~ '^Patch Set [0-9]+: .*Code-Review\\+[12](\\y|[^0-9])'
    ), '[]'::jsonb)
  )), '[]'::jsonb)::text
  from repointel_records
  where collection = 'raw-records'
    and doc->>'record_type' = 'gerrit_change'
    and doc->>'repository_id' = ${sqlLiteral(repositoryId)}
    and upper(coalesce(doc->'payload'->>'status', '')) = 'MERGED';
`);

const existingMetadataRows = existingApprovalSurvivalRows(repositoryId);
const approvalRows = [];
const reviewerByKey = new Map();
let skippedLargeChange = 0;
let skippedNoSurvivalCommit = 0;
let skippedNoApproval = 0;

for (const change of rawChanges) {
  const messages = Array.isArray(change.messages) ? change.messages : [];
  if (!messages.length) {
    skippedNoApproval += 1;
    continue;
  }
  const reviewChangedLines = numberValue(change.insertions) + numberValue(change.deletions);
  if (maxReviewChangedLines > 0 && reviewChangedLines > maxReviewChangedLines) {
    skippedLargeChange += 1;
    continue;
  }
  const commitSha = String(change.current_revision || "");
  const commitStats = commitStatsBySha.get(commitSha);
  if (!commitStats) {
    skippedNoSurvivalCommit += 1;
    continue;
  }
  for (const message of messages) {
    for (const approval of approvalsFromMessage(message)) {
      const reviewer = reviewerFromMessageAuthor(message.author || {});
      if (!reviewer.accountId) continue;
      const reviewerKey = `gerrit:${reviewer.accountId}`;
      const reviewerRecord = {
        reviewer_key: reviewerKey,
        gerrit_account_id: reviewer.accountId,
        reviewer_name: reviewer.name,
        reviewer_email: reviewer.email,
        reviewer_username: reviewer.username,
      };
      if (!reviewerByKey.has(reviewerKey)) reviewerByKey.set(reviewerKey, reviewerRecord);
      approvalRows.push({
        ...reviewerRecord,
        repository_id: String(change.repository_id || repositoryId),
        source_id: String(change.source_id || ""),
        ingestion_job_id: String(change.ingestion_job_id || ""),
        raw_record_id: String(change.raw_record_id || ""),
        change_number: String(change.change_number || ""),
        change_id: String(change.change_id || ""),
        project: String(change.project || ""),
        branch: String(change.branch || branch),
        status: String(change.status || ""),
        subject: String(change.subject || ""),
        owner_account_id: String(change.owner_account_id || ""),
        commit_sha: commitSha,
        approval_message_id: String(message.id || stableHash(JSON.stringify(message))),
        approval_patch_set: numberValue(approval.patchSet || message._revision_number),
        approval_date: String(message.date || change.updated_at || ""),
        approval_label: approval.label,
        approval_value: approval.value,
        approval_raw: approval.raw,
        labels: approval.labels,
        review_insertions: numberValue(change.insertions),
        review_deletions: numberValue(change.deletions),
        review_changed_lines: reviewChangedLines,
        line_survival_branch: branch,
        line_survival_head_sha: headSha,
        line_survival_max_changed_lines: maxChangedLines,
        commit_insertions_tracked: numberValue(commitStats.insertions_tracked),
        commit_deletions_tracked: numberValue(commitStats.deletions_tracked),
        surviving_lines: numberValue(commitStats.surviving_lines),
        cross_author_overwritten_lines: numberValue(commitStats.cross_author_overwritten_lines),
        self_reworked_lines: numberValue(commitStats.self_reworked_lines),
        line_survival_rate: numberValue(commitStats.line_survival_rate),
        cross_author_overwrite_rate: numberValue(commitStats.cross_author_overwrite_rate),
        self_rework_rate: numberValue(commitStats.self_rework_rate),
      });
    }
  }
}

const authorsByExternal = existingAuthorsByExternal(Array.from(reviewerByKey.keys()));
const authorDocs = [];
for (const reviewer of reviewerByKey.values()) {
  if (authorsByExternal.has(reviewer.reviewer_key)) continue;
  const authorId = `author-${stableHash(reviewer.reviewer_key)}`;
  authorsByExternal.set(reviewer.reviewer_key, {
    id: authorId,
    display_name: reviewer.reviewer_name || reviewer.reviewer_email || reviewer.reviewer_key,
    external_author_id: reviewer.reviewer_key,
  });
  authorDocs.push({
    id: authorId,
    external_author_id: reviewer.reviewer_key,
    display_name: reviewer.reviewer_name || reviewer.reviewer_email || reviewer.reviewer_key,
    email: reviewer.reviewer_email || "",
    username: reviewer.reviewer_username || "",
    profile_url: `https://review.opendev.org/q/owner:${reviewer.gerrit_account_id}`,
    repository_id: repositoryId,
    source_id: "",
    first_seen_at: new Date().toISOString(),
    last_seen_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
}

const metadataDocs = approvalRows.map((row) => {
  const author = authorsByExternal.get(row.reviewer_key) || {};
  const id = `metadata-${stableHash([
    "review.approval_line_survival.change",
    repositoryId,
    row.raw_record_id,
    row.reviewer_key,
    row.approval_message_id,
    row.approval_label,
    row.approval_value,
    row.commit_sha,
  ].join("|"))}`;
  return {
    id,
    repository_id: row.repository_id,
    source_id: row.source_id,
    ingestion_job_id: row.ingestion_job_id,
    raw_record_id: row.raw_record_id,
    subject_type: "raw_record",
    subject_id: row.raw_record_id,
    namespace: "review.approval_line_survival",
    key: "change",
    value_type: "object",
    value: {
      change_number: row.change_number,
      change_id: row.change_id,
      project: row.project,
      branch: row.branch,
      status: row.status,
      subject: row.subject,
      owner_account_id: row.owner_account_id,
      commit_sha: row.commit_sha,
      approval_message_id: row.approval_message_id,
      approval_patch_set: row.approval_patch_set,
      approval_date: row.approval_date,
      reviewer_key: row.reviewer_key,
      reviewer_author_id: author.id || "",
      gerrit_account_id: row.gerrit_account_id,
      reviewer_name: row.reviewer_name,
      reviewer_email: row.reviewer_email,
      reviewer_username: row.reviewer_username,
      label: row.approval_label,
      value: row.approval_value,
      raw: row.approval_raw,
      labels: row.labels,
      review_insertions: row.review_insertions,
      review_deletions: row.review_deletions,
      review_changed_lines: row.review_changed_lines,
      max_review_changed_lines: maxReviewChangedLines,
      line_survival_branch: row.line_survival_branch,
      line_survival_head_sha: row.line_survival_head_sha,
      line_survival_max_changed_lines: row.line_survival_max_changed_lines,
      commit_insertions_tracked: row.commit_insertions_tracked,
      commit_deletions_tracked: row.commit_deletions_tracked,
      surviving_lines: row.surviving_lines,
      cross_author_overwritten_lines: row.cross_author_overwritten_lines,
      self_reworked_lines: row.self_reworked_lines,
      line_survival_rate: row.line_survival_rate,
      cross_author_overwrite_rate: row.cross_author_overwrite_rate,
      self_rework_rate: row.self_rework_rate,
      source: "gerrit_message_code_review_vote",
    },
    source_created_at: row.approval_date,
    source_updated_at: row.approval_date,
    imported_at: new Date().toISOString(),
    last_seen_at: new Date().toISOString(),
  };
});

const summaryDocs = summaryRows(approvalRows, authorsByExternal).map((summary) => ({
  id: `metadata-${stableHash(["review.approval_line_survival.summary", repositoryId, summary.reviewer_key].join("|"))}`,
  repository_id: repositoryId,
  source_id: summary.source_id,
  ingestion_job_id: summary.ingestion_job_id,
  raw_record_id: summary.raw_record_id,
  subject_type: "author",
  subject_id: summary.reviewer_author_id,
  namespace: "review.approval_line_survival",
  key: "summary",
  value_type: "object",
  value: summary,
  source_created_at: new Date().toISOString(),
  source_updated_at: new Date().toISOString(),
  imported_at: new Date().toISOString(),
  last_seen_at: new Date().toISOString(),
}));

let deletedMetadataRows = 0;
if (!dryRun) {
  if (replaceExisting) {
    deletedMetadataRows = deleteExistingApprovalSurvivalRows(repositoryId);
  }
  upsertRecords("authors", authorDocs);
  upsertRecords("metadata", [...metadataDocs, ...summaryDocs]);
}

console.log(JSON.stringify({
  repository_id: repositoryId,
  line_survival_json: lineSurvivalPath,
  dry_run: dryRun,
  replace_existing: replaceExisting,
  max_review_changed_lines: maxReviewChangedLines,
  raw_merged_changes: rawChanges.length,
  line_survival_commits: commitStatsBySha.size,
  existing_metadata_rows: existingMetadataRows,
  deleted_metadata_rows: deletedMetadataRows,
  approvals_found: approvalRows.length,
  change_metadata_rows: metadataDocs.length,
  reviewer_summary_rows: summaryDocs.length,
  authors_created: authorDocs.length,
  skipped_no_approval: skippedNoApproval,
  skipped_large_change: skippedLargeChange,
  skipped_no_survival_commit: skippedNoSurvivalCommit,
}, null, 2));

function approvalsFromMessage(message) {
  const firstLine = String(message?.message || "").split(/\r?\n/, 1)[0] || "";
  const patchMatch = firstLine.match(/^Patch Set\s+(\d+):\s+(.*)$/);
  if (!patchMatch) return [];
  const rest = patchMatch[2] || "";
  const codeReviewMatches = Array.from(rest.matchAll(/\bCode-Review([+][12])\b/g));
  if (!codeReviewMatches.length) return [];
  const labels = [];
  for (const match of codeReviewMatches) {
    labels.push({ label: "Code-Review", value: Number.parseInt(match[1], 10), raw: `Code-Review${match[1]}` });
  }
  for (const match of rest.matchAll(/\bWorkflow([+]1)\b/g)) {
    labels.push({ label: "Workflow", value: Number.parseInt(match[1], 10), raw: `Workflow${match[1]}` });
  }
  return codeReviewMatches.map((match) => ({
    patchSet: Number.parseInt(patchMatch[1], 10),
    label: "Code-Review",
    value: Number.parseInt(match[1], 10),
    raw: `Code-Review${match[1]}`,
    labels,
  }));
}

function reviewerFromMessageAuthor(author) {
  const accountId = String(author?._account_id || "").trim();
  return {
    accountId,
    name: stringValue(author?.name),
    email: stringValue(author?.email),
    username: stringValue(author?.username),
  };
}

function existingAuthorsByExternal(externalIds) {
  const ids = externalIds.filter(Boolean);
  if (!ids.length) return new Map();
  const rows = queryJson(`
    select coalesce(jsonb_agg(jsonb_build_object(
      'id', id,
      'external_author_id', doc->>'external_author_id',
      'display_name', coalesce(doc->>'display_name', doc->>'name', doc->>'email', doc->>'username', id)
    )), '[]'::jsonb)::text
    from repointel_records
    where collection = 'authors'
      and doc->>'external_author_id' in (${sqlInList(ids)});
  `);
  return new Map(rows.map((row) => [String(row.external_author_id), row]));
}

function existingApprovalSurvivalRows(repoId) {
  const rows = queryJson(`
    select jsonb_build_object('count', count(*))::text
    from repointel_records
    where collection = 'metadata'
      and doc->>'repository_id' = ${sqlLiteral(repoId)}
      and doc->>'namespace' = 'review.approval_line_survival';
  `);
  return numberValue(rows.count);
}

function deleteExistingApprovalSurvivalRows(repoId) {
  const rows = queryJson(`
    with deleted as (
      delete from repointel_records
      where collection = 'metadata'
        and doc->>'repository_id' = ${sqlLiteral(repoId)}
        and doc->>'namespace' = 'review.approval_line_survival'
      returning 1
    )
    select jsonb_build_object('count', count(*))::text
    from deleted;
  `);
  return numberValue(rows.count);
}

function summaryRows(rows, authorsByExternal) {
  const byReviewer = new Map();
  for (const row of rows) {
    if (!byReviewer.has(row.reviewer_key)) {
      byReviewer.set(row.reviewer_key, {
        reviewer_key: row.reviewer_key,
        gerrit_account_ids: [row.gerrit_account_id],
        reviewer_name: row.reviewer_name,
        reviewer_email: row.reviewer_email,
        reviewer_username: row.reviewer_username,
        reviewer_author_id: String(authorsByExternal.get(row.reviewer_key)?.id || ""),
        source_id: row.source_id,
        ingestion_job_id: row.ingestion_job_id,
        raw_record_id: row.raw_record_id,
        branch,
        head_sha: headSha,
        max_review_changed_lines: maxReviewChangedLines,
        line_survival_max_changed_lines: maxChangedLines,
        approvals_count: 0,
        reviewed_changes: new Set(),
        approved_commits: new Set(),
        labels: new Map(),
        insertions_tracked: 0,
        deletions_tracked: 0,
        surviving_lines: 0,
        cross_author_overwritten_lines: 0,
        self_reworked_lines: 0,
      });
    }
    const summary = byReviewer.get(row.reviewer_key);
    summary.approvals_count += 1;
    summary.reviewed_changes.add(row.change_number);
    summary.approved_commits.add(row.commit_sha);
    summary.insertions_tracked += row.commit_insertions_tracked;
    summary.deletions_tracked += row.commit_deletions_tracked;
    summary.surviving_lines += row.surviving_lines;
    summary.cross_author_overwritten_lines += row.cross_author_overwritten_lines;
    summary.self_reworked_lines += row.self_reworked_lines;
    for (const label of row.labels || []) {
      const key = `${label.label}:${label.value}`;
      summary.labels.set(key, {
        label: label.label,
        value: label.value,
        count: (summary.labels.get(key)?.count || 0) + 1,
      });
    }
  }
  return Array.from(byReviewer.values()).map((summary) => {
    const insertions = summary.insertions_tracked;
    return {
      ...summary,
      reviewed_changes_count: summary.reviewed_changes.size,
      approved_commits_count: summary.approved_commits.size,
      reviewed_changes: undefined,
      approved_commits: undefined,
      labels: Array.from(summary.labels.values()).sort((left, right) =>
        left.label.localeCompare(right.label) || right.value - left.value
      ),
      line_survival_rate: ratio(summary.surviving_lines, insertions),
      cross_author_overwrite_rate: ratio(summary.cross_author_overwritten_lines, insertions),
      self_rework_rate: ratio(summary.self_reworked_lines, insertions),
    };
  }).map(cleanUndefined);
}

function upsertRecords(collection, docs) {
  if (!docs.length) return;
  const chunkSize = 250;
  for (let index = 0; index < docs.length; index += chunkSize) {
    const chunk = docs.slice(index, index + chunkSize).map((doc) => ({ id: doc.id, doc }));
    const jsonText = JSON.stringify(chunk);
    const sql = `
      with rows as (
        select *
        from jsonb_to_recordset($repointel_json$${jsonText}$repointel_json$::jsonb)
          as row(id text, doc jsonb)
      )
      insert into repointel_records(collection, id, doc, created_at, updated_at)
      select ${sqlLiteral(collection)}, id, doc, now(), now()
      from rows
      on conflict (collection, id) do update
      set doc = excluded.doc,
          updated_at = now();
    `;
    runPsql(sql);
  }
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
    if (arg === "--no-replace-existing") {
      parsed.noReplaceExisting = true;
      continue;
    }
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    parsed[key] = args[index + 1];
    index += 1;
  }
  return parsed;
}

function integerOption(...values) {
  for (const value of values) {
    if (value === undefined || value === null || value === "") continue;
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function ratio(numerator, denominator) {
  const den = numberValue(denominator);
  if (!den) return 0;
  return Math.round((numberValue(numerator) / den) * 10000) / 10000;
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

function sqlInList(values = []) {
  const unique = Array.from(new Set(values.map((value) => String(value || "").trim()).filter(Boolean)));
  return unique.length ? unique.map(sqlLiteral).join(",") : "''";
}

function cleanUndefined(value) {
  return JSON.parse(JSON.stringify(value));
}

function fail(message) {
  console.error(message);
  process.exit(2);
}
