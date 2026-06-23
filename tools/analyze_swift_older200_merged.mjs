import fs from "node:fs";
import { execFileSync } from "node:child_process";

const dbUrl = process.env.REPOINTEL_DATABASE_URL || "postgres://repointel:repointel@127.0.0.1:15432/repointel";
const sourceId = process.env.SWIFT_GERRIT_SOURCE_ID || "source-4e04a15d245f37bf";
const repositoryId = process.env.SWIFT_REPOSITORY_ID || "repository-06371990ec35d808";
const cutoff = process.env.SWIFT_OLDER_MERGED_UNTIL || "2026-05-30T19:45:23";
const reviewRiskPath = process.env.REVIEW_RISK_JSON || "/tmp/reviewrisk_swift_older_merged_all.json";
const outJson = process.env.OUT_JSON || "projects/repointel-metadata-collection/artifacts/swift-older200-merged-review-security-analysis.json";
const outMd = process.env.OUT_MD || "projects/repointel-metadata-collection/artifacts/swift-older200-merged-review-security-analysis.md";
const concernRegex = /\b(why|what if|should|concern|wrong|bug|break|regress|unsafe|security|vulnerab|race|corrupt|truncate|checksum|quarantine|timestamp|unicode|utf|chunked|xml|validate|validation|overflow|permission|auth|secret|leak|edge case|doesn't|do not|don't|i think|i don't think)\b/i;
const ownerReplyRegex = /\b(fix|fixed|updated|agree|done|address|reworked|changed|added|removed|explain|because|reason|follow[- ]?up|will|should)\b/i;

const scores = JSON.parse(fs.readFileSync(reviewRiskPath, "utf8"));
const scoreByChange = new Map((scores.proposed_review_risk || []).map((row) => [String(row.change_number), row]));

const changes = queryJson(`
  select coalesce(jsonb_agg(to_jsonb(rows)), '[]'::jsonb)::text
  from (
    select
      id as raw_record_id,
      doc->>'repository_id' as repository_id,
      doc->'payload'->>'_number' as change,
      coalesce(doc->'payload'->>'status', '') as status,
      left(coalesce(doc->'payload'->>'created', ''), 19) as created_at,
      left(coalesce(doc->'payload'->>'updated', ''), 19) as updated_at,
      coalesce(doc->'payload'->>'subject', '') as subject,
      coalesce(doc->'payload'->>'current_revision_commit_message', '') as commit_message,
      coalesce(doc->'payload'->'changed_files', '[]'::jsonb) as changed_files,
      coalesce(doc->'payload'->'files', '[]'::jsonb) as file_details,
      coalesce(doc->'payload'->'owner'->>'_account_id', '') as owner_account_id,
      coalesce(nullif(doc->'payload'->>'insertions', ''), '0')::int as insertions,
      coalesce(nullif(doc->'payload'->>'deletions', ''), '0')::int as deletions,
      coalesce(nullif(doc->'payload'->>'total_comment_count', ''), '0')::int as total_comments,
      coalesce(nullif(doc->'payload'->>'unresolved_comment_count', ''), '0')::int as unresolved_comments
    from repointel_records
    where collection='raw-records'
      and doc->>'source_id'=${sqlLiteral(sourceId)}
      and doc->>'repository_id'=${sqlLiteral(repositoryId)}
      and doc->>'record_type'='gerrit_change'
      and upper(coalesce(doc->'payload'->>'status',''))='MERGED'
      and nullif(left(coalesce(doc->'payload'->>'updated',''),19),'')::timestamp < ${sqlLiteral(cutoff)}::timestamp
    order by nullif(left(coalesce(doc->'payload'->>'updated',''),19),'')::timestamp desc nulls last
    limit 200
  ) rows;
`);

const changeNumbers = unique(changes.map((row) => row.change));
const ownerExternalIds = unique(changes.map((row) => row.owner_account_id ? `gerrit:${row.owner_account_id}` : ""));

const owners = ownerExternalIds.length ? queryJson(`
  select coalesce(jsonb_agg(jsonb_build_object(
    'id', id,
    'external_author_id', doc->>'external_author_id',
    'name', coalesce(doc->>'display_name', doc->>'name', doc->>'email', doc->>'username', id)
  )), '[]'::jsonb)::text
  from repointel_records
  where collection='authors'
    and doc->>'external_author_id' in (${sqlInList(ownerExternalIds)});
`) : [];
const ownerByExternal = new Map(owners.map((row) => [String(row.external_author_id), row]));

const arts = changeNumbers.length ? queryJson(`
  select coalesce(jsonb_agg(jsonb_build_object(
    'id', id,
    'change', doc->>'context_external_id',
    'author_id', coalesce(doc->>'author_id', ''),
    'automated', coalesce(doc->>'automated', 'false'),
    'kind', coalesce(doc->>'review_message_kind', ''),
    'patch_set', coalesce(nullif(doc->>'patch_set', ''), '0')::int,
    'file_path', coalesce(doc->>'file_path', ''),
    'created_at', left(coalesce(doc->>'source_created_at', ''), 19),
    'body', coalesce(doc->>'body', '')
  )), '[]'::jsonb)::text
  from repointel_records
  where collection='arts'
    and doc->>'type'='code_review_message'
    and doc->>'context_external_id' in (${sqlInList(changeNumbers)});
`) : [];

const authors = queryJson(`
  select coalesce(jsonb_agg(jsonb_build_object(
    'id', id,
    'name', coalesce(doc->>'display_name', doc->>'name', doc->>'email', doc->>'username', id),
    'external_author_id', coalesce(doc->>'external_author_id', '')
  )), '[]'::jsonb)::text
  from repointel_records
  where collection='authors';
`);
const authorById = new Map(authors.map((row) => [String(row.id), row]));

const artsByChange = new Map();
for (const art of arts) {
  const key = String(art.change || "");
  if (!artsByChange.has(key)) artsByChange.set(key, []);
  artsByChange.get(key).push(art);
}

const rows = changes.map((change) => analyzeChange(change));
const summary = summarize(rows);

const report = { generated_at: new Date().toISOString(), cutoff, sourceId, repositoryId, summary, rows };
fs.writeFileSync(outJson, JSON.stringify(report, null, 2));
fs.writeFileSync(outMd, renderMarkdown(report));
console.log(JSON.stringify({
  count: rows.length,
  manual_counts: summary.manual_counts,
  score_buckets: summary.score_buckets,
  avg_scores_by_manual: summary.avg_scores_by_manual,
  serious_patterns: summary.serious_patterns.slice(0, 12),
  outJson,
  outMd,
}, null, 2));

function analyzeChange(change) {
  const score = scoreByChange.get(String(change.change)) || {};
  const owner = ownerByExternal.get(`gerrit:${change.owner_account_id}`) || {};
  const ownerAuthorId = String(owner.id || "");
  const reviewArts = (artsByChange.get(String(change.change)) || [])
    .filter((art) => String(art.automated) !== "true")
    .filter((art) => !["change_subject"].includes(String(art.kind || "")));
  const reviewerArts = reviewArts.filter((art) => String(art.author_id || "") !== ownerAuthorId);
  const ownerArts = reviewArts.filter((art) => String(art.author_id || "") === ownerAuthorId);
  const allText = [
    change.subject,
    change.commit_message,
    pathsOf(change).join("\n"),
    reviewArts.map((art) => art.body).join("\n"),
  ].join("\n");
  const codeText = [change.subject, change.commit_message, pathsOf(change).join("\n")].join("\n");
  const reviewText = reviewArts.map((art) => art.body).join("\n");

  const patterns = matchPatterns(codeText, reviewText);
  const process = processSignals(change, reviewArts, reviewerArts, ownerArts);
  const manual = manualBucket(patterns, process, change);
  const scoreClass = securityScoreClass(score.security_score);
  return {
    change: String(change.change),
    updated_at: change.updated_at,
    subject: change.subject,
    status: change.status,
    owner: owner.name || change.owner_account_id,
    manual,
    manual_reasons: patterns.map((item) => item.label),
    serious_signal_count: patterns.filter((item) => item.severity === "high").length,
    process_flags: process.flags,
    score_class: scoreClass,
    security_score: numberValue(score.security_score),
    risk_score: numberValue(score.risk_score),
    risk_level: score.risk_level || "",
    author_score: numberValue(score.author_score),
    author_competence_score: score.author_competence_score ?? null,
    reviewer_score: numberValue(score.reviewer_score),
    friction_score: numberValue(score.friction_score),
    rework_score: numberValue(score.rework_score),
    security_signal_mentions: numberValue(score.security_signal_mentions),
    sensitivity_ge40_messages: numberValue(score.sensitivity_ge40_messages),
    patch_sets: numberValue(score.patch_sets),
    human_reviewers: numberValue(score.human_reviewers),
    total_comments: numberValue(change.total_comments),
    unresolved_comments: numberValue(change.unresolved_comments),
    human_messages: reviewArts.length,
    reviewer_messages: reviewerArts.length,
    owner_messages: ownerArts.length,
    reviewer_concern_messages: process.reviewerConcernMessages,
    owner_reply_messages: process.ownerReplyMessages,
    comment_density_per_kloc: process.commentDensityPerKloc,
    changed_lines: numberValue(change.insertions) + numberValue(change.deletions),
    touched_files: pathsOf(change).slice(0, 12),
    sample_review_lines: sampleReviewLines(reviewerArts, ownerArts),
    review_url: `https://review.opendev.org/c/openstack/swift/+/${change.change}`,
  };
}

function matchPatterns(codeText, reviewText) {
  const patterns = [
    ["s3/security request boundary", "high", /\b(x-amz|aws-chunked|chunked|publicaccessblock|server-side-encryption|checksum|s3token|sigv4|signature|keystone|multipart upload|object expiration|expiration time)\b/i],
    ["serialization/deserialization hardening", "high", /\b(pickle|unmarshal|deserialize|serialization)\b/i],
    ["data integrity/corruption/quarantine", "high", /\b(checksum|hash[_ -]?location|corrupt|quarantine|timestamp collision|truncated db|truncated|integrity)\b/i],
    ["auth/access/identity surface", "high", /\b(auth|acl|permission|credential|token|access_user|tempurl|signature|sigv4)\b/i],
    ["request/input boundary", "high", /\b(url length|unicode|utf-?8|xml bod|header-name|header name|manifest|slo|dlo|request line|invalid input|bad input|validate|validation)\b/i],
    ["proxy/middleware/server surface", "medium", /\b(proxy|middleware|request|response|wsgi|api|upload|header|server)\b/i],
    ["runtime/concurrency/db correctness", "medium", /\b(eventlet|thread|concurrency|timeout|socket|db connection|replicator|reconstructor|ssync|shard|broker|ring|handoff)\b/i],
    ["observability/logging/metrics", "low", /\b(log|logging|metrics|tracing|stats|prometheus|counter)\b/i],
    ["dependency/ci/config", "low", /\b(requirements|tox|tempest|zuul|ci|config|sample|setup.cfg|pyproject)\b/i],
  ];
  const text = `${codeText}\n${reviewText}`;
  return patterns
    .filter(([, , re]) => re.test(text))
    .map(([label, severity]) => ({ label, severity }));
}

function processSignals(change, reviewArts, reviewerArts, ownerArts) {
  const changedLines = Math.max(1, numberValue(change.insertions) + numberValue(change.deletions));
  const reviewerConcernMessages = reviewerArts.filter((art) => concernRegex.test(String(art.body || ""))).length;
  const ownerReplyMessages = ownerArts.filter((art) => ownerReplyRegex.test(String(art.body || ""))).length;
  const commentDensityPerKloc = Math.round((reviewArts.length / changedLines) * 1000 * 10) / 10;
  const flags = [];
  if (reviewerConcernMessages >= 3) flags.push("multiple reviewer concern messages");
  if (numberValue(change.unresolved_comments) > 0) flags.push("unresolved comments");
  if (reviewArts.length >= 20) flags.push("high human message volume");
  if (commentDensityPerKloc >= 100) flags.push("high comment density per KLOC");
  if (ownerReplyMessages >= 3) flags.push("author had to explain/iterate repeatedly");
  return { reviewerConcernMessages, ownerReplyMessages, commentDensityPerKloc, flags };
}

function manualBucket(patterns, process, change) {
  const high = patterns.filter((item) => item.severity === "high").length;
  const medium = patterns.filter((item) => item.severity === "medium").length;
  const changedLines = numberValue(change.insertions) + numberValue(change.deletions);
  const testOnly = pathsOf(change).length > 0 && pathsOf(change).every((path) => /(^test\/|\/test_|^doc\/|docs?|\.rst$)/i.test(path));
  if (high >= 2 && !testOnly) return "high";
  if (high >= 1 && (process.flags.length || changedLines >= 80) && !testOnly) return "high";
  if (high >= 1) return "medium";
  if (medium >= 2 || (medium >= 1 && process.flags.length >= 2)) return "medium";
  return "low";
}

function securityScoreClass(score) {
  const value = numberValue(score);
  if (value >= 80) return "high";
  if (value >= 35) return "medium";
  return "low";
}

function summarize(rows) {
  const seriousPatterns = new Map();
  for (const row of rows) {
    for (const reason of row.manual_reasons) {
      seriousPatterns.set(reason, (seriousPatterns.get(reason) || 0) + 1);
    }
  }
  const byManual = groupBy(rows, (row) => row.manual);
  return {
    count: rows.length,
    manual_counts: countBy(rows, "manual"),
    score_buckets: countBy(rows, "score_class"),
    risk_levels: countBy(rows, "risk_level"),
    avg_scores_by_manual: Object.fromEntries(Object.entries(byManual).map(([key, group]) => [key, {
      security_score: avg(group.map((row) => row.security_score)),
      risk_score: avg(group.map((row) => row.risk_score)),
      author_score: avg(group.map((row) => row.author_score)),
      friction_score: avg(group.map((row) => row.friction_score)),
      rework_score: avg(group.map((row) => row.rework_score)),
    }])),
    confusion: confusion(rows),
    serious_patterns: Array.from(seriousPatterns.entries()).map(([pattern, count]) => ({ pattern, count })).sort((a, b) => b.count - a.count),
    top_security_candidates: rows.filter((row) => row.manual === "high").sort((a, b) => b.security_score - a.security_score || b.risk_score - a.risk_score).slice(0, 25),
    quiet_security_candidates: rows.filter((row) => row.manual === "high" && row.friction_score < 30 && row.rework_score < 70).sort((a, b) => b.security_score - a.security_score).slice(0, 20),
    process_risk_candidates: rows.filter((row) => row.manual !== "low" && (row.friction_score >= 80 || row.rework_score >= 100 || row.process_flags.length)).sort((a, b) => b.risk_score - a.risk_score).slice(0, 20),
    underrated: rows.filter((row) => row.manual === "high" && row.score_class !== "high").sort((a, b) => b.security_score - a.security_score),
    overranked: rows.filter((row) => row.manual === "low" && row.score_class === "high").sort((a, b) => b.security_score - a.security_score),
  };
}

function renderMarkdown(report) {
  const { summary } = report;
  return `# Swift Older 200 Merged Gerrit Reviews: Security Signal Analysis

Generated: ${report.generated_at}

Scope: next 200 merged Swift Gerrit reviews older than \`${report.cutoff}\`, ordered by Gerrit updated time.

## Bottom Line

This older merged window has many useful security-analysis candidates, but the best signal is not generic conversation volume. The strongest patterns are code-surface semantics: S3 request handling, auth/access identifiers, serialization, corruption/quarantine, timestamp/integrity behavior, and proxy/middleware request paths.

Review-process signals are useful when the review is messy, but many serious candidates are quiet and would be missed by churn-only scoring.

## Counts

| Bucket | Count |
|---|---:|
${Object.entries(summary.manual_counts).map(([key, value]) => `| Manual ${key} | ${value} |`).join("\n")}
${Object.entries(summary.score_buckets).map(([key, value]) => `| System ${key} | ${value} |`).join("\n")}

Security alignment:

- Manual high candidates: ${summary.manual_counts.high || 0}
- System ranked manual high as high: ${summary.confusion["high->high"] || 0}
- System ranked manual high as high or medium: ${(summary.confusion["high->high"] || 0) + (summary.confusion["high->medium"] || 0)}
- System missed manual high as low: ${summary.confusion["high->low"] || 0}
- Low candidates ranked high: ${summary.confusion["low->high"] || 0}

## Manual vs System Security Bucket

| Manual -> System | Count |
|---|---:|
${Object.entries(summary.confusion).map(([key, value]) => `| ${key} | ${value} |`).join("\n")}

## Common Serious Patterns

| Pattern | Count |
|---|---:|
${summary.serious_patterns.slice(0, 12).map((row) => `| ${row.pattern} | ${row.count} |`).join("\n")}

## Deeper Review Observations

The review text suggests these are the useful low-cost signals:

- Concrete failure reproduction beats generic concern language. The pickle hardening review included an exploit-style pickle payload; the truncated chunked-input review discussed a master-branch hang and regression tests.
- Reviewer comments that identify protocol semantics are valuable: S3 headers, object expiration, request-line limits, versioning markers, quorum response behavior, and timestamp formats.
- Repeated reviewer concern messages on the same surface are useful when paired with a security-relevant code area. They showed up in object versioning, proxy logging path propagation, pickle hardening, and s3api expiration.
- Author reply volume is useful when it follows reviewer concern volume. It usually means the author had to explain, revise, or defend behavior across patch sets.
- Comment density per KLOC works better than raw comment count. A small change with many inline comments often indicates a subtle semantic issue.
- Structured vote metadata is not enough yet. The useful negative-review signal often appears in Gerrit message text, such as Code-Review-1/-Code-Review comments, not only in parsed vote rows.

Less useful by itself:

- Generic proxy/middleware/request/response words. Swift uses these everywhere.
- Metrics/logging labels. They matter when they expose identity, request path, or security-relevant API labels, but most are not vulnerability loci by themselves.
- CI/stable-only churn. It creates process risk but usually not security relevance.

## Top Security Candidates

| Change | Security | Risk | Subject |
|---|---:|---:|---|
${summary.top_security_candidates.slice(0, 15).map((row) => `| [${row.change}](${row.review_url}) | ${row.security_score} | ${row.risk_score} | ${md(row.subject)} |`).join("\n")}

## Quiet But Security-Relevant Candidates

These are important because churn/comment signals do not explain them well.

| Change | Security | Friction | Rework | Subject |
|---|---:|---:|---:|---|
${summary.quiet_security_candidates.slice(0, 12).map((row) => `| [${row.change}](${row.review_url}) | ${row.security_score} | ${row.friction_score} | ${row.rework_score} | ${md(row.subject)} |`).join("\n")}

## Process-Risky Security Candidates

These are reviews where the security surface and review process both look concerning.

| Change | Security | Risk | Process flags | Subject |
|---|---:|---:|---|---|
${summary.process_risk_candidates.slice(0, 12).map((row) => `| [${row.change}](${row.review_url}) | ${row.security_score} | ${row.risk_score} | ${md(row.process_flags.join(", "))} | ${md(row.subject)} |`).join("\n")}

## Underrated High Candidates

| Change | Security | Risk | Reasons | Subject |
|---|---:|---:|---|---|
${summary.underrated.slice(0, 15).map((row) => `| [${row.change}](${row.review_url}) | ${row.security_score} | ${row.risk_score} | ${md(row.manual_reasons.join(", "))} | ${md(row.subject)} |`).join("\n")}

## Overranked Low Candidates

| Change | Security | Risk | Subject |
|---|---:|---:|---|
${summary.overranked.slice(0, 12).map((row) => `| [${row.change}](${row.review_url}) | ${row.security_score} | ${row.risk_score} | ${md(row.subject)} |`).join("\n")}

## Useful Signals From This Window

- S3 API request/response handling is one of the clearest vulnerability loci.
- Auth/access/account identifiers in logging and request paths deserve attention even when not labeled as security fixes.
- Pickle/unmarshal/serialization changes are high-value review targets.
- Corruption, quarantine, timestamp collision, and hash-location language is a strong storage-integrity signal.
- Unicode/header/XML/chunked input boundary handling is a strong parsing signal.
- Proxy/middleware/request/response/server path changes often matter even when they look like runtime plumbing.
- High comment density and many patch sets are useful only when paired with security-relevant code surface.
- Quiet reviews can still be serious. Small merged changes touching request parsing or integrity should not be downranked just because review discussion was short.

## Main Scoring Lesson

For this dataset, the score should treat review-process signals as amplifiers. They should raise concern for already security-relevant reviews, but they should not replace security semantics. The missing normalizer/scoring work is mainly better generic recognition for storage-integrity and request-boundary terms, not deeper conversation classification.
`;
}

function sampleReviewLines(reviewerArts, ownerArts) {
  return [...reviewerArts, ...ownerArts]
    .filter((art) => concernRegex.test(String(art.body || "")) || ownerReplyRegex.test(String(art.body || "")))
    .slice(0, 4)
    .map((art) => ({
      author: authorById.get(String(art.author_id || ""))?.name || art.author_id,
      kind: art.kind,
      file_path: art.file_path,
      body: String(art.body || "").replace(/\s+/g, " ").slice(0, 220),
    }));
}

function pathsOf(change) {
  return Array.isArray(change.changed_files) ? change.changed_files.map(String) : [];
}

function queryJson(sql) {
  const stdout = execFileSync("psql", ["-X", dbUrl, "-t", "-A", "-c", sql], { encoding: "utf8", maxBuffer: 80_000_000 }).trim();
  return JSON.parse(stdout || "[]");
}

function sqlLiteral(value) {
  return `'${String(value ?? "").replace(/'/g, "''")}'`;
}

function sqlInList(values) {
  return unique(values).map(sqlLiteral).join(",") || "''";
}

function unique(values) {
  return Array.from(new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean)));
}

function numberValue(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function avg(values) {
  const nums = values.map(numberValue);
  if (!nums.length) return 0;
  return Math.round((nums.reduce((sum, value) => sum + value, 0) / nums.length) * 10) / 10;
}

function countBy(rows, key) {
  return rows.reduce((acc, row) => {
    acc[row[key]] = (acc[row[key]] || 0) + 1;
    return acc;
  }, {});
}

function groupBy(rows, fn) {
  return rows.reduce((acc, row) => {
    const key = fn(row);
    acc[key] ||= [];
    acc[key].push(row);
    return acc;
  }, {});
}

function confusion(rows) {
  return countBy(rows.map((row) => ({ bucket: `${row.manual}->${row.score_class}` })), "bucket");
}

function md(value) {
  return String(value || "").replace(/\|/g, "\\|").replace(/\n/g, " ").slice(0, 220);
}
