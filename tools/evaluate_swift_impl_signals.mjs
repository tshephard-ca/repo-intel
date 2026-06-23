import fs from "node:fs";
import { execFileSync } from "node:child_process";

const dbUrl = process.env.REPOINTEL_DATABASE_URL || "postgres://repointel:repointel@127.0.0.1:15432/repointel";
const analysisPath = process.env.ANALYSIS_JSON || "projects/repointel-metadata-collection/artifacts/swift-older200-merged-review-security-analysis.json";
const outJson = process.env.OUT_JSON || "projects/repointel-metadata-collection/artifacts/swift-older200-implementation-signal-evaluation.json";
const outMd = process.env.OUT_MD || "projects/repointel-metadata-collection/artifacts/swift-older200-implementation-signal-evaluation.md";

const concernRegex = /\b(why|what if|should|concern|wrong|bug|break|regress|unsafe|security|vulnerab|race|corrupt|truncate|checksum|quarantine|timestamp|unicode|utf|chunked|xml|validate|validation|overflow|permission|auth|secret|leak|edge case|doesn't|do not|don't|i think|i don't think|fails?|hang|infinite loop|should return|not sure|confus|does this|what happens)\b/i;
const responseRegex = /\b(fix|fixed|updated|agree|done|address|reworked|changed|added|removed|explain|because|reason|follow[- ]?up|will|should|rebased|tested|covered)\b/i;

const analysis = JSON.parse(fs.readFileSync(analysisPath, "utf8"));
const rows = analysis.rows || [];
const changeNumbers = rows.map((row) => row.change);
const rowByChange = new Map(rows.map((row) => [String(row.change), row]));

const ownerRows = queryJson(`
  with changes as (
    select
      doc->'payload'->>'_number' as change,
      coalesce(doc->'payload'->'owner'->>'_account_id', '') as owner_account_id
    from repointel_records
    where collection='raw-records'
      and doc->>'record_type'='gerrit_change'
      and doc->'payload'->>'_number' in (${sqlInList(changeNumbers)})
  )
  select coalesce(jsonb_agg(jsonb_build_object(
    'change', c.change,
    'owner_author_id', a.id
  )), '[]'::jsonb)::text
  from changes c
  left join repointel_records a
    on a.collection='authors'
   and a.doc->>'external_author_id' = 'gerrit:' || c.owner_account_id;
`);
const ownerByChange = new Map(ownerRows.map((row) => [String(row.change), String(row.owner_author_id || "")]));

const arts = queryJson(`
  select coalesce(jsonb_agg(jsonb_build_object(
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
`);

const artsByChange = new Map();
for (const art of arts) {
  if (String(art.automated) === "true") continue;
  if (String(art.kind) === "change_subject") continue;
  const key = String(art.change || "");
  if (!artsByChange.has(key)) artsByChange.set(key, []);
  artsByChange.get(key).push(art);
}

const enriched = rows.map((row) => ({ ...row, proposed_signals: computeSignals(row) }));
const evaluation = evaluate(enriched);

fs.writeFileSync(outJson, JSON.stringify({ generated_at: new Date().toISOString(), evaluation, rows: enriched }, null, 2));
fs.writeFileSync(outMd, renderMarkdown(evaluation));

console.log(JSON.stringify({
  count: enriched.length,
  signal_summary: evaluation.signal_summary,
  strongest: evaluation.strongest,
  weakest: evaluation.weakest,
  outJson,
  outMd,
}, null, 2));

function computeSignals(row) {
  const ownerAuthorId = ownerByChange.get(String(row.change)) || "";
  const messages = (artsByChange.get(String(row.change)) || []).slice().sort((a, b) =>
    String(a.created_at || "").localeCompare(String(b.created_at || "")) || Number(a.patch_set || 0) - Number(b.patch_set || 0)
  );
  const reviewerMessages = messages.filter((msg) => String(msg.author_id || "") !== ownerAuthorId);
  const authorMessages = messages.filter((msg) => String(msg.author_id || "") === ownerAuthorId);
  const concernMessages = reviewerMessages.filter((msg) => concernRegex.test(String(msg.body || "")));
  const firstConcern = concernMessages[0] || null;
  const touchedFileCount = Math.max(1, Array.isArray(row.touched_files) ? row.touched_files.length : 0);
  const changedLines = Math.max(1, Number(row.changed_lines || 0));
  const fileConcernCounts = new Map();
  for (const msg of concernMessages) {
    const file = String(msg.file_path || "");
    if (!file || file === "/PATCHSET_LEVEL" || file === "/COMMIT_MSG") continue;
    fileConcernCounts.set(file, (fileConcernCounts.get(file) || 0) + 1);
  }
  const firstConcernPatchSet = firstConcern ? Number(firstConcern.patch_set || 0) : 0;
  const maxPatchSet = Math.max(0, ...messages.map((msg) => Number(msg.patch_set || 0)), Number(row.patch_sets || 0));
  const afterFirstConcern = firstConcern
    ? messages.filter((msg) =>
        String(msg.created_at || "") >= String(firstConcern.created_at || "")
        || Number(msg.patch_set || 0) > firstConcernPatchSet
      )
    : [];
  const reviewerSpreadAfterFirstConcern = new Set(afterFirstConcern
    .filter((msg) => String(msg.author_id || "") !== ownerAuthorId)
    .map((msg) => String(msg.author_id || ""))
    .filter(Boolean)).size;
  const authorResponsesAfterConcern = firstConcern
    ? authorMessages.filter((msg) =>
        String(msg.created_at || "") >= String(firstConcern.created_at || "")
        || Number(msg.patch_set || 0) > firstConcernPatchSet
      ).filter((msg) => responseRegex.test(String(msg.body || ""))).length
    : 0;
  const concernDensityPerTouchedFile = concernMessages.length / touchedFileCount;
  const repeatedConcernFileCount = Array.from(fileConcernCounts.values()).filter((count) => count >= 2).length;
  const authorResponseRatio = concernMessages.length ? authorResponsesAfterConcern / concernMessages.length : 0;
  const patchSetsAfterFirstConcern = firstConcern ? Math.max(0, maxPatchSet - firstConcernPatchSet) : 0;
  return {
    concern_density_per_touched_file: round(concernDensityPerTouchedFile, 2),
    repeated_concern_file_count: repeatedConcernFileCount,
    author_response_ratio: round(authorResponseRatio, 2),
    reviewer_spread_after_first_concern: reviewerSpreadAfterFirstConcern,
    patch_sets_after_first_concern: patchSetsAfterFirstConcern,
    small_change_high_friction: changedLines <= 100 && (concernMessages.length >= 3 || concernDensityPerTouchedFile >= 1.5),
    concern_messages: concernMessages.length,
    author_responses_after_concern: authorResponsesAfterConcern,
    touched_file_count: touchedFileCount,
    changed_lines: changedLines,
  };
}

function evaluate(rows) {
  const signals = [
    {
      id: "concern_density_per_touched_file",
      label: "Concern density per touched file >= 1",
      hit: (row) => row.proposed_signals.concern_density_per_touched_file >= 1,
    },
    {
      id: "repeated_concerns_on_same_file",
      label: "Repeated concerns on same file",
      hit: (row) => row.proposed_signals.repeated_concern_file_count >= 1,
    },
    {
      id: "author_response_ratio",
      label: "Author response ratio >= 0.25 with >=3 concerns",
      hit: (row) => row.proposed_signals.concern_messages >= 3 && row.proposed_signals.author_response_ratio >= 0.25,
    },
    {
      id: "reviewer_spread_after_first_concern",
      label: "Reviewer spread after first concern >= 3",
      hit: (row) => row.proposed_signals.reviewer_spread_after_first_concern >= 3,
    },
    {
      id: "patch_set_churn_after_first_concern",
      label: "Patch sets after first concern >= 3",
      hit: (row) => row.proposed_signals.patch_sets_after_first_concern >= 3,
    },
    {
      id: "small_change_high_friction",
      label: "Small change high friction",
      hit: (row) => row.proposed_signals.small_change_high_friction,
    },
  ];
  const signalSummary = signals.map((signal) => summarizeSignal(rows, signal));
  const compositeRows = rows.map((row) => ({
    ...row,
    proposed_impl_score: signals.reduce((sum, signal) => sum + (signal.hit(row) ? 1 : 0), 0),
  }));
  return {
    signal_summary: signalSummary,
    strongest: signalSummary.slice().sort((a, b) => b.lift_high_vs_low - a.lift_high_vs_low).slice(0, 4),
    weakest: signalSummary.slice().sort((a, b) => a.lift_high_vs_low - b.lift_high_vs_low).slice(0, 4),
    composite: {
      high_avg: avg(compositeRows.filter((row) => row.manual === "high").map((row) => row.proposed_impl_score)),
      medium_avg: avg(compositeRows.filter((row) => row.manual === "medium").map((row) => row.proposed_impl_score)),
      low_avg: avg(compositeRows.filter((row) => row.manual === "low").map((row) => row.proposed_impl_score)),
      score_ge3_high: compositeRows.filter((row) => row.manual === "high" && row.proposed_impl_score >= 3).length,
      score_ge3_medium: compositeRows.filter((row) => row.manual === "medium" && row.proposed_impl_score >= 3).length,
      score_ge3_low: compositeRows.filter((row) => row.manual === "low" && row.proposed_impl_score >= 3).length,
    },
    top_impl: compositeRows
      .filter((row) => row.proposed_impl_score >= 3)
      .sort((a, b) => b.proposed_impl_score - a.proposed_impl_score || b.risk_score - a.risk_score)
      .slice(0, 25)
      .map(trimRow),
    quiet_security: compositeRows
      .filter((row) => row.manual === "high" && row.proposed_impl_score <= 1)
      .sort((a, b) => b.security_score - a.security_score)
      .slice(0, 20)
      .map(trimRow),
  };
}

function summarizeSignal(rows, signal) {
  const high = rows.filter((row) => row.manual === "high");
  const medium = rows.filter((row) => row.manual === "medium");
  const low = rows.filter((row) => row.manual === "low");
  const highHits = high.filter(signal.hit).length;
  const mediumHits = medium.filter(signal.hit).length;
  const lowHits = low.filter(signal.hit).length;
  const totalHits = rows.filter(signal.hit).length;
  const highRate = highHits / Math.max(1, high.length);
  const lowRate = lowHits / Math.max(1, low.length);
  return {
    id: signal.id,
    label: signal.label,
    hits: totalHits,
    high_hits: highHits,
    medium_hits: mediumHits,
    low_hits: lowHits,
    high_rate: round(highRate, 3),
    medium_rate: round(mediumHits / Math.max(1, medium.length), 3),
    low_rate: round(lowRate, 3),
    precision_high_or_medium: round((highHits + mediumHits) / Math.max(1, totalHits), 3),
    lift_high_vs_low: round(highRate / Math.max(0.001, lowRate), 2),
  };
}

function trimRow(row) {
  return {
    change: row.change,
    subject: row.subject,
    manual: row.manual,
    security_score: row.security_score,
    risk_score: row.risk_score,
    proposed_impl_score: row.proposed_impl_score,
    signals: row.proposed_signals,
  };
}

function renderMarkdown(evaluation) {
  return `# Swift Older 200: Proposed Implementation Signal Evaluation

This evaluates the proposed implementation-risk signals against the same older 200 merged Swift Gerrit reviews.

Important caveat: this uses manual security/process buckets as proxy labels. We do not have ground-truth "implementation was actually bad" labels.

## Signal Performance

| Signal | Hits | High hits | Medium hits | Low hits | High rate | Low rate | Lift high/low | Precision high+medium |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
${evaluation.signal_summary.map((row) => `| ${row.label} | ${row.hits} | ${row.high_hits} | ${row.medium_hits} | ${row.low_hits} | ${row.high_rate} | ${row.low_rate} | ${row.lift_high_vs_low} | ${row.precision_high_or_medium} |`).join("\n")}

## Composite

Simple composite = one point for each proposed signal that fires.

| Bucket | Avg proposed impl score |
|---|---:|
| High security-relevant | ${evaluation.composite.high_avg} |
| Medium security-relevant | ${evaluation.composite.medium_avg} |
| Low security-relevant | ${evaluation.composite.low_avg} |

Rows with composite >= 3:

| Bucket | Count |
|---|---:|
| High | ${evaluation.composite.score_ge3_high} |
| Medium | ${evaluation.composite.score_ge3_medium} |
| Low | ${evaluation.composite.score_ge3_low} |

## What This Means

The proposed signals help, especially when combined. They are not vulnerability indicators by themselves; they are implementation weakness indicators.

Best individual indicators:

- author response ratio with several concerns
- reviewer spread after first concern
- patch-set churn after first concern
- repeated concerns on the same file

Noisy but still useful:

- concern density per touched file
- small-change high-friction

The signals are strongest for finding reviews that looked hard to get right. They do not catch quiet security-relevant patches, such as s3token/token-flow changes with little discussion.

## Top Implementation-Risk Rows By Proposed Composite

| Change | Score | Manual | Security | Risk | Subject |
|---|---:|---|---:|---:|---|
${evaluation.top_impl.slice(0, 15).map((row) => `| ${row.change} | ${row.proposed_impl_score} | ${row.manual} | ${row.security_score} | ${row.risk_score} | ${md(row.subject)} |`).join("\n")}

## Quiet Security-Relevant Rows These Signals Miss

| Change | Score | Security | Risk | Subject |
|---|---:|---:|---:|---|
${evaluation.quiet_security.slice(0, 12).map((row) => `| ${row.change} | ${row.proposed_impl_score} | ${row.security_score} | ${row.risk_score} | ${md(row.subject)} |`).join("\n")}
`;
}

function queryJson(sql) {
  const stdout = execFileSync("psql", ["-X", dbUrl, "-t", "-A", "-c", sql], { encoding: "utf8", maxBuffer: 80_000_000 }).trim();
  return JSON.parse(stdout || "[]");
}

function sqlLiteral(value) {
  return `'${String(value ?? "").replace(/'/g, "''")}'`;
}

function sqlInList(values) {
  return Array.from(new Set(values.map((value) => String(value || "").trim()).filter(Boolean))).map(sqlLiteral).join(",") || "''";
}

function avg(values) {
  if (!values.length) return 0;
  return round(values.reduce((sum, value) => sum + Number(value || 0), 0) / values.length, 2);
}

function round(value, digits = 2) {
  const factor = 10 ** digits;
  return Math.round(Number(value || 0) * factor) / factor;
}

function md(value) {
  return String(value || "").replace(/\|/g, "\\|").replace(/\n/g, " ").slice(0, 220);
}
