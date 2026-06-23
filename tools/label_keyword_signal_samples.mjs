#!/usr/bin/env node
import fs from "node:fs";

const [inputPath, outputJsonlPath, outputMarkdownPath] = process.argv.slice(2);

if (!inputPath || !outputJsonlPath || !outputMarkdownPath) {
  console.error("usage: node tools/label_keyword_signal_samples.mjs <samples.jsonl> <labeled.jsonl> <summary.md>");
  process.exit(2);
}

const samples = fs
  .readFileSync(inputPath, "utf8")
  .trim()
  .split(/\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line));

const goIndexes = new Map(
  Object.entries({
    regression: [1, 2, 3, 5, 6, 7, 8, 9, 10],
    regressed: [1, 2],
    "introduced by": [1, 2, 3, 4],
    "introduced in": [2, 6, 9],
    "introduced with": [1, 2, 3, 4],
    "caused by": [1, 2, 3, 4],
    "started failing": [1],
    "previously worked": [],
    "no longer works": [],
    "stopped working": [2, 4],
    "since commit": [],
    "since change": [1],
    "after change": [1, 2, 3, 4, 5],
    "after upgrade": [1, 2, 3, 5],
    "after backport": [1, 2, 3, 4, 5],
    culprit: [1, 2, 3, 4, 5],
    revert: [1, 2, 4, 5, 9, 11, 12, 13, 14, 15, 17],
    reverted: [1, 2, 3, 4, 5, 6],
    reverting: [],
    "backed out": [1],
    rollback: [],
    "rolled back": [1, 4],
    "revert this": [1, 2, 3, 4, 5],
    "revert of": [2],
    "follow-up fix": [1, 2, 3],
    fixup: [],
    breaks: [37, 40],
    broke: [1, 5],
    fallout: [1, 2, 3, 4, 5],
    "root cause": [1, 2, 3, 4, 5],
  }).map(([keyword, indexes]) => [keyword, new Set(indexes)])
);

const labeled = samples.map((sample) => {
  const decision = decide(sample);
  return {
    ...sample,
    reviewer_decision: decision.decision,
    reviewer_notes: decision.notes,
  };
});

fs.writeFileSync(outputJsonlPath, labeled.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");
fs.writeFileSync(outputMarkdownPath, renderSummary(labeled), "utf8");

console.log(JSON.stringify(summaryRows(labeled), null, 2));

function decide(sample) {
  if (sample.keyword === "Change abandoned by" || sample.keyword === "abandoned") {
    return decideAbandoned(sample);
  }

  const goSet = goIndexes.get(sample.keyword);
  if (!goSet) {
    return { decision: "no-go", notes: "keyword was not in the manually reviewed signal map" };
  }
  if (goSet.has(sample.sample_index)) {
    return { decision: "go", notes: noteForGo(sample.keyword) };
  }
  return { decision: "no-go", notes: noteForNoGo(sample.keyword) };
}

function decideAbandoned(sample) {
  const text = `${sample.bug_title || ""} ${sample.ref_context || ""}`.toLowerCase();
  if (
    /(end of life|about to be deleted|branch.*deleted|all open patches need to be abandoned|completed in change|duplicat|more comprehensive approach|merged changes to|new branch is created|move the patch|moved the patch|moved? to .*plugin|same as|already fixed|superseded)/i.test(text)
  ) {
    return { decision: "no-go", notes: "abandon appears administrative, duplicate, superseded, or already completed" };
  }
  return { decision: "go", notes: "abandoned review is useful failed-proposal/review-lifecycle evidence" };
}

function noteForGo(keyword) {
  if (/(introduced|caused|culprit|regress|after|since|started|stopped)/i.test(keyword)) {
    return "sample context links the review/SHA to a regression, cause, version-change, or suspicious code location";
  }
  if (/(revert|backed out|rolled back|follow-up|fallout|broke|breaks)/i.test(keyword)) {
    return "sample context links the review/SHA to revert, bad-fix, fallout, or breakage evidence";
  }
  if (keyword === "root cause") return "sample context explicitly identifies root cause near the ref";
  return "sample context carries useful signal";
}

function noteForNoGo(keyword) {
  if (keyword === "breaks") return "mostly title-only or unrelated commit-list matches, not signal for the sampled ref";
  if (keyword === "rollback" || keyword === "reverting" || keyword === "fixup") return "mostly domain/test/commit-message wording, not bad-fix evidence";
  if (keyword === "introduced in") return "often feature/version-introduction wording, not regression cause for the sampled ref";
  if (keyword === "since commit") return "sampled contexts were cleanup/metadata relationships, not issue-cause evidence";
  if (keyword === "previously worked") return "sampled phrase was 'previously worked around', not prior behavior evidence";
  if (keyword === "no longer works") return "sampled phrase was mostly author-employment/admin wording or token noise";
  return "sample context did not make the sampled ref useful evidence for this keyword bucket";
}

function summaryRows(rows) {
  const byKeyword = new Map();
  for (const row of rows) {
    const key = `${row.group}\0${row.keyword}`;
    if (!byKeyword.has(key)) {
      byKeyword.set(key, {
        group: row.group,
        keyword: row.keyword,
        rows: row.keyword_total_rows,
        sample: row.keyword_sample_rows,
        go: 0,
        no_go: 0,
      });
    }
    const entry = byKeyword.get(key);
    if (row.reviewer_decision === "go") entry.go += 1;
    else entry.no_go += 1;
  }
  return [...byKeyword.values()].map((entry) => ({
    ...entry,
    real_signal_pct: entry.sample ? Math.round((entry.go / entry.sample) * 1000) / 10 : 0,
  }));
}

function renderSummary(rows) {
  const lines = [];
  lines.push("# Keyword Signal Sample Labels");
  lines.push("");
  lines.push(`Input: \`${inputPath}\``);
  lines.push(`Labeled JSONL: \`${outputJsonlPath}\``);
  lines.push("");
  lines.push("Decision standard: `go` means the sampled ref occurrence carries useful signal for that keyword bucket; `no-go` means the word matched but the occurrence is title-only, administrative, duplicated lifecycle noise, or semantically unrelated to the sampled ref.");
  lines.push("");
  lines.push("Group | Keyword | Rows | Sample | Go | No-Go | Real Signal %");
  for (const row of summaryRows(rows)) {
    lines.push(`${row.group} | ${row.keyword} | ${row.rows.toLocaleString()} | ${row.sample.toLocaleString()} | ${row.go.toLocaleString()} | ${row.no_go.toLocaleString()} | ${row.real_signal_pct.toFixed(1)}%`);
  }
  lines.push("");
  lines.push("## Row Labels");
  for (const row of rows) {
    lines.push(`- ${row.group} | ${row.keyword} | sample ${row.sample_index}/${row.keyword_sample_rows} | ${row.reviewer_decision} | ${row.repository_name} bug ${row.bug_id} | ${row.ref_type}:${row.ref_value} | ${row.reviewer_notes}`);
  }
  return `${lines.join("\n")}\n`;
}
