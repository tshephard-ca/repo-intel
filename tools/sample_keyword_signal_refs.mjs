#!/usr/bin/env node
import fs from "node:fs";

const [inputPath, outputJsonlPath, outputMarkdownPath] = process.argv.slice(2);

if (!inputPath || !outputJsonlPath || !outputMarkdownPath) {
  console.error("usage: node tools/sample_keyword_signal_refs.mjs <refs.jsonl> <samples.jsonl> <samples.md>");
  process.exit(2);
}

const KEYWORDS = [
  {
    group: "Regression / Cause",
    keywords: [
      ["regression", /\bregression\b/i],
      ["regressed", /\bregressed\b/i],
      ["introduced by", /\bintroduced by\b/i],
      ["introduced in", /\bintroduced in\b/i],
      ["introduced with", /\bintroduced with\b/i],
      ["caused by", /\bcaused by\b/i],
      ["started failing", /\bstarted failing\b/i],
      ["previously worked", /\bpreviously worked\b/i],
      ["no longer works", /\bno longer works?\b/i],
      ["stopped working", /\bstopped working\b/i],
      ["since commit", /\bsince commit\b/i],
      ["since change", /\bsince change\b/i],
      ["after change", /\bafter change\b/i],
      ["after upgrade", /\bafter (?:an? )?upgrade\b/i],
      ["after backport", /\bafter (?:an? )?backport\b/i],
      ["culprit", /\bculprit\b/i],
    ],
  },
  {
    group: "Bad Fix / Revert",
    keywords: [
      ["revert", /\brevert\b/i],
      ["reverted", /\breverted\b/i],
      ["reverting", /\breverting\b/i],
      ["backed out", /\bbacked out\b/i],
      ["rollback", /\brollback\b/i],
      ["rolled back", /\brolled back\b/i],
      ["revert this", /\brevert this\b/i],
      ["revert of", /\brevert of\b/i],
      ["follow-up fix", /\bfollow-up fix\b/i],
      ["fixup", /\bfixup\b/i],
      ["breaks", /\bbreaks\b/i],
      ["broke", /\bbroke\b/i],
      ["fallout", /\bfallout\b/i],
    ],
  },
  {
    group: "Review Failure / Author Risk",
    keywords: [
      ["Change abandoned by", /\bChange abandoned by\b/i],
      ["abandoned", /\babandoned\b/i],
    ],
  },
  {
    group: "Confidence Boosters",
    keywords: [["root cause", /\broot cause\b/i]],
  },
];

const rows = fs
  .readFileSync(inputPath, "utf8")
  .trim()
  .split(/\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line));

const jsonl = [];
const markdown = [];

markdown.push("# Keyword Signal Samples");
markdown.push("");
markdown.push(`Input: \`${inputPath}\``);
markdown.push("");
markdown.push("Sampling rule: 10% of matching ref rows per keyword, minimum 5 samples when at least 5 rows exist; otherwise all rows.");
markdown.push("Sampling is deterministic by hash of keyword + artifact + ref target, so reruns are stable.");
markdown.push("");

for (const bucket of KEYWORDS) {
  markdown.push(`## ${bucket.group}`);
  markdown.push("");

  for (const [keyword, regex] of bucket.keywords) {
    const matches = rows.filter((row) => regex.test(searchText(row)));
    const sampleSize = Math.min(matches.length, Math.max(5, Math.ceil(matches.length * 0.1)));
    const samples = matches
      .map((row) => ({ row, sortKey: stableHash(`${keyword}\0${row.art_id}\0${row.ref_type}\0${row.ref_value}\0${row.ref_position}`) }))
      .sort((a, b) => a.sortKey - b.sortKey)
      .slice(0, sampleSize)
      .map((entry, index) => ({ ...entry.row, sample_index: index + 1 }));

    markdown.push(`### ${keyword}`);
    markdown.push("");
    markdown.push(`Count: ${matches.length.toLocaleString()} rows; sample: ${samples.length.toLocaleString()} rows`);
    markdown.push("");

    for (const sample of samples) {
      const record = {
        group: bucket.group,
        keyword,
        keyword_total_rows: matches.length,
        keyword_sample_rows: samples.length,
        sample_index: sample.sample_index,
        suggested_decision: "",
        reviewer_decision: "",
        reviewer_notes: "",
        repository_name: sample.repository_name,
        bug_id: sample.bug_id,
        bug_title: sample.bug_title,
        bug_url: sample.bug_url,
        message_url: sample.message_url,
        ref_type: sample.ref_type,
        ref_value: sample.ref_value,
        ref_url: sample.ref_url,
        role_hint: sample.role_hint,
        role_flags: sample.role_flags,
        ref_context: sample.ref_context,
      };
      jsonl.push(record);

      markdown.push(`- [ ] decision: go / no-go / maybe`);
      markdown.push(`  - repo: ${sample.repository_name || ""}; bug: ${sample.bug_id || ""}; ref: ${sample.ref_type || ""}:${sample.ref_value || ""}`);
      markdown.push(`  - title: ${oneLine(sample.bug_title)}`);
      markdown.push(`  - message: ${sample.message_url || sample.art_external_id || ""}`);
      if (sample.ref_url) markdown.push(`  - ref_url: ${sample.ref_url}`);
      markdown.push(`  - context: ${oneLine(sample.ref_context).slice(0, 700)}`);
    }
    markdown.push("");
  }
}

fs.writeFileSync(outputJsonlPath, jsonl.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");
fs.writeFileSync(outputMarkdownPath, markdown.join("\n") + "\n", "utf8");

const summary = {};
for (const row of jsonl) {
  const key = `${row.group} :: ${row.keyword}`;
  summary[key] = { total: row.keyword_total_rows, sample: row.keyword_sample_rows };
}

console.log(JSON.stringify({ inputPath, outputJsonlPath, outputMarkdownPath, sampledRows: jsonl.length, keywords: Object.keys(summary).length, summary }, null, 2));

function searchText(row) {
  return `${row.bug_title || ""}\n${row.ref_context || ""}\n${row.ref_text || ""}`;
}

function oneLine(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function stableHash(value) {
  let hash = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}
