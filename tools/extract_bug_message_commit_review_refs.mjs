#!/usr/bin/env node
import fs from "node:fs";
import readline from "node:readline";

const [inputPath, outputPath, summaryPath] = process.argv.slice(2);

if (!inputPath || !outputPath || !summaryPath) {
  console.error("usage: node tools/extract_bug_message_commit_review_refs.mjs <bug_messages.jsonl> <refs.jsonl> <summary.md>");
  process.exit(2);
}

const REGEXES = [
  {
    type: "commit_url",
    confidence: 0.98,
    regex: /https?:\/\/[^\s<>"')]*commit[^\s<>"')]*?([0-9a-fA-F]{12,40})[^\s<>"')]*/gi,
    value: (match) => match[1].toLowerCase(),
    url: (match) => trimUrl(match[0]),
    text: (match) => match[0],
    offset: (match) => match.index,
  },
  {
    type: "review_url",
    confidence: 0.96,
    regex: /https?:\/\/review\.(?:openstack|opendev)\.org[^\s<>"')]+/gi,
    value: (match) => firstReviewNumber(match[0]),
    url: (match) => trimUrl(match[0]),
    text: (match) => match[0],
    offset: (match) => match.index,
  },
  {
    type: "review_number_text",
    confidence: 0.72,
    regex: /\b(?:review|change|gerrit)\b[^0-9\n\r]{0,30}([0-9]{5,7})/gi,
    value: (match) => match[1],
    url: () => "",
    text: (match) => match[0],
    offset: (match) => match.index,
    skip: (match) => /review\.(openstack|opendev)\.org|change-id/i.test(match[0]),
  },
  {
    type: "gerrit_change_id",
    confidence: 0.94,
    regex: /\bI[0-9a-fA-F]{8,40}\b/g,
    value: (match) => match[0],
    url: () => "",
    text: (match) => match[0],
    offset: (match) => match.index,
  },
  {
    type: "commit_sha_contextual",
    confidence: 0.78,
    regex: /\b(?:commit|sha|revert|bisect|cherry[- ]?pick|backport|introduced|caused|culprit|merged|landed|committed)\b[^0-9a-fA-F]{0,80}([0-9a-fA-F]{12,40})\b/gi,
    value: (match) => match[1].toLowerCase(),
    url: () => "",
    text: (match) => match[0],
    offset: (match) => match.index,
  },
  {
    type: "commit_sha_full_unqualified",
    confidence: 0.55,
    regex: /(^|[^0-9a-fA-FI])([0-9a-fA-F]{40})(?=[^0-9a-fA-F]|$)/g,
    value: (match) => match[2].toLowerCase(),
    url: () => "",
    text: (match) => match[2],
    offset: (match) => match.index + match[1].length,
  },
  {
    type: "commit_sha_short_contextual",
    confidence: 0.64,
    regex: /\b(?:commit|sha|revert|bisect|cherry[- ]?pick|backport|introduced|caused|culprit|merged|landed)\b[^0-9a-fA-F]{0,50}([0-9a-fA-F]{7,11})\b/gi,
    value: (match) => match[1].toLowerCase(),
    url: () => "",
    text: (match) => match[0],
    offset: (match) => match.index,
  },
];

const counters = {
  messages: 0,
  refs: 0,
  bugs: new Set(),
  repos: new Set(),
  refType: new Map(),
  role: new Map(),
  kindRole: new Map(),
  repoRefs: new Map(),
};
const examples = new Map();
const output = fs.createWriteStream(outputPath, { encoding: "utf8" });

const rl = readline.createInterface({
  input: fs.createReadStream(inputPath, { encoding: "utf8" }),
  crlfDelay: Infinity,
});

for await (const line of rl) {
  if (!line.trim()) continue;
  const message = JSON.parse(line);
  counters.messages += 1;
  if (message.bug_id) counters.bugs.add(String(message.bug_id));
  if (message.repository_name) counters.repos.add(String(message.repository_name));
  for (const ref of extractRefs(message)) {
    counters.refs += 1;
    increment(counters.refType, ref.ref_type);
    increment(counters.role, ref.role_hint);
    increment(counters.kindRole, `${ref.bug_message_kind}:${ref.role_hint}`);
    increment(counters.repoRefs, ref.repository_name || ref.repository_id || "unknown");
    collectExample(ref);
    output.write(`${JSON.stringify(ref)}\n`);
  }
}

await new Promise((resolve) => output.end(resolve));
fs.writeFileSync(summaryPath, renderSummary(), "utf8");

function extractRefs(message) {
  const body = String(message.body || "");
  if (!body) return [];
  const refs = [];
  const seen = new Set();
  for (const spec of REGEXES) {
    spec.regex.lastIndex = 0;
    for (const match of body.matchAll(spec.regex)) {
      if (spec.skip?.(match)) continue;
      const refValue = spec.value(match);
      if (!refValue) continue;
      const refText = spec.text(match);
      const refOffset = spec.offset(match);
      const refUrl = spec.url(match);
      const key = `${spec.type}|${refValue}|${refOffset}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const context = contextAround(body, refOffset, refText.length);
      const roleFlags = classifyRoleFlags(context);
      refs.push({
        repository_id: message.repository_id || "",
        repository_name: message.repository_name || "",
        repository_slug: message.repository_slug || "",
        repository_url: message.repository_url || "",
        bug_id: message.bug_id || "",
        bug_url: message.bug_url || "",
        bug_title: message.bug_title || "",
        bug_status: message.bug_status || "",
        bug_importance: message.bug_importance || "",
        bug_created_at: message.bug_created_at || "",
        bug_last_updated_at: message.bug_last_updated_at || "",
        bug_last_message_at: message.bug_last_message_at || "",
        bug_raw_record_id: message.bug_raw_record_id || "",
        art_id: message.art_id || "",
        art_external_id: message.art_external_id || "",
        bug_message_kind: message.bug_message_kind || "",
        message_created_at: message.message_created_at || "",
        message_url: message.message_url || "",
        author_id: message.author_id || "",
        author_name: message.author_name || "",
        author_username: message.author_username || "",
        external_author_id: message.external_author_id || "",
        ref_type: spec.type,
        ref_value: refValue,
        ref_url: refUrl,
        ref_text: refText,
        ref_position: refOffset,
        confidence: spec.confidence,
        role_hint: roleFlags[0] || "unknown",
        role_flags: roleFlags,
        ref_context: squeezeWhitespace(context),
      });
    }
  }
  return refs;
}

function classifyRoleFlags(text) {
  const lower = text.toLowerCase();
  const flags = [];
  if (/(regression|regressed|introduced by|caused by|bisect|bisected|culprit|broke|broken|breaks|started failing|offending|since )/.test(lower)) {
    flags.push("regression_candidate");
  }
  if (/(revert|reverted|backed out|rollback)/.test(lower)) {
    flags.push("revert_candidate");
  }
  if (/(backport|cherry.?pick|stable\/|stable branch|proposed to stable)/.test(lower)) {
    flags.push("backport_candidate");
  }
  if (/(fix|fixed|fixes|resolved|committed|merged|landed|reviewed|closes|released|submitter)/.test(lower)) {
    flags.push("fix_candidate");
  }
  return flags;
}

function firstReviewNumber(text) {
  const match = String(text).match(/[0-9]{5,7}/);
  return match ? match[0] : "";
}

function trimUrl(text) {
  return String(text).replace(/[),.;]+$/g, "");
}

function contextAround(body, offset, length) {
  const start = Math.max(0, offset - 180);
  const end = Math.min(body.length, offset + length + 240);
  return body.slice(start, end);
}

function squeezeWhitespace(text) {
  return String(text).replace(/\s+/g, " ").trim();
}

function increment(map, key) {
  map.set(key, (map.get(key) || 0) + 1);
}

function collectExample(ref) {
  const role = ref.role_hint || "unknown";
  if (!examples.has(role)) examples.set(role, []);
  const list = examples.get(role);
  if (list.length < 6 && ref.ref_context) {
    list.push({
      bug_id: ref.bug_id,
      repository_name: ref.repository_name,
      ref_type: ref.ref_type,
      ref_value: ref.ref_value,
      bug_message_kind: ref.bug_message_kind,
      context: ref.ref_context,
    });
  }
}

function renderSummary() {
  const lines = [];
  lines.push("# Bug Message Commit/Review Reference Analysis");
  lines.push("");
  lines.push(`Input: \`${inputPath}\``);
  lines.push(`Reference dump: \`${outputPath}\``);
  lines.push("");
  lines.push(`Bug messages scanned: ${counters.messages.toLocaleString()}`);
  lines.push(`References emitted: ${counters.refs.toLocaleString()}`);
  lines.push(`Unique bugs represented: ${counters.bugs.size.toLocaleString()}`);
  lines.push(`Repositories represented: ${counters.repos.size.toLocaleString()}`);
  lines.push("");
  lines.push("## Reference Types");
  renderMap(lines, counters.refType);
  lines.push("");
  lines.push("## Role Hints");
  renderMap(lines, counters.role);
  lines.push("");
  lines.push("## Original vs Comment");
  renderMap(lines, counters.kindRole);
  lines.push("");
  lines.push("## Top Repositories By References");
  renderMap(lines, counters.repoRefs, 15);
  lines.push("");
  lines.push("## First-Pass Pattern");
  lines.push("- Fix references are high volume and often machine-generated Launchpad comments containing `Reviewed:`, `Committed:`, `Submitter:`, Gerrit URLs, or commit URLs. Treat these as strong `fixed_by` / `landed_as` evidence, but not regression evidence.");
  lines.push("- Regression references are phrase-bound and lower volume: `regression`, `regressed`, `introduced by`, `caused by`, `bisect`, `culprit`, `broke`, `broken`, or `since <sha/change>` near a reference.");
  lines.push("- Revert references are distinct: `revert`, `reverted in`, `backed out`, or `rollback` near a review/commit ref. These often indicate a bad fix or a fix that caused fallout.");
  lines.push("- Backport/fix-propagation references use `backport`, `cherry-pick`, `stable/*`, or `proposed to stable`; these should be tracked separately from both root-cause and primary-fix edges.");
  lines.push("- Direct commit URLs/full SHAs are highest confidence. Gerrit review URLs should resolve through change number to current revision; short SHAs need repo/time/context disambiguation.");
  lines.push("");
  lines.push("## Example Contexts");
  for (const [role, list] of examples.entries()) {
    lines.push(`### ${role}`);
    for (const item of list) {
      lines.push(`- ${item.repository_name} bug ${item.bug_id} ${item.ref_type}:${item.ref_value} (${item.bug_message_kind})`);
      lines.push(`  ${item.context}`);
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

function renderMap(lines, map, limit = 20) {
  for (const [key, value] of [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit)) {
    lines.push(`- ${key}: ${value.toLocaleString()}`);
  }
}
