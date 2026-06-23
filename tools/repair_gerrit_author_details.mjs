#!/usr/bin/env node

import { spawnSync } from "node:child_process";

const databaseUrl =
  process.env.REPOINTEL_DATABASE_URL ||
  process.env.DATABASE_URL ||
  "postgres://repointel:repointel@127.0.0.1:15432/repointel";
const apiBase = (process.env.REPOINTEL_API_BASE || "http://127.0.0.1:18101").replace(/\/$/, "");
const authHeader = process.env.REPOINTEL_AUTH || "Bearer admin";
const gerritBase = (process.env.GERRIT_BASE || "https://review.opendev.org").replace(/\/$/, "");
const maxAuthors = Number.parseInt(process.env.MAX_AUTHORS || "500", 10);

function queryJson(sql) {
  const result = spawnSync("psql", ["-X", databaseUrl, "-tA", "-c", sql], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 16,
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || `psql exited with ${result.status}`);
  }
  const text = result.stdout.trim();
  return text ? JSON.parse(text) : [];
}

function stripGerritJson(text) {
  const trimmed = text.trimStart();
  if (trimmed.startsWith(")]}'")) {
    const newline = trimmed.indexOf("\n");
    return newline >= 0 ? trimmed.slice(newline + 1) : "";
  }
  return trimmed;
}

async function fetchGerritAccount(accountId) {
  const response = await fetch(`${gerritBase}/accounts/${encodeURIComponent(accountId)}/detail`, {
    headers: { "user-agent": "repointel-author-repair/0.1" },
  });
  if (!response.ok) {
    throw new Error(`Gerrit account ${accountId} returned ${response.status}`);
  }
  return JSON.parse(stripGerritJson(await response.text()));
}

async function patchAuthor(row, detail) {
  const accountId = String(row.account_id || "");
  const body = {
    external_author_id: `gerrit:${accountId}`,
    username: detail.username || row.username || accountId,
    display_name: detail.name || row.display_name || detail.email || accountId,
    email: detail.email || row.email || "",
    profile_url: `${gerritBase}/q/owner:${accountId}`,
  };
  const response = await fetch(`${apiBase}/authors/${encodeURIComponent(row.author_id)}`, {
    method: "PATCH",
    headers: {
      authorization: authHeader,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`PATCH ${row.author_id} returned ${response.status}: ${text.slice(0, 500)}`);
  }
  return response.json();
}

async function main() {
  const rows = queryJson(`
    select coalesce(jsonb_agg(row_to_json(t)), '[]'::jsonb)
    from (
      select
        doc->>'id' as author_id,
        regexp_replace(doc->>'external_author_id', '^gerrit:', '') as account_id,
        doc->>'username' as username,
        doc->>'display_name' as display_name,
        doc->>'email' as email,
        doc->>'profile_url' as profile_url,
        doc->>'updated_at' as updated_at
      from repointel_records
      where collection = 'authors'
        and doc->>'external_author_id' ~ '^gerrit:[0-9]+$'
      order by doc->>'updated_at' desc, doc->>'id'
      limit ${Number.isFinite(maxAuthors) && maxAuthors > 0 ? maxAuthors : 500}
    ) t;
  `);

  let patched = 0;
  let skipped = 0;
  let failed = 0;
  const seenAccounts = new Map();

  for (const row of rows) {
    const accountId = String(row.account_id || "").trim();
    if (!accountId) {
      skipped += 1;
      continue;
    }
    try {
      let detail = seenAccounts.get(accountId);
      if (!detail) {
        detail = await fetchGerritAccount(accountId);
        seenAccounts.set(accountId, detail);
      }
      await patchAuthor(row, detail);
      patched += 1;
      console.log(
        JSON.stringify({
          patched,
          account_id: accountId,
          author_id: row.author_id,
          name: detail.name || "",
          email: detail.email || "",
          username: detail.username || "",
        })
      );
    } catch (error) {
      failed += 1;
      console.error(
        JSON.stringify({
          failed,
          account_id: accountId,
          author_id: row.author_id,
          error: error.message,
        })
      );
    }
  }

  console.log(JSON.stringify({ done: true, candidates: rows.length, patched, skipped, failed }));
  if (failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
