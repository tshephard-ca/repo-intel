#!/usr/bin/env node

const baseUrl = stripSlash(process.env.REPOINTEL_BASE_URL || "http://127.0.0.1:18101");
const token = process.env.REPOINTEL_TOKEN || "writer";
const defaultSlugs = [
  "cinder",
  "glance",
  "ironic",
  "oslo.config",
  "oslo.log",
  "oslo.messaging",
  "oslo.policy",
  "placement",
  "heat",
  "horizon",
];

const options = parseArgs(process.argv.slice(2));
const slugs = options.slugs.length ? options.slugs : defaultSlugs;
const concurrency = Math.max(1, Number(options.concurrency || 3));
const pollMs = Math.max(5000, Number(options.pollMs || 30000));
const reportMs = Math.max(pollMs, Number(options.reportMs || 30 * 60 * 1000));
const firstReportMs = Math.max(0, Number(options.firstReportMs ?? reportMs));
const requestedBy = options.requestedBy || "codex-openstack-batch-sync";

function stripSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function parseArgs(args) {
  const out = {
    slugs: [],
    concurrency: 3,
    pollMs: 30000,
    reportMs: 30 * 60 * 1000,
    firstReportMs: undefined,
    requestedBy: "",
  };
  for (let idx = 0; idx < args.length; idx += 1) {
    const arg = args[idx];
    const next = () => args[++idx] || "";
    if (arg === "--repos" || arg === "--slugs") out.slugs = next().split(",").map((item) => item.trim()).filter(Boolean);
    else if (arg === "--concurrency") out.concurrency = Number(next());
    else if (arg === "--poll-ms") out.pollMs = Number(next());
    else if (arg === "--report-ms") out.reportMs = Number(next());
    else if (arg === "--first-report-ms") out.firstReportMs = Number(next());
    else if (arg === "--requested-by") out.requestedBy = next();
    else if (arg === "--help") {
      console.log("Usage: node tools/sync_openstack_repositories.mjs [--repos a,b] [--concurrency 3] [--report-ms 1800000]");
      process.exit(0);
    }
  }
  return out;
}

async function api(method, path, body) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "cache-control": "no-store",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`${method} ${path} failed ${response.status}: ${text}`);
  }
  return value;
}

function items(value) {
  return Array.isArray(value?.items) ? value.items : Array.isArray(value) ? value : [];
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function terminalStatus(status) {
  return ["completed", "failed", "cancelled", "canceled", "paused"].includes(String(status || "").toLowerCase());
}

function unixSeconds(value) {
  const match = String(value || "").match(/^unix:(\d+)$/);
  return match ? Number(match[1]) : 0;
}

function countNumber(value) {
  const n = Number(value || 0);
  return Number.isFinite(n) ? n : 0;
}

function summarizeJob(job) {
  return {
    id: job.id,
    status: job.status || "",
    raw: countNumber(job.raw_records_count),
    arts: countNumber(job.arts_count),
    authors: countNumber(job.authors_count),
    metadata: countNumber(job.metadata_count),
    relationships: countNumber(job.relationships_count),
    active_source_id: job.active_source_id || "",
    started_at: job.started_at || "",
    finished_at: job.finished_at || "",
    elapsed_sec: Math.max(0, (unixSeconds(job.finished_at) || Math.floor(Date.now() / 1000)) - unixSeconds(job.started_at)),
    error: job.error || "",
  };
}

function aggregate(results) {
  return results.reduce((acc, result) => {
    const job = result.job || {};
    acc.raw += countNumber(job.raw_records_count);
    acc.arts += countNumber(job.arts_count);
    acc.authors += countNumber(job.authors_count);
    acc.metadata += countNumber(job.metadata_count);
    acc.relationships += countNumber(job.relationships_count);
    return acc;
  }, { raw: 0, arts: 0, authors: 0, metadata: 0, relationships: 0 });
}

function progressLine(results, queue, active, final = false) {
  const done = results.filter((result) => terminalStatus(result.job?.status)).length;
  const failed = results.filter((result) => ["failed", "cancelled", "canceled"].includes(String(result.job?.status || "").toLowerCase())).length;
  const totals = aggregate(results);
  const activeText = active.map((item) => `${item.slug}:${item.job?.status || "queued"}`).join(",");
  return JSON.stringify({
    event: final ? "sync_final" : "sync_progress",
    done,
    total: slugs.length,
    active: activeText,
    queued: queue.length,
    failed,
    totals,
  });
}

async function enqueueRepository(repository) {
  return api("POST", `/repositories/${encodeURIComponent(repository.id)}/enqueue-ingestion`, {
    requested_by: requestedBy,
    mode: "repository-sync",
    priority: 10,
    params: {
      sync_current: true,
      git_fetch: true,
      run_sensitivity_scoring: true,
    },
  });
}

async function main() {
  const repositories = items(await api("GET", "/repositories"));
  const bySlug = new Map(repositories.map((repo) => [repo.slug, repo]));
  const queue = slugs.map((slug) => {
    const repository = bySlug.get(slug);
    if (!repository) throw new Error(`repository slug not found: ${slug}`);
    return { slug, repository, job: null };
  });
  const active = [];
  const results = [];
  const firstReportAt = Date.now() + firstReportMs;
  let nextReportAt = firstReportAt;

  async function fillSlots() {
    while (active.length < concurrency && queue.length) {
      const item = queue.shift();
      item.job = await enqueueRepository(item.repository);
      active.push(item);
      results.push(item);
    }
  }

  await fillSlots();

  while (active.length || queue.length) {
    await sleep(pollMs);
    for (const item of [...active]) {
      item.job = await api("GET", `/ingestion-jobs/${encodeURIComponent(item.job.id)}`);
      if (terminalStatus(item.job.status)) {
        active.splice(active.indexOf(item), 1);
      }
    }
    await fillSlots();
    if (Date.now() >= nextReportAt) {
      console.log(progressLine(results, queue, active));
      nextReportAt = Date.now() + reportMs;
    }
  }

  const finished = [];
  for (const item of results) {
    const job = await api("GET", `/ingestion-jobs/${encodeURIComponent(item.job.id)}`);
    finished.push({ slug: item.slug, repository_id: item.repository.id, job: summarizeJob(job) });
  }
  if (Date.now() < firstReportAt) {
    await sleep(firstReportAt - Date.now());
  }
  console.log(progressLine(results, queue, active, true));
  console.log(JSON.stringify({ repositories: finished }, null, 2));
}

main().catch((error) => {
  console.error(error.stack || String(error));
  process.exit(1);
});
