#!/usr/bin/env node

import fs from "node:fs";

const baseUrl = stripSlash(process.env.REPOINTEL_BASE_URL || "http://127.0.0.1:18101");
const token = process.env.REPOINTEL_TOKEN || "writer";
const localRoot = process.env.OPENSTACK_REPO_ROOT || "/home/tim/tb/dev/openstack";
const fallbackLocalRoot = process.env.OPENSTACK_REPO_FALLBACK_ROOT || "/media/tb/linux/home/tim/dev/openstack";
const wantedSlugs = [
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

const args = new Set(process.argv.slice(2));
const dryRun = args.has("--dry-run");

function stripSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function repoName(slug) {
  return `openstack/${slug}`;
}

function repoUrl(slug) {
  return `https://opendev.org/openstack/${slug}`;
}

function launchpadUrl(slug) {
  return `https://api.launchpad.net/1.0/${slug}`;
}

function localPath(slug) {
  const primary = `${localRoot}/${slug}`;
  const fallback = `${fallbackLocalRoot}/${slug}`;
  if (fs.existsSync(`${primary}/.git`)) return primary;
  if (fs.existsSync(`${fallback}/.git`)) return fallback;
  return primary;
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

function sourceTemplates(repositoryId, slug, normalizerId) {
  return [
    {
      repository_id: repositoryId,
      name: "Gerrit reviews",
      type: "code_reviews",
      provider: "gerrit",
      base_url: "https://review.opendev.org",
      external_key: repoName(slug),
      enabled: true,
      normalizer_id: normalizerId,
      ingestion_policy: {
        limit: 1000,
        review_limit: 1000,
        reviews_per_minute: 0,
        comments_per_change: 10000,
        include_automated_messages: false,
      },
      ingestion_filters: {},
    },
    {
      repository_id: repositoryId,
      name: "Commit messages",
      type: "commits",
      provider: "git",
      base_url: repoUrl(slug),
      external_key: repoName(slug),
      enabled: true,
      normalizer_id: normalizerId,
      ingestion_policy: {
        limit: 20000,
        local_path: localPath(slug),
        line_survival_enabled: true,
        line_survival_branch: "origin/master",
        line_survival_window_days: 365,
        line_survival_max_changed_lines: 100,
        approval_line_survival_enabled: true,
        approval_line_survival_branch: "origin/master",
        approval_line_survival_max_review_changed_lines: 200,
      },
      ingestion_filters: {},
    },
    {
      repository_id: repositoryId,
      name: "Launchpad bugs",
      type: "bugs",
      provider: "launchpad",
      base_url: launchpadUrl(slug),
      external_key: slug,
      enabled: true,
      normalizer_id: normalizerId,
      ingestion_policy: {
        limit: 1000,
      },
      ingestion_filters: {},
    },
  ];
}

function sourceKey(source) {
  return `${source.repository_id}\0${source.provider}\0${source.external_key}`;
}

async function main() {
  const [groupsResponse, normalizersResponse, repositoriesResponse, sourcesResponse] = await Promise.all([
    api("GET", "/repository-groups"),
    api("GET", "/normalizers"),
    api("GET", "/repositories"),
    api("GET", "/sources"),
  ]);
  const group = items(groupsResponse).find((item) => item.slug === "openstack-debug") || items(groupsResponse)[0];
  if (!group?.id) throw new Error("No repository group found");
  const normalizer = items(normalizersResponse).find((item) => /openstack/i.test(item.name || "")) || items(normalizersResponse)[0];
  if (!normalizer?.id) throw new Error("No shared normalizer found");

  const repositories = new Map(items(repositoriesResponse).map((repo) => [repo.slug, repo]));
  const sources = new Map(items(sourcesResponse).map((source) => [sourceKey(source), source]));
  const summary = [];

  for (const slug of wantedSlugs) {
    const gitPath = localPath(slug);
    const hasLocalGit = fs.existsSync(`${gitPath}/.git`);
    if (!hasLocalGit) {
      throw new Error(`${slug} local git checkout missing at ${gitPath}`);
    }

    let repository = repositories.get(slug);
    let repositoryAction = "exists";
    if (!repository) {
      const body = {
        repository_group_id: group.id,
        slug,
        name: repoName(slug),
        vcs: "git",
        canonical_url: repoUrl(slug),
        default_branch: "master",
        status: "active",
      };
      repositoryAction = dryRun ? "would_create" : "created";
      repository = dryRun ? { id: `<dry-run:${slug}>`, ...body } : await api("POST", "/repositories", body);
      repositories.set(slug, repository);
    }

    const sourceResults = [];
    for (const template of sourceTemplates(repository.id, slug, normalizer.id)) {
      const existing = sources.get(sourceKey(template));
      if (existing) {
        sourceResults.push({ provider: template.provider, action: "exists", id: existing.id });
        continue;
      }
      const action = dryRun ? "would_create" : "created";
      const created = dryRun ? { id: `<dry-run:${slug}:${template.provider}>`, ...template } : await api("POST", "/sources", template);
      sources.set(sourceKey(created), created);
      sourceResults.push({ provider: template.provider, action, id: created.id });
    }

    summary.push({
      slug,
      repository_id: repository.id,
      repository: repositoryAction,
      local_path: gitPath,
      sources: sourceResults,
    });
  }

  console.log(JSON.stringify({
    dry_run: dryRun,
    base_url: baseUrl,
    repository_group_id: group.id,
    normalizer_id: normalizer.id,
    repositories: summary,
  }, null, 2));
}

main().catch((error) => {
  console.error(error.stack || String(error));
  process.exit(1);
});
