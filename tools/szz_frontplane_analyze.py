#!/usr/bin/env python3
"""Frontplane-oriented SZZ analysis wrapper.

Reads a SzzAnalysisRequest JSON object from stdin and writes a normalized
SzzAnalysis JSON object to stdout. The heavy SZZ work is delegated to the
standalone szz_review_analyze.py module; this wrapper handles review selection,
candidate review enrichment, and evidence-hit shaping for the facade.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GIT_ROOT = Path(
    os.environ.get("REPOINTEL_GIT_ROOT")
    or (ROOT / ".repointel-git")
)
DATABASE_URL = (
    os.environ.get("REPOINTEL_DATABASE_URL")
    or os.environ.get("DATABASE_URL")
    or "postgres://repointel:repointel@127.0.0.1:15432/repointel"
)
GERRIT_URL = os.environ.get("REPOINTEL_GERRIT_URL", "").strip().rstrip("/")
SZZ_VERSION = "szz_review_analyze_v1"
_REPOSITORY_PATH_CACHE: dict[str, Path] = {}
SZZ_PROVIDER_AUTH_ENV = (
    "REPOINTEL_SZZ_PROVIDER_TOKEN",
    "METADATACOLLECTIONFACADE_REPOINTEL_SZZ_PROVIDER_TOKEN",
    "FRONTPLANE_AUTH_REPOINTEL_SZZ_PROVIDER_TOKEN",
)


def load_szz_module():
    module_path = ROOT / "tools" / "szz_review_analyze.py"
    spec = importlib.util.spec_from_file_location("szz_review_analyze", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["szz_review_analyze"] = module
    spec.loader.exec_module(module)
    return module


szz = load_szz_module()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_hash(value: object) -> str:
    return hashlib.md5(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def psql_json(sql: str):
    output = subprocess.run(
        ["psql", "-X", DATABASE_URL, "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if output.returncode:
        raise RuntimeError(output.stderr.strip() or "psql failed")
    text = output.stdout.strip()
    return json.loads(text) if text else None


def strip_xssi(payload: str) -> str:
    return payload.split("\n", 1)[1] if payload.startswith(")]}'") else payload


def get_json(url: str, timeout: int = 45):
    request = urllib.request.Request(url, headers={"User-Agent": "repointel-szz-frontplane/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(strip_xssi(response.read().decode("utf-8", "replace")))


def requested_limit(request: dict) -> int | None:
    selector = request.get("selector") or {}
    params = request.get("params") or {}
    if selector.get("all") is True or params.get("all") is True:
        return None
    for value in (selector.get("limit"), request.get("limit")):
        if isinstance(value, int):
            return value if value > 0 else None
        if isinstance(value, str) and value.lower() == "all":
            return None
    return None


def repository_slug(project_or_name: str) -> str:
    if not project_or_name:
        return ""
    return project_or_name.rstrip("/").split("/")[-1]


def repository_path(project: str) -> Path:
    slug = repository_slug(project)
    if slug in _REPOSITORY_PATH_CACHE:
        return _REPOSITORY_PATH_CACHE[slug]
    configured = configured_repository_path(project, slug)
    path = configured or (DEFAULT_GIT_ROOT / slug)
    _REPOSITORY_PATH_CACHE[slug] = path
    return path


def gerrit_base_url() -> str:
    if not GERRIT_URL:
        raise RuntimeError("REPOINTEL_GERRIT_URL is required for Gerrit candidate-review backfill")
    return GERRIT_URL


def configured_repository_path(project: str, slug: str) -> Path | None:
    try:
        rows = psql_json(f"""
with git_sources as (
  select
    coalesce(s.doc->'ingestion_policy'->>'local_path','') as local_path,
    coalesce(s.doc->>'external_key','') as external_key,
    coalesce(r.doc->>'slug','') as repository_slug,
    coalesce(r.doc->>'name','') as repository_name
  from repointel_records s
  left join repointel_records r
    on r.collection='repositories'
   and r.id=s.doc->>'repository_id'
  where s.collection='sources'
    and s.doc->>'provider'='git'
)
select coalesce(jsonb_agg(to_jsonb(git_sources)), '[]'::jsonb)::text
from git_sources
where local_path <> ''
  and (
    external_key = {sql_literal(project)}
    or repository_name = {sql_literal(project)}
    or repository_slug = {sql_literal(slug)}
  );
""")
    except Exception:
        return None
    for row in rows or []:
        path = Path(row.get("local_path") or "")
        if (path / ".git").exists():
            return path
    return None


def select_reviews(request: dict, mode: str) -> list[dict]:
    selector = request.get("selector") or {}
    params = request.get("params") or {}
    review_ids = selector.get("review_ids") or []
    if request.get("review_id"):
        review_ids = [str(request["review_id"])]
    if mode == "review" and request.get("commit_sha"):
        project = request.get("repository_name") or selector.get("repository_name") or ""
        return [{
            "raw_record_id": "",
            "repository_id": request.get("repository_id") or selector.get("repository_id") or "",
            "source_id": "",
            "ingestion_job_id": "",
            "change_number": str(request.get("review_id") or ""),
            "change_id": "",
            "project": project,
            "branch": "",
            "status": "MERGED",
            "subject": "",
            "current_revision": request["commit_sha"],
            "created": "",
            "updated": "",
            "submitted": "",
            "url": "",
            "insertions": 0,
            "deletions": 0,
        }]

    where = [
        "collection='raw-records'",
        "doc->>'record_type'='gerrit_change'",
        "upper(coalesce(doc->'payload'->>'status',''))='MERGED'",
        "coalesce(doc->'payload'->>'current_revision','') <> ''",
        "(doc->'payload'->>'current_revision_commit_message') ~* '(^|\\n)\\s*(Closes-Bug|Close-Bug|Fixes-Bug)\\s*:'",
    ]
    repository_id = request.get("repository_id") or selector.get("repository_id")
    repository_name = request.get("repository_name") or selector.get("repository_name")
    explicit_scope = bool(repository_id or repository_name or review_ids)
    allow_all = params.get("all") is True or ((selector.get("filters") or {}).get("all") is True)
    if not explicit_scope and not allow_all:
        raise ValueError(
            "SZZ analysis requires repository_id, repository_name, review_ids, review_id, "
            "commit_sha, or params.all=true"
        )
    if repository_id:
        where.append(f"doc->>'repository_id' = {sql_literal(repository_id)}")
    if repository_name:
        where.append(f"coalesce(doc->'payload'->>'project','') = {sql_literal(repository_name)}")
    if review_ids:
        values = ",".join(sql_literal(str(item)) for item in review_ids)
        where.append(f"coalesce(doc->'payload'->>'_number','') in ({values})")
    limit = requested_limit(request)
    limit_clause = "" if review_ids or limit is None else f"limit {limit}"
    return psql_json(f"""
with selected as (
  select
    id as raw_record_id,
    doc->>'repository_id' as repository_id,
    coalesce(doc->>'source_id','') as source_id,
    coalesce(doc->>'ingestion_job_id','') as ingestion_job_id,
    coalesce(doc->'payload'->>'_number','') as change_number,
    coalesce(doc->'payload'->>'change_id','') as change_id,
    coalesce(doc->'payload'->>'project','') as project,
    coalesce(doc->'payload'->>'branch','') as branch,
    coalesce(doc->'payload'->>'status','') as status,
    coalesce(doc->'payload'->>'subject','') as subject,
    coalesce(doc->'payload'->>'current_revision','') as current_revision,
    coalesce(doc->'payload'->>'created','') as created,
    coalesce(doc->'payload'->>'updated','') as updated,
    coalesce(doc->'payload'->>'submitted','') as submitted,
    coalesce(doc->>'url','') as url,
    coalesce(nullif(doc->'payload'->>'insertions',''),'0')::int as insertions,
    coalesce(nullif(doc->'payload'->>'deletions',''),'0')::int as deletions
  from repointel_records
  where {' and '.join(where)}
  order by coalesce(nullif(doc->'payload'->>'updated',''), nullif(doc->'payload'->>'submitted',''), nullif(doc->'payload'->>'created',''), '') desc,
           coalesce(nullif(doc->'payload'->>'_number',''),'0')::bigint desc
  {limit_clause}
)
select coalesce(jsonb_agg(to_jsonb(selected)), '[]'::jsonb)::text from selected;
""")


def analyze_reviews(reviews: list[dict], request: dict) -> tuple[list[dict], list[dict], list[dict], dict[str, str]]:
    min_direct = int(request.get("min_direct_lines") or 4)
    min_context = int(request.get("min_context_lines") or 4)
    include_context = request.get("include_context_candidates", True) is not False
    rows: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    change_ids: dict[str, str] = {}
    total = len(reviews)
    started = time.monotonic()
    last_report = started
    for index, review in enumerate(reviews, start=1):
        repo = repository_path(review.get("project", ""))
        if not (repo / ".git").exists():
            skipped.append({"review": review.get("change_number", ""), "project": review.get("project", ""), "reason": "missing_git_repo", "repo_path": str(repo)})
            continue
        try:
            commit = review.get("current_revision", "")
            if not szz.git_exists(repo, commit):
                skipped.append({"review": review.get("change_number", ""), "project": review.get("project", ""), "reason": "missing_fix_commit", "commit": commit})
                continue
            result = szz.analyze_szz(
                repo=repo,
                commit=commit,
                review_info={
                    "review": review.get("change_number", ""),
                    "project": review.get("project", ""),
                    "status": review.get("status", ""),
                    "subject": review.get("subject", ""),
                    "url": review.get("url", ""),
                },
                include_related_bug=False,
                include_tests=False,
                ignore_revs_file=None,
                max_evidence_lines=int(request.get("max_evidence_lines") or 3),
            )
            candidates = [("direct", item) for item in result["candidate_introducing_commits"] if item.get("direct_lines", 0) >= min_direct]
            if include_context:
                candidates.extend(("context", item) for item in result["added_line_context_candidates"] if item.get("context_lines", 0) >= min_context)
            for candidate_type, candidate in candidates:
                try:
                    change_id = szz.parse_change_id(szz.commit_message(repo, candidate["commit"]))
                except Exception:
                    change_id = ""
                change_ids[candidate["commit"]] = change_id
                rows.append({
                    "review": str(review.get("change_number", "")),
                    "project": review.get("project", ""),
                    "repo": repository_slug(review.get("project", "")),
                    "repository_id": review.get("repository_id", ""),
                    "source_id": review.get("source_id", ""),
                    "ingestion_job_id": review.get("ingestion_job_id", ""),
                    "raw_record_id": review.get("raw_record_id", ""),
                    "subject": review.get("subject", ""),
                    "review_url": review.get("url", ""),
                    "fix_sha": commit,
                    "submitted": review.get("submitted", ""),
                    "updated": review.get("updated", ""),
                    "type": candidate_type,
                    "lines": candidate.get("direct_lines") if candidate_type == "direct" else candidate.get("context_lines"),
                    "score": candidate.get("score", 0),
                    "confidence": candidate.get("confidence", ""),
                    "candidate_sha": candidate["commit"],
                    "candidate_change_id": change_id,
                    "candidate_author": candidate.get("author_name") or candidate.get("author_email", ""),
                    "candidate_email": candidate.get("author_email", ""),
                    "candidate_summary": candidate.get("summary", ""),
                    "files": [item["path"] for item in candidate.get("files", [])[:5]],
                    "evidence": candidate.get("evidence", []),
                })
        except BaseException as exc:
            errors.append({"review": review.get("change_number", ""), "project": review.get("project", ""), "error": str(exc)})
        progress_now = time.monotonic()
        if progress_now - last_report >= 30 or index == total:
            print(json.dumps({
                "event": "szz_progress",
                "processed_reviews": index,
                "selected_reviews": total,
                "candidate_rows": len(rows),
                "skipped_reviews": len(skipped),
                "errors": len(errors),
                "elapsed_s": round(progress_now - started, 1),
            }, sort_keys=True), file=sys.stderr, flush=True)
            last_report = progress_now
    return rows, skipped, errors, change_ids


def load_candidate_review_map(rows: list[dict], change_ids: dict[str, str]) -> dict[str, list[dict]]:
    commits = sorted({row["candidate_sha"] for row in rows})
    if not commits:
        return {}
    shas = ",".join(sql_literal(item) for item in commits)
    cids = ",".join(sql_literal(item) for item in sorted({value for value in change_ids.values() if value})) or "''"
    found = psql_json(f"""
with found as (
  select
    id as raw_record_id,
    doc->>'repository_id' as repository_id,
    coalesce(doc->>'url','') as url,
    coalesce(doc->'payload'->>'_number','') as change_number,
    coalesce(doc->'payload'->>'change_id','') as change_id,
    coalesce(doc->'payload'->>'project','') as project,
    coalesce(doc->'payload'->>'status','') as status,
    coalesce(doc->'payload'->>'subject','') as subject,
    coalesce(doc->'payload'->>'current_revision','') as current_revision,
    coalesce(doc->'payload'->'labels'->'Code-Review'->'all','[]'::jsonb) as label_all,
    coalesce(doc->'payload'->'messages','[]'::jsonb) as messages
  from repointel_records
  where collection='raw-records'
    and doc->>'record_type'='gerrit_change'
    and (
      coalesce(doc->'payload'->>'current_revision','') in ({shas})
      or coalesce(doc->'payload'->>'change_id','') in ({cids})
    )
)
select coalesce(jsonb_agg(to_jsonb(found)), '[]'::jsonb)::text from found;
""")
    review_map: dict[str, list[dict]] = defaultdict(list)
    for item in found:
        for key in (item.get("current_revision", ""), item.get("change_id", "")):
            if key:
                review_map[key].append(item)
    return review_map


def approvers(raw: dict) -> list[dict]:
    people = []
    for actor in raw.get("label_all") or []:
        try:
            value = int(actor.get("value") or 0)
        except Exception:
            value = 0
        if value >= 2:
            people.append(actor_doc(actor, value=value))
    if not people:
        pattern = re.compile(r"Code-Review\+([12])\b")
        for message in raw.get("messages") or []:
            hit = pattern.search(message.get("message") or "")
            if hit and int(hit.group(1)) >= 2:
                people.append(actor_doc(message.get("author") or {}, value=int(hit.group(1))))
    out = []
    seen = set()
    for person in people:
        key = (person.get("account_id"), person.get("name"), person.get("email"))
        if key not in seen:
            seen.add(key)
            out.append(person)
    return out


def actor_doc(actor: dict, value: int | None = None) -> dict:
    result = {
        "name": actor.get("name") or "",
        "email": actor.get("email") or "",
        "username": actor.get("username") or "",
        "account_id": str(actor.get("_account_id") or actor.get("account_id") or ""),
        "author_id": "",
        "identity_key": "",
        "metadata": {},
    }
    if value is not None:
        result["metadata"]["approval_value"] = value
    if result["account_id"]:
        result["identity_key"] = f"gerrit:{result['account_id']}"
    elif result["email"]:
        result["identity_key"] = f"email:{result['email'].lower()}"
    elif result["name"]:
        result["identity_key"] = f"name:{result['name'].lower()}"
    return result


def candidate_review_doc(row: dict) -> dict:
    existing = row.get("candidate_review") or {}
    if isinstance(existing, dict):
        return {
            "change_number": str(existing.get("change_number") or ""),
            "status": existing.get("status") or "",
            "subject": existing.get("subject") or "",
            "url": existing.get("url") or "",
            "change_id": existing.get("change_id") or row.get("candidate_change_id", ""),
            "current_revision": existing.get("current_revision") or row.get("candidate_sha", ""),
            "found_in_db": existing.get("found_in_db", bool(existing.get("change_number"))),
            "backfilled": existing.get("backfilled", False),
        }
    return {
        "change_number": str(existing),
        "status": row.get("candidate_review_status", ""),
        "subject": row.get("candidate_review_subject", ""),
        "url": row.get("candidate_review_url", ""),
        "change_id": row.get("candidate_change_id", ""),
        "current_revision": row.get("candidate_sha", ""),
        "found_in_db": bool(existing),
        "backfilled": False,
    }


def approver_docs(row: dict) -> list[dict]:
    normalized = []
    for item in row.get("approvers") or []:
        if isinstance(item, dict):
            normalized.append(actor_doc(item, value=item.get("value")))
    return normalized


def fetch_change(query: str, project: str, sha: str) -> dict | None:
    base_url = gerrit_base_url()
    options = ["CURRENT_REVISION", "CURRENT_COMMIT", "DETAILED_LABELS", "DETAILED_ACCOUNTS", "MESSAGES", "SUBMITTABLE"]
    query_string = urllib.parse.urlencode({"q": query, "n": "10"}) + "".join("&o=" + urllib.parse.quote(option) for option in options)
    items = get_json(f"{base_url}/changes/?{query_string}")
    if not items:
        return None
    return sorted(
        items,
        key=lambda item: (
            0 if item.get("project") == project else 1,
            0 if item.get("current_revision") == sha else 1,
            0 if item.get("status") == "MERGED" else 1,
            -int(item.get("_number") or 0),
        ),
    )[0]


def enrich_payload(payload: dict) -> dict:
    payload = dict(payload)
    revision = payload.get("current_revision") or ""
    commit = ((payload.get("revisions") or {}).get(revision) or {}).get("commit") or {}
    payload["current_revision_commit_message"] = commit.get("message") or payload.get("current_revision_commit_message", "")
    payload["current_revision_subject"] = commit.get("subject") or payload.get("subject", "")
    if commit.get("author"):
        payload["current_revision_author"] = commit["author"]
    if commit.get("committer"):
        payload["current_revision_committer"] = commit["committer"]
    if commit.get("parents"):
        payload["current_revision_parents"] = [item.get("commit") for item in commit["parents"] if item.get("commit")]
    return payload


def enrich_candidate_review(detail: dict, seed: dict) -> dict:
    base_url = gerrit_base_url()
    payload = enrich_payload(detail)
    number = str(payload.get("_number") or "")
    project = payload.get("project") or seed.get("project", "")
    url = f"{base_url}/c/{project}/+/{number}" if project and number else ""
    seed["candidate_review"] = {
        "change_number": number,
        "status": payload.get("status", ""),
        "subject": payload.get("subject", ""),
        "url": url,
        "change_id": payload.get("change_id", ""),
        "current_revision": payload.get("current_revision", ""),
        "found_in_db": False,
        "backfilled": True,
    }
    seed["approvers"] = approvers({
        "label_all": ((payload.get("labels") or {}).get("Code-Review") or {}).get("all") or [],
        "messages": payload.get("messages") or [],
    })
    return {
        "review": number,
        "commit": seed.get("candidate_sha", ""),
        "project": project,
        "url": url,
        "persisted": False,
        "source": "gerrit_api",
    }


def attach_candidate_reviews(rows: list[dict], review_map: dict[str, list[dict]]) -> tuple[int, int, list[dict]]:
    found = 0
    with_approver = 0
    missing = []
    for row in rows:
        candidates = review_map.get(row["candidate_sha"]) or review_map.get(row.get("candidate_change_id", "")) or []
        if not candidates:
            row["candidate_review"] = {"found_in_db": False, "backfilled": False}
            row["approvers"] = []
            missing.append(row)
            continue
        raw = sorted(candidates, key=lambda item: 0 if item.get("current_revision") == row["candidate_sha"] else 1)[0]
        row["candidate_review"] = {
            "change_number": raw.get("change_number", ""),
            "status": raw.get("status", ""),
            "subject": raw.get("subject", ""),
            "url": raw.get("url", ""),
            "change_id": raw.get("change_id", ""),
            "current_revision": raw.get("current_revision", ""),
            "found_in_db": True,
            "backfilled": raw.get("raw_record_id", "").startswith("raw-record-"),
        }
        row["approvers"] = approvers(raw)
        found += 1
        if row["approvers"]:
            with_approver += 1
    return found, with_approver, missing


def backfill_missing_reviews(missing: list[dict]) -> tuple[list[dict], list[str]]:
    added = []
    errors = []
    for row in {item["candidate_sha"]: item for item in missing}.values():
        try:
            detail = fetch_change("commit:" + row["candidate_sha"], row["project"], row["candidate_sha"])
            if detail is None and row.get("candidate_change_id"):
                detail = fetch_change("change:" + row["candidate_change_id"], row["project"], row["candidate_sha"])
            if detail is None:
                errors.append(f"candidate review not found for {row['candidate_sha']}")
                continue
            added.append(enrich_candidate_review(detail, row))
        except Exception as exc:
            errors.append(f"{row['candidate_sha']}: {exc}")
    return added, errors


def candidate_from_row(row: dict) -> dict:
    return {
        "type": row["type"],
        "lines": int(row.get("lines") or 0),
        "score": float(row.get("score") or 0),
        "confidence": row.get("confidence", ""),
        "candidate_commit": row["candidate_sha"],
        "candidate_change_id": row.get("candidate_change_id", ""),
        "author": actor_doc({"name": row.get("candidate_author", ""), "email": row.get("candidate_email", "")}),
        "candidate_review": candidate_review_doc(row),
        "approvers": approver_docs(row),
        "files": row.get("files") or [],
        "reason": row.get("candidate_summary", ""),
        "evidence": row.get("evidence") or [],
        "metadata": {
            "fix_review": row.get("review", ""),
            "fix_commit": row.get("fix_sha", ""),
            "project": row.get("project", ""),
            "repository_id": row.get("repository_id", ""),
            "source_id": row.get("source_id", ""),
            "raw_record_id": row.get("raw_record_id", ""),
        },
    }


def evidence_hit(row: dict, analysis_id: str) -> dict:
    hit_hash = stable_hash(["szz", analysis_id, row.get("review", ""), row["candidate_sha"], row["type"], row.get("lines")])
    key = "direct_candidate" if row["type"] == "direct" else "context_candidate"
    value = {
        "review": row.get("review", ""),
        "fix_commit": row.get("fix_sha", ""),
        "candidate_commit": row["candidate_sha"],
        "candidate_change_id": row.get("candidate_change_id", ""),
        "candidate_author": row.get("candidate_author", ""),
        "candidate_email": row.get("candidate_email", ""),
        "candidate_review": candidate_review_doc(row),
        "approvers": approver_docs(row),
        "type": row["type"],
        "lines": row.get("lines", 0),
        "score": row.get("score", 0),
        "files": row.get("files") or [],
        "reason": row.get("candidate_summary", ""),
    }
    return {
        "id": "evidence-hit-" + hit_hash,
        "collection_run_id": analysis_id,
        "profile_id": "profile_vuln_intel_priority_v1",
        "scenario_id": "scenario_szz_competence_outcomes",
        "bundle_id": "bundle_vuln_intel_core_extractors",
        "rule_id": "rule_szz_candidate_outcome",
        "rule_version": SZZ_VERSION,
        "repository_id": row.get("repository_id", ""),
        "source_id": row.get("source_id", ""),
        "ingestion_job_id": row.get("ingestion_job_id", ""),
        "raw_record_id": row.get("raw_record_id", ""),
        "art_id": "",
        "author_id": "",
        "source_kind": "szz_analysis",
        "source_field_path": f"szz.{key}",
        "matched_text_preview": f"{row['type']} {row.get('lines', 0)} lines {row['candidate_sha'][:12]} {row.get('candidate_author', '')}",
        "namespace": "szz",
        "key": key,
        "value": value,
        "value_type": "object",
        "canonical_value": value,
        "value_hash": stable_hash(value),
        "confidence": round(max(0.0, min(1.0, float(row.get("score") or 0) / 100.0)), 4),
        "disposition": "accepted",
        "origin": "szz_review_analyze.v1",
        "hit_hash": hit_hash,
        "proposed_metadata": [
            {
                "local_ref": "szz_candidate",
                "repository_id": row.get("repository_id", ""),
                "source_id": row.get("source_id", ""),
                "ingestion_job_id": row.get("ingestion_job_id", ""),
                "raw_record_id": row.get("raw_record_id", ""),
                "subject_type": "review",
                "subject_id": row.get("review", ""),
                "namespace": "szz",
                "key": key,
                "value": value,
                "value_type": "object",
                "role": "competence_outcome_evidence",
            }
        ],
        "proposed_relationships": [],
        "created_at": now(),
        "updated_at": now(),
    }


def build_analysis(request: dict, mode: str) -> dict:
    if request.get("params", {}).get("analysis_artifact_path"):
        artifact = json.loads(Path(request["params"]["analysis_artifact_path"]).read_text())
        rows = artifact.get("rows", [])
        selected = artifact.get("summary", {}).get("selected_reviews", len({row.get("review") for row in rows}))
        skipped = artifact.get("skipped", [])
        errors = artifact.get("errors_detail", [])
        backfilled = artifact.get("backfilled", [])
    else:
        reviews = select_reviews(request, mode)
        rows, skipped, errors, change_ids = analyze_reviews(reviews, request)
        found_before, approver_before, missing = attach_candidate_reviews(rows, load_candidate_review_map(rows, change_ids))
        backfilled = []
        backfill_errors = []
        if request.get("backfill_missing_reviews", True) is not False and missing:
            backfilled, backfill_errors = backfill_missing_reviews(missing)
            errors.extend({"error": error, "stage": "backfill"} for error in backfill_errors)
        selected = len(reviews)

    analysis_id = request.get("szz_analysis_id") or "szz-analysis-" + stable_hash({
        "mode": mode,
        "selector": request.get("selector") or {},
        "review_id": request.get("review_id") or "",
        "commit_sha": request.get("commit_sha") or "",
        "min_direct": request.get("min_direct_lines") or 4,
        "min_context": request.get("min_context_lines") or 4,
        "version": SZZ_VERSION,
    })
    evidence_hits = [evidence_hit(row, analysis_id) for row in rows]
    candidates = [candidate_from_row(row) for row in rows]
    direct_rows = sum(1 for row in rows if row.get("type") == "direct")
    context_rows = sum(1 for row in rows if row.get("type") == "context")
    rows_with_review = sum(1 for row in rows if candidate_review_doc(row).get("change_number"))
    rows_with_approver = sum(1 for row in rows if approver_docs(row))
    details = {
        "repo_candidate_rows": dict(sorted(Counter(row.get("repo", "") for row in rows).items())),
        "repo_review_counts": dict(sorted(Counter(row.get("repo", "") for row in rows).items())),
        "bug_link_policy": "closes_or_fixes_only",
    }
    return {
        "id": analysis_id,
        "selector": request.get("selector") or {},
        "status": "completed",
        "mode": mode,
        "szz_version": SZZ_VERSION,
        "bug_link_policy": "closes_or_fixes_only",
        "min_direct_lines": int(request.get("min_direct_lines") or 4),
        "min_context_lines": int(request.get("min_context_lines") or 4),
        "include_context_candidates": request.get("include_context_candidates", True) is not False,
        "backfill_missing_reviews": request.get("backfill_missing_reviews", True) is not False,
        "commit_evidence": request.get("commit_evidence", True) is not False,
        "cache_key": stable_hash([mode, request, SZZ_VERSION]),
        "review_id": str(request.get("review_id") or ""),
        "repository_id": request.get("repository_id") or "",
        "repository_name": request.get("repository_name") or "",
        "commit_sha": request.get("commit_sha") or "",
        "candidates": candidates,
        "evidence_hits": evidence_hits,
        "summary": {
            "selected_reviews": selected,
            "analyzed_reviews": selected - len(skipped) - len(errors),
            "skipped_reviews": len(skipped),
            "candidate_rows_kept": len(rows),
            "direct_rows": direct_rows,
            "context_rows": context_rows,
            "unique_candidate_commits": len({row["candidate_sha"] for row in rows}),
            "rows_with_review": rows_with_review,
            "rows_with_approver": rows_with_approver,
            "unique_reviews_backfilled": len(backfilled),
            "evidence_hits_count": len(evidence_hits),
            "errors": len(errors),
            "details": details,
        },
        "errors": [json.dumps(error, sort_keys=True) if isinstance(error, dict) else str(error) for error in errors],
        "artifacts": {
            "backfilled": backfilled,
            "skipped": skipped,
            "source": "szz_frontplane_analyze.py",
        },
        "generated_at": now(),
        "created_at": now(),
        "updated_at": now(),
    }


def provider_token() -> str:
    for name in SZZ_PROVIDER_AUTH_ENV:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def bearer_token(header: str) -> str:
    header = (header or "").strip()
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def failed_analysis(request: dict, mode: str, exc: Exception) -> dict:
    return {
        "id": request.get("szz_analysis_id") or "szz-analysis-" + stable_hash([mode, request, time.time()]),
        "status": "failed",
        "mode": mode,
        "szz_version": SZZ_VERSION,
        "errors": [str(exc)],
        "summary": {
            "selected_reviews": 0,
            "analyzed_reviews": 0,
            "skipped_reviews": 0,
            "candidate_rows_kept": 0,
            "direct_rows": 0,
            "context_rows": 0,
            "unique_candidate_commits": 0,
            "rows_with_review": 0,
            "rows_with_approver": 0,
            "unique_reviews_backfilled": 0,
            "evidence_hits_count": 0,
            "errors": 1,
            "details": {},
        },
        "generated_at": now(),
        "created_at": now(),
        "updated_at": now(),
    }


def run_analysis_request(request: dict, mode: str) -> tuple[dict, int]:
    try:
        return build_analysis(request, mode), 200
    except Exception as exc:
        return failed_analysis(request, mode, exc), 200


class SzzProviderHandler(BaseHTTPRequestHandler):
    server_version = "RepointelSzzProvider/1.0"

    def do_POST(self) -> None:
        routes = {
            "/szz/analyze-review": "review",
            "/szz/analyze-batch": "batch",
        }
        mode = routes.get(urllib.parse.urlparse(self.path).path)
        if not mode:
            self.write_json(404, {"error": "NotFound", "message": f"No SZZ provider route for {self.path}"})
            return
        expected = getattr(self.server, "provider_token", "")
        presented = bearer_token(self.headers.get("authorization", ""))
        if not expected or not hmac.compare_digest(presented, expected):
            self.write_json(401, {"error": "Unauthorized", "message": "valid SZZ provider bearer token required"})
            return
        try:
            length = int(self.headers.get("content-length", "0") or "0")
            body = self.rfile.read(length) if length else b"{}"
            request = json.loads(body.decode("utf-8") or "{}")
            if not isinstance(request, dict):
                raise ValueError("request body must be a JSON object")
            request["_mode"] = mode
            value, status = run_analysis_request(request, mode)
            self.write_json(status, value)
        except Exception as exc:
            self.write_json(400, {"error": "BadRequest", "message": str(exc)})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("szz-provider " + (fmt % args) + "\n")

    def write_json(self, status: int, value: dict) -> None:
        payload = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve_provider(host: str, port: int) -> int:
    token = provider_token()
    if not token:
        sys.stderr.write(
            "Set one of REPOINTEL_SZZ_PROVIDER_TOKEN, "
            "METADATACOLLECTIONFACADE_REPOINTEL_SZZ_PROVIDER_TOKEN, or "
            "FRONTPLANE_AUTH_REPOINTEL_SZZ_PROVIDER_TOKEN to start the SZZ provider.\n"
        )
        return 2
    server = ThreadingHTTPServer((host, port), SzzProviderHandler)
    server.provider_token = token
    sys.stderr.write(f"Repointel SZZ provider listening on http://{host}:{port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main() -> int:
    if "--provider" in sys.argv:
        host = os.environ.get("HOST", "127.0.0.1")
        port = int(os.environ.get("PORT", "18195"))
        return serve_provider(host, port)
    request = json.load(sys.stdin)
    mode = request.pop("_mode", "batch")
    value, _status = run_analysis_request(request, mode)
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("status") != "failed" else 1


if __name__ == "__main__":
    sys.exit(main())
