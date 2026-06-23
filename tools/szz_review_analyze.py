#!/usr/bin/env python3
"""SZZ-style analysis for a merged Gerrit review or fix commit.

The tool is intentionally standalone and dependency-free. It resolves a
merged review to a commit when Gerrit is reachable, parses bug footers from the
fix commit, then blames pre-fix deleted/modified lines to identify candidate
bug-introducing commits.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


BUG_FOOTER_RE = re.compile(
    r"^\s*(Closes-Bug|Close-Bug|Fixes-Bug|Partial-Bug|Related-Bug|Launchpad-Bug|LP)\s*:\s*(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
BUG_ID_RE = re.compile(r"(?:bugs?/|bug\s*#?|#)?(\d{5,})", re.IGNORECASE)
CHANGE_ID_RE = re.compile(r"^\s*Change-Id:\s*(I[0-9a-fA-F]{8,40})\s*$", re.MULTILINE)


DEFAULT_EXCLUDE_PATHS = [
    r"(^|/)doc(s)?/",
    r"(^|/)releasenotes/",
    r"(^|/)api-ref/",
    r"(^|/)test(s)?/",
    r"(^|/)tests?\.py$",
    r"(^|/)test_[^/]*\.py$",
    r"(^|/)[^/]*_test\.py$",
    r"(^|/)tools/",
    r"(^|/)examples?/",
    r"(^|/)vendor/",
    r"(^|/)node_modules/",
    r"(^|/)dist/",
    r"(^|/)build/",
    r"\.rst$",
    r"\.md$",
    r"\.po$",
    r"\.pot$",
]

TEST_EXCLUDE_PATHS = {
    r"(^|/)test(s)?/",
    r"(^|/)tests?\.py$",
    r"(^|/)test_[^/]*\.py$",
    r"(^|/)[^/]*_test\.py$",
}


@dataclass(frozen=True)
class BugLink:
    bug_id: str
    link_type: str
    source: str
    confidence: float


@dataclass(frozen=True)
class LineRef:
    path: str
    line_no: int
    content: str


@dataclass
class BlameLine:
    commit: str
    author_name: str = ""
    author_email: str = ""
    authored_at: str = ""
    summary: str = ""
    path: str = ""
    line_no: int = 0
    content: str = ""


@dataclass
class Candidate:
    commit: str
    author_name: str = ""
    author_email: str = ""
    authored_at: str = ""
    summary: str = ""
    blamed_lines: int = 0
    context_lines: int = 0
    files: Counter[str] = field(default_factory=Counter)
    file_roles: Counter[str] = field(default_factory=Counter)
    evidence: list[dict] = field(default_factory=list)


@dataclass
class DiffOldLines:
    changed_old_lines: int = 0
    added_lines: int = 0
    deleted_lines: int = 0
    skipped_old_lines: int = 0
    added_context_lines: int = 0
    skipped_files: Counter[str] = field(default_factory=Counter)
    ranges_by_file: dict[str, list[tuple[int, int]]] = field(default_factory=lambda: defaultdict(list))
    added_context_ranges_by_file: dict[str, list[tuple[int, int]]] = field(default_factory=lambda: defaultdict(list))


def git_stdout(repo: Path, args: list[str], *, check: bool = True) -> str:
    output = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and output.returncode != 0:
        raise SystemExit(output.stderr.strip() or f"git {' '.join(args)} failed")
    return output.stdout


def git_exists(repo: Path, rev: str) -> bool:
    output = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return output.returncode == 0


def resolve_commit(repo: Path, commit: str) -> str:
    return git_stdout(repo, ["rev-parse", f"{commit}^{{commit}}"]).strip()


def commit_message(repo: Path, commit: str) -> str:
    return git_stdout(repo, ["show", "-s", "--format=%B", commit])


def commit_meta(repo: Path, commit: str) -> dict:
    raw = git_stdout(repo, ["show", "-s", "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%s", commit]).rstrip("\n")
    fields = raw.split("\x00")
    if len(fields) < 6:
        raise SystemExit(f"could not parse commit metadata for {commit}")
    sha, parents, author_name, author_email, authored_at, subject = fields[:6]
    return {
        "sha": sha,
        "parents": parents.split() if parents else [],
        "author_name": author_name,
        "author_email": author_email,
        "authored_at": authored_at,
        "subject": subject,
    }


def resolve_gerrit_review(gerrit_url: str, review: str) -> dict:
    encoded = urllib.parse.quote(review, safe="")
    url = f"{gerrit_url.rstrip('/')}/changes/{encoded}/detail?o=CURRENT_REVISION&o=CURRENT_COMMIT"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - network is optional in tests.
        raise SystemExit(
            f"could not resolve Gerrit review {review}: {exc}. "
            "Pass --commit with the merged commit SHA to run fully offline."
        )
    if payload.startswith(")]}'"):
        payload = payload.split("\n", 1)[1]
    data = json.loads(payload)
    current_revision = data.get("current_revision") or ""
    if not current_revision:
        raise SystemExit(f"Gerrit review {review} did not include current_revision")
    return {
        "review": str(data.get("_number") or review),
        "project": data.get("project") or "",
        "branch": data.get("branch") or "",
        "status": data.get("status") or "",
        "current_revision": current_revision,
        "change_id": data.get("change_id") or "",
        "subject": data.get("subject") or "",
        "url": f"{gerrit_url.rstrip('/')}/c/{data.get('project', '')}/+/{data.get('_number', review)}",
    }


def parse_bug_links(message: str) -> list[BugLink]:
    by_bug: dict[str, BugLink] = {}
    for match in BUG_FOOTER_RE.finditer(message):
        raw_type = match.group(1).lower()
        body = match.group(2)
        link_type = normalize_bug_link_type(raw_type)
        for bug_match in BUG_ID_RE.finditer(body):
            bug_id = bug_match.group(1)
            link = BugLink(
                bug_id=bug_id,
                link_type=link_type,
                source=match.group(0).strip(),
                confidence=bug_link_confidence(link_type),
            )
            current = by_bug.get(bug_id)
            if current is None or link.confidence > current.confidence:
                by_bug[bug_id] = link
    return sorted(by_bug.values(), key=lambda item: (-item.confidence, item.bug_id))


def normalize_bug_link_type(raw: str) -> str:
    if raw in {"closes-bug", "close-bug", "fixes-bug", "lp", "launchpad-bug"}:
        return "closes"
    if raw == "partial-bug":
        return "partial"
    return "related"


def bug_link_confidence(link_type: str) -> float:
    return {"closes": 1.0, "partial": 0.75, "related": 0.35}.get(link_type, 0.1)


def parse_change_id(message: str) -> str:
    match = CHANGE_ID_RE.search(message)
    return match.group(1) if match else ""


def compile_excludes(patterns: list[str], include_tests: bool) -> list[re.Pattern[str]]:
    active = []
    for pattern in patterns:
        if include_tests and pattern in TEST_EXCLUDE_PATHS:
            continue
        active.append(re.compile(pattern))
    return active


def path_role(path: str) -> str:
    lower = path.lower()
    if re.search(r"(^|/)test(s)?/", lower) or lower.startswith("test_") or "/test_" in lower:
        return "test"
    if re.search(r"(^|/)doc(s)?/|(^|/)releasenotes/|(^|/)api-ref/|\.rst$|\.md$", lower):
        return "docs"
    if re.search(r"(^|/)vendor/|(^|/)node_modules/|(^|/)dist/|(^|/)build/|\.po$|\.pot$", lower):
        return "generated_or_vendor"
    return "code"


def excluded(path: str, excludes: Iterable[re.Pattern[str]]) -> bool:
    return any(pattern.search(path) for pattern in excludes)


def normalize_diff_path(value: str) -> str:
    value = value.strip()
    if value == "/dev/null":
        return value
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if value.startswith("a/") or value.startswith("b/"):
        return value[2:]
    return value


def parse_hunk_old_range(line: str) -> tuple[int, int] | None:
    match = re.match(r"@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@", line)
    if not match:
        return None
    start = int(match.group(1))
    count = int(match.group(2) or "1")
    return start, count


def extract_old_lines_from_diff(diff_text: str, excludes: list[re.Pattern[str]]) -> DiffOldLines:
    result = DiffOldLines()
    old_path = ""
    current_path = ""
    current_old_line = 0
    current_hunk_old_count = 0
    added_context_recorded_for_hunk = False
    file_is_excluded = False
    in_hunk = False
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            old_path = ""
            current_path = ""
            current_old_line = 0
            current_hunk_old_count = 0
            added_context_recorded_for_hunk = False
            file_is_excluded = False
            in_hunk = False
            continue
        if line.startswith("--- "):
            old_path = normalize_diff_path(line[4:])
            continue
        if line.startswith("+++ "):
            new_path = normalize_diff_path(line[4:])
            current_path = old_path if old_path != "/dev/null" else new_path
            file_is_excluded = current_path == "/dev/null" or excluded(current_path, excludes)
            continue
        if line.startswith("@@ "):
            parsed = parse_hunk_old_range(line)
            if parsed is None:
                in_hunk = False
                continue
            current_old_line = parsed[0]
            current_hunk_old_count = parsed[1]
            added_context_recorded_for_hunk = False
            in_hunk = True
            continue
        if not in_hunk or line.startswith("\\ "):
            continue
        if line.startswith("-") and not line.startswith("--- "):
            result.deleted_lines += 1
            if file_is_excluded:
                result.skipped_old_lines += 1
                result.skipped_files[current_path] += 1
            else:
                result.changed_old_lines += 1
                append_line(result.ranges_by_file[current_path], current_old_line)
            current_old_line += 1
        elif line.startswith("+") and not line.startswith("+++ "):
            result.added_lines += 1
            if (
                current_hunk_old_count == 0
                and not added_context_recorded_for_hunk
                and old_path != "/dev/null"
                and not file_is_excluded
            ):
                start = max(1, current_old_line - 1)
                end = max(start, current_old_line + 2)
                append_range(result.added_context_ranges_by_file[current_path], start, end)
                result.added_context_lines += end - start + 1
                added_context_recorded_for_hunk = True
        else:
            current_old_line += 1
    return result


def append_range(ranges: list[tuple[int, int]], start: int, end: int) -> None:
    for line_no in range(start, end + 1):
        append_line(ranges, line_no)


def append_line(ranges: list[tuple[int, int]], line_no: int) -> None:
    if ranges and ranges[-1][0] <= line_no <= ranges[-1][1]:
        return
    if ranges and ranges[-1][1] + 1 == line_no:
        start, _ = ranges[-1]
        ranges[-1] = (start, line_no)
    else:
        ranges.append((line_no, line_no))


def diff_old_lines(repo: Path, parent: str, commit: str, excludes: list[re.Pattern[str]]) -> DiffOldLines:
    diff = git_stdout(
        repo,
        [
            "diff",
            "--find-renames=40%",
            "--find-copies=40%",
            "--ignore-space-change",
            "--unified=0",
            parent,
            commit,
            "--",
        ],
    )
    return extract_old_lines_from_diff(diff, excludes)


def blame_range(
    repo: Path,
    parent: str,
    path: str,
    start: int,
    end: int,
    ignore_revs_file: Path | None,
) -> list[BlameLine]:
    args = ["blame", "--line-porcelain", "-w", "-M", "-C", "-L", f"{start},{end}"]
    if ignore_revs_file:
        args.extend(["--ignore-revs-file", str(ignore_revs_file)])
    args.extend([parent, "--", path])
    raw = git_stdout(repo, args, check=False)
    if not raw.strip():
        return []
    return parse_blame_porcelain(raw, path)


def parse_blame_porcelain(raw: str, path: str) -> list[BlameLine]:
    lines = []
    current: BlameLine | None = None
    for line in raw.splitlines():
        header = re.match(r"^([0-9a-f]{40})\s+\d+\s+(\d+)(?:\s+\d+)?$", line)
        if header:
            current = BlameLine(commit=header.group(1), path=path, line_no=int(header.group(2)))
            continue
        if current is None:
            continue
        if line.startswith("author "):
            current.author_name = line[7:]
        elif line.startswith("author-mail "):
            current.author_email = line[12:].strip("<>")
        elif line.startswith("author-time "):
            current.authored_at = timestamp_from_epoch(line[12:])
        elif line.startswith("summary "):
            current.summary = line[8:]
        elif line.startswith("\t"):
            current.content = line[1:]
            lines.append(current)
            current = None
    return lines


def timestamp_from_epoch(value: str) -> str:
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).isoformat()
    except ValueError:
        return ""


def analyze_szz(
    repo: Path,
    commit: str,
    review_info: dict | None,
    include_related_bug: bool,
    include_tests: bool,
    ignore_revs_file: Path | None,
    max_evidence_lines: int,
) -> dict:
    commit = resolve_commit(repo, commit)
    meta = commit_meta(repo, commit)
    if not meta["parents"]:
        raise SystemExit(f"{commit} has no parent; cannot run SZZ")
    parent = meta["parents"][0]
    message = commit_message(repo, commit)
    all_bug_links = parse_bug_links(message)
    bug_links = [
        link for link in all_bug_links if include_related_bug or link.link_type in {"closes", "partial"}
    ]
    excludes = compile_excludes(DEFAULT_EXCLUDE_PATHS, include_tests)
    old_lines = diff_old_lines(repo, parent, commit, excludes)
    candidates: dict[str, Candidate] = {}

    for path, ranges in sorted(old_lines.ranges_by_file.items()):
        for start, end in ranges:
            for blamed in blame_range(repo, parent, path, start, end, ignore_revs_file):
                if blamed.commit == commit:
                    continue
                add_candidate_line(candidates, blamed, path, "changed_old_line", max_evidence_lines)

    for path, ranges in sorted(old_lines.added_context_ranges_by_file.items()):
        for start, end in ranges:
            for blamed in blame_range(repo, parent, path, start, end, ignore_revs_file):
                if blamed.commit == commit:
                    continue
                add_candidate_line(candidates, blamed, path, "added_line_context", max_evidence_lines)

    link_confidence = max((link.confidence for link in bug_links), default=0.1)
    candidate_rows = [
        candidate_to_json(candidate, link_confidence, old_lines.changed_old_lines)
        for candidate in candidates.values()
    ]
    candidate_rows.sort(
        key=lambda row: (
            -row["score"],
            -row["blamed_lines"],
            row["commit"],
        )
    )
    direct_candidate_rows = [row for row in candidate_rows if row["direct_lines"] > 0]
    context_candidate_rows = [
        row for row in candidate_rows
        if row["direct_lines"] == 0 and row["context_lines"] > 0
    ]
    return {
        "repo": str(repo),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "review": review_info or {},
        "fix_commit": {
            "sha": commit,
            "parent": parent,
            "author_name": meta["author_name"],
            "author_email": meta["author_email"],
            "authored_at": meta["authored_at"],
            "subject": meta["subject"],
            "change_id": parse_change_id(message),
        },
        "bugs": [link.__dict__ for link in bug_links],
        "bug_links_all": [link.__dict__ for link in all_bug_links],
        "analysis": {
            "include_related_bug": include_related_bug,
            "include_tests": include_tests,
            "changed_old_lines_analyzed": old_lines.changed_old_lines,
            "added_lines_not_blameable": old_lines.added_lines,
            "added_context_lines_analyzed": old_lines.added_context_lines,
            "deleted_lines_seen": old_lines.deleted_lines,
            "skipped_old_lines": old_lines.skipped_old_lines,
            "skipped_files": [
                {"path": path, "old_lines": count}
                for path, count in old_lines.skipped_files.most_common()
            ],
            "candidate_count": len(direct_candidate_rows),
            "context_candidate_count": len(context_candidate_rows),
        },
        "candidate_introducing_commits": direct_candidate_rows,
        "added_line_context_candidates": context_candidate_rows,
    }


def add_candidate_line(
    candidates: dict[str, Candidate],
    blamed: BlameLine,
    path: str,
    source: str,
    max_evidence_lines: int,
) -> None:
    candidate = candidates.get(blamed.commit)
    if candidate is None:
        candidate = Candidate(
            commit=blamed.commit,
            author_name=blamed.author_name,
            author_email=blamed.author_email,
            authored_at=blamed.authored_at,
            summary=blamed.summary,
        )
        candidates[blamed.commit] = candidate
    candidate.blamed_lines += 1
    if source == "added_line_context":
        candidate.blamed_lines -= 1
        candidate.context_lines += 1
    candidate.files[path] += 1
    candidate.file_roles[path_role(path)] += 1
    if len(candidate.evidence) < max_evidence_lines:
        candidate.evidence.append(
            {
                "path": path,
                "line": blamed.line_no,
                "source": source,
                "content": blamed.content[:300],
            }
        )


def candidate_to_json(candidate: Candidate, bug_link_confidence: float, total_old_lines: int) -> dict:
    evidence_lines = candidate.blamed_lines + 0.35 * candidate.context_lines
    code_lines = candidate.file_roles.get("code", 0)
    useful_lines = code_lines + 0.45 * candidate.file_roles.get("test", 0) + 0.2 * candidate.file_roles.get("docs", 0)
    total_lines = candidate.blamed_lines + candidate.context_lines
    file_factor = useful_lines / total_lines if total_lines else 0.0
    # A one-line fix can be a precise bug fix, so line count should boost
    # confidence when there are multiple blamed lines rather than sharply
    # penalize small fixes.
    line_factor = 0.55 + 0.45 * min(1.0, math.log1p(evidence_lines) / math.log1p(12))
    context_factor = 1.0 if candidate.blamed_lines else 0.45
    fix_size_factor = 1.0
    if total_old_lines > 1000:
        fix_size_factor = 0.45
    elif total_old_lines > 300:
        fix_size_factor = 0.7
    score = round(100 * bug_link_confidence * file_factor * line_factor * fix_size_factor * context_factor, 1)
    return {
        "commit": candidate.commit,
        "author_name": candidate.author_name,
        "author_email": candidate.author_email,
        "authored_at": candidate.authored_at,
        "summary": candidate.summary,
        "blamed_lines": candidate.blamed_lines + candidate.context_lines,
        "direct_lines": candidate.blamed_lines,
        "context_lines": candidate.context_lines,
        "files_touched": len(candidate.files),
        "files": [
            {"path": path, "blamed_lines": count, "role": path_role(path)}
            for path, count in candidate.files.most_common()
        ],
        "file_roles": dict(candidate.file_roles),
        "score": score,
        "confidence": confidence_label(score),
        "evidence": candidate.evidence,
    }


def confidence_label(score: float) -> str:
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def markdown_report(result: dict, top: int) -> str:
    lines = [
        "# SZZ Review Analysis",
        "",
        f"- Repo: `{result['repo']}`",
        f"- Fix commit: `{result['fix_commit']['sha']}`",
        f"- Parent: `{result['fix_commit']['parent']}`",
        f"- Subject: {escape_md(result['fix_commit']['subject'])}",
        f"- Change-Id: `{result['fix_commit']['change_id'] or 'unknown'}`",
        f"- Bugs used: {', '.join(format_bug(link) for link in result['bugs']) or 'none'}",
        f"- Old lines analyzed: `{result['analysis']['changed_old_lines_analyzed']}`",
        f"- Added lines not blameable: `{result['analysis']['added_lines_not_blameable']}`",
        f"- Added context lines analyzed: `{result['analysis'].get('added_context_lines_analyzed', 0)}`",
        f"- Skipped old lines: `{result['analysis']['skipped_old_lines']}`",
        f"- Direct SZZ candidate commits: `{result['analysis']['candidate_count']}`",
        f"- Added-line context candidates: `{result['analysis'].get('context_candidate_count', 0)}`",
        "",
        "## Direct SZZ Candidate Commits",
        "",
        "| Commit | Confidence | Score | Lines | Files | Author | Subject |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for candidate in result["candidate_introducing_commits"][:top]:
        lines.append(
            "| `{commit}` | {confidence} | {score:.1f} | {lines_count} | {files} | {author} | {subject} |".format(
                commit=candidate["commit"][:12],
                confidence=candidate["confidence"],
                score=candidate["score"],
                lines_count=candidate["direct_lines"],
                files=candidate["files_touched"],
                author=escape_md(candidate["author_name"] or candidate["author_email"]),
                subject=escape_md(candidate["summary"]),
            )
        )
    lines.append("")
    context_candidates = result.get("added_line_context_candidates", [])
    if context_candidates:
        lines.extend(
            [
                "## Added-Line Context Heuristic",
                "",
                "These are not classic SZZ candidates. They blame nearby pre-fix lines around added-only hunks, useful for missing guard/escape-table fixes.",
                "",
                "| Commit | Heuristic Score | Context Lines | Files | Author | Subject |",
                "|---|---:|---:|---:|---|---|",
            ]
        )
        for candidate in context_candidates[:top]:
            lines.append(
                "| `{commit}` | {score:.1f} | {context_lines} | {files} | {author} | {subject} |".format(
                    commit=candidate["commit"][:12],
                    score=candidate["score"],
                    context_lines=candidate.get("context_lines", 0),
                    files=candidate["files_touched"],
                    author=escape_md(candidate["author_name"] or candidate["author_email"]),
                    subject=escape_md(candidate["summary"]),
                )
            )
        lines.append("")
    if result["analysis"]["skipped_files"]:
        lines.extend(["## Skipped Files", ""])
        for skipped in result["analysis"]["skipped_files"][:20]:
            lines.append(f"- `{skipped['path']}`: {skipped['old_lines']} old lines")
        lines.append("")
    return "\n".join(lines)


def escape_md(value: str) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def format_bug(link: dict) -> str:
    return f"{link['link_type']}:{link['bug_id']}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SZZ-style analysis for a merged Gerrit review or fix commit.")
    parser.add_argument("--repo", required=True, type=Path, help="Local git repository path.")
    parser.add_argument("--commit", help="Merged fix commit SHA. If omitted, --review is resolved through Gerrit.")
    parser.add_argument("--review", help="Gerrit review/change number.")
    parser.add_argument("--gerrit-url", default="https://review.opendev.org")
    parser.add_argument("--include-related-bug", action="store_true", help="Include Related-Bug links as bug-fix evidence.")
    parser.add_argument("--include-tests", action="store_true", help="Include tests/docs paths in blame analysis.")
    parser.add_argument("--ignore-revs-file", type=Path, help="Path to git blame ignore-revs file.")
    parser.add_argument("--max-evidence-lines", type=int, default=5)
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()

    repo = args.repo.expanduser().resolve()
    if not (repo / ".git").exists():
        raise SystemExit(f"{repo} does not look like a git repository")
    if not args.commit and not args.review:
        raise SystemExit("pass --commit or --review")

    review_info = None
    commit = args.commit
    if not commit:
        review_info = resolve_gerrit_review(args.gerrit_url, args.review or "")
        if review_info.get("status") != "MERGED":
            raise SystemExit(f"review {args.review} is {review_info.get('status')}, not MERGED")
        commit = review_info["current_revision"]
    elif args.review:
        review_info = {"review": args.review}

    assert commit is not None
    if not git_exists(repo, commit):
        raise SystemExit(f"commit {commit} is not present in {repo}; update/fetch the git repo first")

    result = analyze_szz(
        repo=repo,
        commit=commit,
        review_info=review_info,
        include_related_bug=args.include_related_bug,
        include_tests=args.include_tests,
        ignore_revs_file=args.ignore_revs_file,
        max_evidence_lines=args.max_evidence_lines,
    )
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = markdown_report(result, args.top)
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
