#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class LineOwner:
    commit_sha: str
    author_key: str
    author_name: str
    author_email: str
    authored_at: str
    track_stats: bool


@dataclass
class CommitStats:
    sha: str
    authored_at: str
    author_key: str
    author_name: str
    author_email: str
    subject: str
    changed_lines: int
    changed_files: int
    files: set[str] = field(default_factory=set)
    insertions: int = 0
    deletions: int = 0
    surviving_lines: int = 0
    self_reworked_lines: int = 0
    cross_author_overwritten_lines: int = 0
    overwritten_by: Counter = field(default_factory=Counter)


@dataclass
class AuthorStats:
    author_key: str
    author_name: str
    author_email: str
    commits: set[str] = field(default_factory=set)
    files: set[str] = field(default_factory=set)
    insertions: int = 0
    deletions: int = 0
    surviving_lines: int = 0
    self_reworked_lines: int = 0
    cross_author_overwritten_lines: int = 0
    overwrote_other_author_lines: int = 0


class Analyzer:
    def __init__(self, repo: Path, branch: str, limit: int, max_changed_lines: int, since: datetime | None):
        self.repo = repo
        self.branch = branch
        self.limit = limit
        self.max_changed_lines = max_changed_lines
        self.since = since
        self.file_lines: dict[str, list[LineOwner]] = defaultdict(list)
        self.commits: dict[str, CommitStats] = {}
        self.authors: dict[str, AuthorStats] = {}
        self.commits_replayed = 0
        self.commits_seen = 0
        self.commits_before_since = 0
        self.commits_analyzed = 0
        self.commits_skipped_by_size = 0

    def analyze(self) -> dict:
        head_sha = git_stdout(self.repo, ["rev-parse", f"{self.branch}^{{commit}}"])
        total_commits = int(git_stdout(self.repo, ["rev-list", "--count", self.branch]) or "0")
        cmd = [
            "git",
            "-C",
            str(self.repo),
            "log",
            "--reverse",
            "--topo-order",
            self.branch,
            "--date=iso-strict",
            "--pretty=format:%x1e%H%x00%aI%x00%an%x00%ae%x00%s%x00",
            "--no-renames",
            "--unified=0",
            "--patch",
        ]
        if self.limit > 0:
            cmd.insert(7, f"-n{self.limit}")
        output = subprocess.run(
            cmd,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if output.returncode != 0:
            raise SystemExit(output.stderr.strip() or "git log failed")

        for record in output.stdout.split("\x1e"):
            self.process_record(record.strip("\n\0"))

        for owners in self.file_lines.values():
            for owner in owners:
                if not owner.track_stats:
                    continue
                self.ensure_commit(owner).surviving_lines += 1
                self.ensure_author(owner).surviving_lines += 1

        authors = [self.author_json(stats) for stats in self.authors.values()]
        commits = [self.commit_json(stats) for stats in self.commits.values()]
        authors.sort(
            key=lambda item: (
                -item["cross_author_overwrite_rate"],
                -item["cross_author_overwritten_lines"],
                -item["insertions_tracked"],
                item["author_key"],
            )
        )
        commits.sort(
            key=lambda item: (
                -item["cross_author_overwrite_rate"],
                -item["cross_author_overwritten_lines"],
                item["sha"],
            )
        )
        return {
            "repo": str(self.repo),
            "branch": self.branch,
            "head_sha": head_sha,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_commits_on_branch": total_commits,
            "since": self.since.isoformat() if self.since else "",
            "commits_replayed": self.commits_replayed,
            "commits_seen": self.commits_seen,
            "commits_before_since": self.commits_before_since,
            "commits_analyzed": self.commits_analyzed,
            "commits_skipped_by_size": self.commits_skipped_by_size,
            "max_changed_lines": self.max_changed_lines,
            "files_tracked": len(self.file_lines),
            "authors_count": len(authors),
            "tracked_insertions": sum(item["insertions_tracked"] for item in authors),
            "tracked_deletions": sum(item["deletions_tracked"] for item in authors),
            "surviving_lines": sum(item["surviving_lines"] for item in authors),
            "cross_author_overwritten_lines": sum(
                item["cross_author_overwritten_lines"] for item in authors
            ),
            "line_survival_rate": ratio(
                sum(item["surviving_lines"] for item in authors),
                sum(item["insertions_tracked"] for item in authors),
            ),
            "cross_author_overwrite_rate": ratio(
                sum(item["cross_author_overwritten_lines"] for item in authors),
                sum(item["insertions_tracked"] for item in authors),
            ),
            "authors": authors,
            "commits": commits,
        }

    def process_record(self, record: str) -> None:
        if not record:
            return
        fields = record.split("\0", 5)
        if len(fields) < 6:
            return
        sha, authored_at, author_name, author_email, subject, patch = fields
        sha = sha.strip()
        if not sha:
            return
        authored_at_dt = parse_timestamp(authored_at.strip())
        in_window = self.since is None or authored_at_dt >= self.since
        changed_lines = patch_changed_lines(patch)
        changed_files = patch_changed_files(patch)
        track_stats = in_window and (self.max_changed_lines <= 0 or changed_lines <= self.max_changed_lines)
        owner = LineOwner(
            commit_sha=sha,
            authored_at=authored_at.strip(),
            author_name=author_name.strip(),
            author_email=author_email.strip(),
            author_key=author_key(author_name, author_email),
            track_stats=track_stats,
        )
        self.commits_replayed += 1
        if in_window:
            self.commits_seen += 1
            if track_stats:
                self.commits_analyzed += 1
                commit = self.ensure_commit(owner)
                commit.subject = subject.strip()
                commit.changed_lines = changed_lines
                commit.changed_files = changed_files
                self.ensure_author(owner).commits.add(sha)
            else:
                self.commits_skipped_by_size += 1
        else:
            self.commits_before_since += 1
        self.apply_patch(patch, owner)

    def apply_patch(self, patch: str, owner: LineOwner) -> None:
        old_path = ""
        current_path = ""
        line_delta = 0
        current_index = 0
        in_hunk = False
        for line in patch.splitlines():
            if line.startswith("diff --git "):
                old_path = ""
                current_path = ""
                line_delta = 0
                current_index = 0
                in_hunk = False
                continue
            if line.startswith("--- "):
                old_path = normalize_diff_path(line[4:])
                continue
            if line.startswith("+++ "):
                new_path = normalize_diff_path(line[4:])
                current_path = old_path if new_path == "/dev/null" else new_path
                continue
            if line.startswith("@@ "):
                old_start = hunk_old_start(line)
                if old_start is not None:
                    base = max(old_start - 1, 0)
                    current_index = max(base + line_delta, 0)
                    in_hunk = bool(current_path and current_path != "/dev/null")
                continue
            if not in_hunk or line.startswith("\\ "):
                continue
            if line.startswith("-") and not line.startswith("--- "):
                self.record_deletion(owner, current_path, current_index)
                line_delta -= 1
            elif line.startswith("+") and not line.startswith("+++ "):
                self.record_addition(owner, current_path, current_index)
                current_index += 1
                line_delta += 1
            elif line.startswith(" "):
                current_index += 1

    def record_addition(self, owner: LineOwner, path: str, index: int) -> None:
        lines = self.file_lines[path]
        index = min(index, len(lines))
        lines.insert(index, owner)
        if not owner.track_stats:
            return
        commit = self.ensure_commit(owner)
        author = self.ensure_author(owner)
        commit.insertions += 1
        commit.files.add(path)
        author.insertions += 1
        author.files.add(path)

    def record_deletion(self, owner: LineOwner, path: str, index: int) -> None:
        if owner.track_stats:
            commit = self.ensure_commit(owner)
            author = self.ensure_author(owner)
            commit.deletions += 1
            commit.files.add(path)
            author.deletions += 1
            author.files.add(path)
        lines = self.file_lines.get(path)
        if not lines or index >= len(lines):
            return
        previous = lines.pop(index)
        if not previous.track_stats:
            return
        if previous.author_key == owner.author_key and owner.track_stats:
            self.ensure_commit(previous).self_reworked_lines += 1
            self.ensure_author(previous).self_reworked_lines += 1
        elif owner.track_stats:
            previous_commit = self.ensure_commit(previous)
            previous_commit.cross_author_overwritten_lines += 1
            previous_commit.overwritten_by[owner.author_key] += 1
            self.ensure_author(previous).cross_author_overwritten_lines += 1
            self.ensure_author(owner).overwrote_other_author_lines += 1

    def ensure_commit(self, owner: LineOwner) -> CommitStats:
        stats = self.commits.get(owner.commit_sha)
        if stats is None:
            stats = CommitStats(
                sha=owner.commit_sha,
                authored_at=owner.authored_at,
                author_key=owner.author_key,
                author_name=owner.author_name,
                author_email=owner.author_email,
                subject="",
                changed_lines=0,
                changed_files=0,
            )
            self.commits[owner.commit_sha] = stats
        return stats

    def ensure_author(self, owner: LineOwner) -> AuthorStats:
        stats = self.authors.get(owner.author_key)
        if stats is None:
            stats = AuthorStats(
                author_key=owner.author_key,
                author_name=owner.author_name,
                author_email=owner.author_email,
            )
            self.authors[owner.author_key] = stats
        return stats

    def commit_json(self, stats: CommitStats) -> dict:
        return {
            "sha": stats.sha,
            "authored_at": stats.authored_at,
            "author_key": stats.author_key,
            "author_name": stats.author_name,
            "author_email": stats.author_email,
            "subject": stats.subject,
            "changed_lines": stats.changed_lines,
            "changed_files": stats.changed_files,
            "files_touched": len(stats.files),
            "insertions_tracked": stats.insertions,
            "deletions_tracked": stats.deletions,
            "surviving_lines": stats.surviving_lines,
            "self_reworked_lines": stats.self_reworked_lines,
            "cross_author_overwritten_lines": stats.cross_author_overwritten_lines,
            "line_survival_rate": ratio(stats.surviving_lines, stats.insertions),
            "cross_author_overwrite_rate": ratio(
                stats.cross_author_overwritten_lines, stats.insertions
            ),
            "self_rework_rate": ratio(stats.self_reworked_lines, stats.insertions),
            "overwritten_by": [
                {"author_key": key, "lines": value}
                for key, value in stats.overwritten_by.most_common()
            ],
        }

    def author_json(self, stats: AuthorStats) -> dict:
        return {
            "author_key": stats.author_key,
            "author_name": stats.author_name,
            "author_email": stats.author_email,
            "commits_analyzed": len(stats.commits),
            "files_touched": len(stats.files),
            "insertions_tracked": stats.insertions,
            "deletions_tracked": stats.deletions,
            "surviving_lines": stats.surviving_lines,
            "self_reworked_lines": stats.self_reworked_lines,
            "cross_author_overwritten_lines": stats.cross_author_overwritten_lines,
            "overwrote_other_author_lines": stats.overwrote_other_author_lines,
            "line_survival_rate": ratio(stats.surviving_lines, stats.insertions),
            "cross_author_overwrite_rate": ratio(
                stats.cross_author_overwritten_lines, stats.insertions
            ),
            "self_rework_rate": ratio(stats.self_reworked_lines, stats.insertions),
            "overwrites_other_author_rate": ratio(
                stats.overwrote_other_author_lines, stats.deletions
            ),
        }


def git_stdout(repo: Path, args: list[str]) -> str:
    output = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if output.returncode != 0:
        raise SystemExit(output.stderr.strip() or f"git {' '.join(args)} failed")
    return output.stdout.strip()


def select_branch(repo: Path, preferred: str | None) -> str:
    candidates = []

    def add_candidate(candidate: str | None) -> None:
        if not candidate:
            return
        # Prefer the remote-tracking ref for normal branch names. Local
        # branches in long-lived analysis checkouts can lag origin/master.
        if "/" not in candidate and not candidate.startswith("refs/"):
            candidates.append(f"origin/{candidate}")
        candidates.append(candidate)

    add_candidate(preferred)
    current = subprocess.run(
        ["git", "-C", str(repo), "symbolic-ref", "--quiet", "--short", "HEAD"],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if current.returncode == 0 and current.stdout.strip():
        add_candidate(current.stdout.strip())
    add_candidate("master")
    add_candidate("main")
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        exists = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if exists.returncode == 0:
            return candidate
    branches = git_stdout(repo, ["for-each-ref", "--format=%(refname:short)", "refs/heads"]).splitlines()
    if not branches:
        raise SystemExit("no local branches found")
    return max(branches, key=lambda branch: int(git_stdout(repo, ["rev-list", "--count", branch]) or "0"))


def parse_timestamp(value: str) -> datetime:
    value = value.strip()
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    if len(value) == 10 and value[4] == "-" and value[7] == "-":
        value = f"{value}T00:00:00+00:00"
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def patch_changed_lines(patch: str) -> int:
    changed = 0
    in_hunk = False
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
        elif line.startswith("@@ "):
            in_hunk = True
        elif in_hunk and not line.startswith("\\ "):
            if (line.startswith("-") and not line.startswith("--- ")) or (
                line.startswith("+") and not line.startswith("+++ ")
            ):
                changed += 1
    return changed


def patch_changed_files(patch: str) -> int:
    return sum(1 for line in patch.splitlines() if line.startswith("diff --git "))


def normalize_diff_path(path: str) -> str:
    path = path.strip().strip('"')
    if path == "/dev/null":
        return path
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def hunk_old_start(line: str) -> int | None:
    if not line.startswith("@@ -"):
        return None
    chunk = line[4:].split(None, 1)[0]
    return int(chunk.split(",", 1)[0])


def author_key(name: str, email: str) -> str:
    email = email.strip()
    return email or name.strip()


def ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def markdown_report(result: dict, top: int, min_insertions: int) -> str:
    authors = [a for a in result["authors"] if a["insertions_tracked"] >= min_insertions]
    commits = result["commits"][:top]
    lines = [
        f"# Git Line Survival Report",
        "",
        f"- Repo: `{result['repo']}`",
        f"- Branch: `{result['branch']}`",
        f"- Head: `{result['head_sha']}`",
        f"- Since: `{result['since'] or 'full history'}`",
        f"- Max changed lines scored: `{result['max_changed_lines']}`",
        f"- Commits replayed: `{result['commits_replayed']}`",
        f"- Commits in window: `{result['commits_seen']}`",
        f"- Commits scored: `{result['commits_analyzed']}`",
        f"- Commits skipped by size: `{result['commits_skipped_by_size']}`",
        f"- Authors scored: `{result['authors_count']}`",
        f"- Tracked insertions: `{result['tracked_insertions']}`",
        f"- Surviving lines: `{result['surviving_lines']}`",
        f"- Overall line survival rate: `{result['line_survival_rate']}`",
        f"- Overall cross-author overwrite rate: `{result['cross_author_overwrite_rate']}`",
        "",
        f"## Authors By Cross-Author Overwrite Rate",
        "",
        "| Author | Commits | Insertions | Surviving | Cross-author overwritten | Survival rate | Cross-author overwrite rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for author in authors[:top]:
        lines.append(
            "| {author} | {commits} | {insertions} | {surviving} | {overwritten} | {survival:.2%} | {overwrite:.2%} |".format(
                author=author["author_name"] or author["author_key"],
                commits=author["commits_analyzed"],
                insertions=author["insertions_tracked"],
                surviving=author["surviving_lines"],
                overwritten=author["cross_author_overwritten_lines"],
                survival=author["line_survival_rate"],
                overwrite=author["cross_author_overwrite_rate"],
            )
        )
    lines.extend(
        [
            "",
            f"## Commits By Cross-Author Overwrite Rate",
            "",
            "| Commit | Author | Changed lines | Insertions | Cross-author overwritten | Survival rate | Subject |",
            "|---|---|---:|---:|---:|---:|---|",
        ]
    )
    for commit in commits:
        lines.append(
            "| `{sha}` | {author} | {changed} | {insertions} | {overwritten} | {survival:.2%} | {subject} |".format(
                sha=commit["sha"][:12],
                author=commit["author_name"] or commit["author_key"],
                changed=commit["changed_lines"],
                insertions=commit["insertions_tracked"],
                overwritten=commit["cross_author_overwritten_lines"],
                survival=commit["line_survival_rate"],
                subject=commit["subject"].replace("|", "\\|"),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze git line survival and cross-author overwrites.")
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--branch")
    parser.add_argument("--since", help="Only score commits at or after this date/time; older commits are replayed for line state.")
    parser.add_argument("--limit", type=int, default=0, help="Maximum commits to scan; 0 means all.")
    parser.add_argument(
        "--max-changed-lines",
        type=int,
        default=100,
        help="Only score commits with this many changed lines or fewer. 0 disables the cutoff.",
    )
    parser.add_argument("--min-insertions", type=int, default=100)
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()

    repo = args.repo.expanduser().resolve()
    if not (repo / ".git").exists():
        raise SystemExit(f"{repo} does not look like a git repo")
    branch = select_branch(repo, args.branch)
    since = parse_timestamp(args.since) if args.since else None
    result = Analyzer(repo, branch, args.limit, args.max_changed_lines, since).analyze()

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    report = markdown_report(result, args.top, args.min_insertions)
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(report)
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
