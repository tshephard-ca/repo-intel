#!/usr/bin/env python3
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("szz_review_analyze.py")
SPEC = importlib.util.spec_from_file_location("szz_review_analyze", MODULE_PATH)
szz_review_analyze = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules["szz_review_analyze"] = szz_review_analyze
SPEC.loader.exec_module(szz_review_analyze)


def git(repo: Path, *args: str) -> str:
    output = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return output.stdout.strip()


def init_repo(root: Path) -> Path:
    repo = root / "repo"
    subprocess.run(["git", "init", "--initial-branch=master", str(repo)], check=True, stdout=subprocess.PIPE)
    git(repo, "config", "user.name", "Test Author")
    git(repo, "config", "user.email", "test@example.com")
    return repo


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", ".")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


class SzzReviewAnalyzeTests(unittest.TestCase):
    def test_changed_line_fix_blames_original_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = init_repo(Path(temp_dir))
            app = repo / "app.py"
            app.write_text(
                "def can_read(user, token):\n"
                "    return user.is_admin\n",
                encoding="utf-8",
            )
            inducing = commit_all(repo, "Add admin check")

            app.write_text(
                "def can_read(user, token):\n"
                "    return user.is_admin and user.project_id == token.project_id\n",
                encoding="utf-8",
            )
            fix = commit_all(repo, "Scope admin check\n\nCloses-Bug: #2149789\nChange-Id: Iabc1234567890")

            result = szz_review_analyze.analyze_szz(
                repo=repo,
                commit=fix,
                review_info={"review": "990001"},
                include_related_bug=False,
                include_tests=False,
                ignore_revs_file=None,
                max_evidence_lines=5,
            )

            self.assertEqual(result["bugs"][0]["bug_id"], "2149789")
            self.assertEqual(result["analysis"]["changed_old_lines_analyzed"], 1)
            candidates = result["candidate_introducing_commits"]
            self.assertEqual(candidates[0]["commit"], inducing)
            self.assertEqual(candidates[0]["blamed_lines"], 1)
            self.assertEqual(candidates[0]["confidence"], "medium")

    def test_added_only_fix_uses_context_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = init_repo(Path(temp_dir))
            app = repo / "app.py"
            app.write_text("def validate(value):\n    return True\n", encoding="utf-8")
            inducing = commit_all(repo, "Add validator")

            app.write_text(
                "def validate(value):\n"
                "    if value is None:\n"
                "        return False\n"
                "    return True\n",
                encoding="utf-8",
            )
            fix = commit_all(repo, "Reject None values\n\nCloses-Bug: #2150001")

            result = szz_review_analyze.analyze_szz(
                repo=repo,
                commit=fix,
                review_info=None,
                include_related_bug=False,
                include_tests=False,
                ignore_revs_file=None,
                max_evidence_lines=5,
            )

            self.assertEqual(result["analysis"]["changed_old_lines_analyzed"], 0)
            self.assertEqual(result["analysis"]["added_lines_not_blameable"], 2)
            self.assertGreaterEqual(result["analysis"]["added_context_lines_analyzed"], 1)
            self.assertEqual(result["candidate_introducing_commits"], [])
            self.assertEqual(result["added_line_context_candidates"][0]["commit"], inducing)
            self.assertGreaterEqual(result["added_line_context_candidates"][0]["context_lines"], 1)

    def test_related_bug_is_excluded_by_default(self) -> None:
        message = "Improve docs\n\nRelated-Bug: #123456\nPartial-Bug: #234567\n"
        links = szz_review_analyze.parse_bug_links(message)
        self.assertEqual([link.link_type for link in links], ["partial", "related"])

    def test_tests_py_is_excluded_unless_tests_are_included(self) -> None:
        default_excludes = szz_review_analyze.compile_excludes(
            szz_review_analyze.DEFAULT_EXCLUDE_PATHS,
            include_tests=False,
        )
        include_tests_excludes = szz_review_analyze.compile_excludes(
            szz_review_analyze.DEFAULT_EXCLUDE_PATHS,
            include_tests=True,
        )
        path = "openstack_dashboard/dashboards/project/api_access/tests.py"

        self.assertTrue(any(pattern.search(path) for pattern in default_excludes))
        self.assertFalse(any(pattern.search(path) for pattern in include_tests_excludes))


if __name__ == "__main__":
    unittest.main()
