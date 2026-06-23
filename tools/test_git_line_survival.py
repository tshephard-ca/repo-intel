#!/usr/bin/env python3
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("git_line_survival.py")
SPEC = importlib.util.spec_from_file_location("git_line_survival", MODULE_PATH)
git_line_survival = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(git_line_survival)


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


class SelectBranchTests(unittest.TestCase):
    def test_plain_master_prefers_origin_master_when_local_branch_lags(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            origin = root / "origin.git"
            work = root / "work"

            subprocess.run(["git", "init", "--bare", "--initial-branch=master", str(origin)], check=True)
            subprocess.run(["git", "clone", str(origin), str(work)], check=True, stdout=subprocess.PIPE)
            git(work, "config", "user.name", "Test Author")
            git(work, "config", "user.email", "test@example.com")

            tracked = work / "tracked.txt"
            tracked.write_text("one\n", encoding="utf-8")
            git(work, "add", "tracked.txt")
            git(work, "commit", "-m", "first")
            git(work, "push", "origin", "master")

            tracked.write_text("one\ntwo\n", encoding="utf-8")
            git(work, "commit", "-am", "second")
            git(work, "push", "origin", "master")
            git(work, "reset", "--hard", "HEAD~1")

            self.assertNotEqual(
                git(work, "rev-parse", "master"),
                git(work, "rev-parse", "origin/master"),
            )
            self.assertEqual(git_line_survival.select_branch(work, "master"), "origin/master")


if __name__ == "__main__":
    unittest.main()
