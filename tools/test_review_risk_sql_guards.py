#!/usr/bin/env python3
import re
import unittest
from pathlib import Path


SERVER = Path(__file__).resolve().parents[1] / "ux" / "server.mjs"


class ReviewRiskSqlGuardTests(unittest.TestCase):
    def test_owner_git_line_survival_match_is_repository_scoped(self) -> None:
        source = SERVER.read_text(encoding="utf-8")

        self.assertIn("git_author.doc->>'repository_id' as repository_id", source)
        self.assertRegex(
            source,
            re.compile(
                r"join\s+git_candidates\s+g\s+on\s+g\.repository_id\s*=\s*o\.repository_id",
                re.IGNORECASE,
            ),
        )

    def test_author_history_route_accepts_review_number_identity(self) -> None:
        source = SERVER.read_text(encoding="utf-8")

        self.assertIn("/api/repointel-author-history", source)
        self.assertIn("change_number", source)
        self.assertIn("change_owner_seed", source)

    def test_author_history_supports_normalized_last_name_matching(self) -> None:
        source = SERVER.read_text(encoding="utf-8")

        self.assertIn("last_name", source)
        self.assertIn("last_name_key", source)
        self.assertIn("name_last_name", source)
        self.assertIn("query_last_name", source)

    def test_author_history_returns_nested_repository_analysis(self) -> None:
        source = SERVER.read_text(encoding="utf-8")

        self.assertIn("'repository_analysis'", source)
        self.assertIn("'matched_authors'", source)
        self.assertIn("'line_survival'", source)
        self.assertIn("'author_history_risk_v1'", source)
        self.assertIn("'author_history_review_risk_v1'", source)

    def test_changed_lines_is_separate_review_risk_score(self) -> None:
        source = SERVER.read_text(encoding="utf-8")

        self.assertIn("changed_lines_score", source)
        self.assertIn("bucket_score", source)
        self.assertIn("reviewRiskWeightedBucketScore", source)
        self.assertIn("bucket: \"Changed lines\"", source)
        self.assertNotIn("'bucket', 'Changed lines'", source)

    def test_author_history_keeps_bug_evidence_sources(self) -> None:
        source = SERVER.read_text(encoding="utf-8")

        self.assertIn("authored_bug_comment", source)
        self.assertIn("bug_links_to_authored_review", source)
        self.assertIn("authored_review_commit_message", source)
        self.assertIn("authored_git_commit_message", source)


if __name__ == "__main__":
    unittest.main()
