# Review Risk Mission Tuning Validation

Generated on 2026-06-10 after switching Review Risk from a flat blended score to a mission-priority lane score.

Mission anchor:

- A novel approach to vulnerability discovery using author competence, reviewer competence, review churn, and review comment-smell signals to prioritize likely vulnerability loci.
- Stay generic across repositories and ecosystems; resist overfitting.

## What Changed

The previous `risk_score` was a flat sum:

`security + author risk + reviewer risk + implementation risk + friction + rework + stale`

That let security relevance dominate too much.

The new primary score is `deep_review_priority_score`, exposed as `risk_score` for the UI. It still keeps the old value as `flat_risk_score`.

New decision fields:

- `priority_lane`
- `security_locus`
- `change_shape`
- `author_competence_bucket`
- `reviewer_competence_bucket`
- `process_smell_bucket`

Ranking now sorts by:

`priority_lane -> deep_review_priority_score -> implementation -> author risk -> security -> flat score`

## Swift Validation

Input:

- Repository: `repository-06371990ec35d808`
- Status: `MERGED`
- Rows: 447

Summary:

| Metric | Value |
|---|---:|
| urgent_reviews | 39 |
| high_compute_reviews | 99 |
| avg priority score | 276.0 |
| max priority score | 805 |
| avg legacy flat score | 243.2 |
| max legacy flat score | 822 |

Lane distribution:

| Lane | Count |
|---|---:|
| suppressed_mechanical | 196 |
| watch | 70 |
| high_compute | 60 |
| medium_high_compute | 55 |
| urgent_compute | 39 |
| process_smell_watch | 15 |
| process_only_locus | 11 |
| security_relevant_routine | 1 |

Expected high rows stayed high:

| Review | Lane | Priority | Flat | Why |
|---|---|---:|---:|---|
| 940791 | urgent_compute | 805 | 822 | weak author, high churn/smell, S3 boundary |
| 890174 | urgent_compute | 805 | 803 | weak author, cooperative token/cache state |
| 682382 | urgent_compute | 790 | 717 | object versioning, thin author evidence, high churn |
| 836755 | urgent_compute | 776 | 743 | SigV4 streaming/input boundary, thin author evidence |
| 908969 | urgent_compute | 773 | 804 | cooperative token/shard state, weak author |
| 952462 | urgent_compute | 704 | 650 | checksum validation and high process smell |
| 834261 | urgent_compute | 703 | 610 | ring/data-state change and high process smell |
| 988826 | high_compute | 596 | 571 | pickle unmarshalling now correctly stays critical/runtime |

Expected noisy rows moved down:

| Review | Lane | Priority | Flat | Why |
|---|---|---:|---:|---|
| 930918 | process_smell_watch | 503 | 819 | observability/logging only |
| 939481 | process_smell_watch | 489 | 801 | observability/metrics only |
| 909882 | process_smell_watch | 466 | 754 | stats/metrics only |
| 972334 | suppressed_mechanical | 196 | 696 | test-only |
| 975591 | suppressed_mechanical | 163 | 574 | merge-only |

## Keystone Validation

Input:

- Repository: `repository-e8017b1c17f7693c`
- Status: `MERGED`
- Rows: 637

Summary:

| Metric | Value |
|---|---:|
| urgent_reviews | 24 |
| high_compute_reviews | 159 |
| avg priority score | 272.6 |
| max priority score | 769 |
| avg legacy flat score | 157.6 |
| max legacy flat score | 745 |

Lane distribution:

| Lane | Count |
|---|---:|
| watch | 165 |
| high_compute | 135 |
| medium_high_compute | 116 |
| suppressed_mechanical | 58 |
| urgent_compute | 24 |
| process_smell_watch | 1 |
| security_relevant_routine | 1 |

Known Keystone clusters behaved sensibly:

| Review | Lane | Priority | Flat | Notes |
|---|---|---:|---:|---|
| 860613 | urgent_compute | 758 | 745 | OAuth mTLS, thin author evidence, high churn/smell |
| 830739 | urgent_compute | 758 | 744 | OAuth client credentials, thin author evidence, high churn/smell |
| 967048 | urgent_compute | 715 | 455 | federated role cache, thin author evidence, high process smell |
| 966069 | urgent_compute | 636 | 472 | service-user auth, strong author but weak/missing reviewer evidence and smell |
| 966871 | high_compute | 567 | 535 | service-user auth backport, thin author evidence |
| 987062 | high_compute | 559 | 412 | app credential / EC2 boundary with smell |
| 983597 | high_compute | 518 | 346 | EC2 credential boundary |
| 990485 | high_compute | 502 | 466 | delegated-token boundary, some smell |
| 990490 | medium_high_compute | 408 | 442 | delegated-token boundary, calmer process |
| 990495 | medium_high_compute | 404 | 436 | delegated-token boundary, calmer process |
| 982913 | process_smell_watch | 450 | 394 | high process smell but not security-locus from current metadata |
| 838108 | suppressed_mechanical | 286 | 745 | docs/API reference only, now suppressed despite high flat score |

## Assessment

This is closer to the mission.

The biggest improvement is that the score now separates:

- runtime security-boundary changes with weak/thin human evidence
- security-boundary changes with calmer process evidence
- process-smelly non-security changes
- mechanical/test/docs/merge rows

The main remaining weakness is reviewer evidence. Keystone still has many `mixed_review` / `weak_or_missing_review` cases, so the ranking leans heavily on author evidence and process smell. That is not a new tree concept problem; it is a data coverage problem.

Next parameter tweak, if needed: reduce the `high_compute` width. Keystone still has 159 high-or-urgent rows out of 637, which may be too broad if the goal is very expensive analysis.
