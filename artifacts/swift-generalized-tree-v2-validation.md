# Swift validation of generalized review-risk tree v2

Validated against the current persisted Swift merged-review set on 2026-06-10.

Input:

- Repository: `repository-06371990ec35d808`
- API view: `/api/repointel-review-risk?repository_id=repository-06371990ec35d808&status=MERGED&limit=500`
- Rows: 447 merged Gerrit reviews
- Current flat score summary: 19 critical, 44 high, average score 243.2, max score 822

The classifier used the generic v2 tree from `keystone-generalized-tree-v2.md`. It did not branch on repository name or Swift-specific review numbers. It used generic mechanisms, author competence, reviewer evidence, churn/friction, and file shape.

## Result

The generalized tree transfers to Swift better than the flat weighted score.

It keeps these classes high:

- Auth/access/request-boundary changes
- S3 request parsing and input validation changes
- Checksum/data-integrity changes
- Pickle/serialization hardening
- Cache/token/state-freshness changes
- Object versioning/ring/shard consistency changes

It demotes these classes:

- Logging/metrics-only changes
- Test-only changes
- Merge-only rows
- CI/mechanical rows

That is the behavior we wanted. It is not just "security keyword high"; it separates security-locus work from process/mechanical noise.

## Classification Counts

| v2 priority | count |
|---|---:|
| suppressed_mechanical | 187 |
| watch | 92 |
| high_compute | 68 |
| urgent_compute | 49 |
| medium_high_compute | 34 |
| process_smell_watch | 11 |
| process_only_locus | 6 |

| v2 locus | count |
|---|---:|
| suppressed_mechanical | 187 |
| critical_locus | 129 |
| watch | 88 |
| important_locus | 26 |
| process_only_locus | 17 |

Author competence coverage is strong for Swift:

| author bucket | count |
|---|---:|
| strong_known | 364 |
| mixed_known | 34 |
| weak_known | 28 |
| thin_unknown | 15 |
| thin_mixed | 6 |

Reviewer evidence is still weaker:

| reviewer bucket | count |
|---|---:|
| weak_or_missing_review | 279 |
| strong_but_struggled | 154 |
| strong_clean_review | 14 |

## Rows That Stayed High

These are good validations of the tree:

| review | v2 priority | why it stays high |
|---|---|---|
| 940791 | urgent_compute | S3 helper boundary, weak known author, high churn/friction |
| 908969 | urgent_compute | cooperative token/state-freshness, weak known author, high churn |
| 890174 | urgent_compute | memcached cooperative token mechanism, weak known author |
| 836755 | urgent_compute | SigV4 streaming/input boundary, thin author evidence, high churn |
| 682382 | urgent_compute | object versioning/data state, thin author evidence |
| 949680 | urgent_compute | conditional write semantics, high churn |
| 944073 | urgent_compute | checksum upload validation/data integrity |
| 952462 | urgent_compute | checksum validation on delete flow |
| 987957 | urgent_compute | truncated aws-chunked input validation |
| 990318 | urgent_compute | server-side encryption/S3 boundary, thin-mixed author evidence |
| 834261 | urgent_compute | ring format/data-state mechanism, high churn |
| 988826 | urgent_compute | pickle unmarshalling/serialization hardening |

## Rows The Tree Correctly Demoted

These were over-promoted by the flat score:

| review | flat score | v2 priority | why demoted |
|---|---:|---|---|
| 930918 | 819 | process_smell_watch | proxy-logging transfer-byte counters |
| 939481 | 801 | process_smell_watch | labeled metrics |
| 909882 | 754 | process_smell_watch | native labeled metrics |
| 937884 | 722 | process_smell_watch | proxy-logging labels |
| 917711 | 701 | process_smell_watch | labeled metrics to proxy-logging |
| 972334 | 696 | suppressed_mechanical | test-only timestamp assertions, zero runtime files |
| 950371 | 612 | suppressed_mechanical | test cases only |
| 975591 | 574 | suppressed_mechanical | merge-only row |
| 946621 | 564 | suppressed_mechanical | tests-only cleanup |

This is the main evidence that conditional partitioning is better than only changing weights. The same high security score means different things depending on whether the change is runtime boundary logic, metrics/logging, tests, or a merge row.

## Lower Flat Scores That V2 Brings Back Up

These are useful cases where the flat score under-ranked likely security-locus work:

| review | flat score | v2 priority | why promoted |
|---|---:|---|---|
| 966062 | 406 | high_compute | s3token passes service auth token to Keystone |
| 956191 | 430 | high_compute | SigChecker refactor |
| 947246 | 416 | high_compute | SigChecker refactor |
| 990355 | 299 | high_compute | truncated aws-chunked input |
| 956195 | 321 | high_compute | crc64nvme checksum |
| 989591 | 265 | high_compute | oversized chunked S3 XML bodies |
| 990805 | 272 | high_compute | pickle unmarshalling |
| 990767 | 272 | high_compute | pickle unmarshalling |
| 966263 | 379 | urgent_compute | secret caching default, thin author evidence |

This is useful because a review can be worth compute even when comment smell/churn is not huge.

## What Still Needs Fixing

The validation exposed four product gaps:

1. We should persist explicit `security_locus` metadata instead of re-deriving it from subject text at scoring time.
2. We need explicit `change_shape` metadata: `runtime_file_count`, `test_only`, `merge_only`, `ci_only`, `observability_only`.
3. Reviewer evidence is still too sparse. Current-review approval survival is often zero, even when reviewer history exists.
4. Observability/logging changes need their own lane. They should not usually rank with auth/input/data-boundary changes unless they expose sensitive data or change enforcement behavior.

## Verdict

Validated, with caveats.

The generalized tree is better than the flat score and does not need Swift-specific hardcoding. The next implementation step should be to add explicit normalizer output for `security_locus` and `change_shape`, then update the Review Risk page to rank by the v2 priority lanes instead of one flat blended score.
