# Swift Decision Tree Validation

Generated: 2026-06-10

Scope: openstack/swift merged Gerrit reviews in the local Repointel database.

Swift repository: `repository-06371990ec35d808`

Sample:

- 1,086 Swift Gerrit changes in DB.
- 447 merged Swift Gerrit changes.
- Validated against current top 500 merged review-risk rows.

Goal: apply the Keystone candidate decision-tree idea to Swift without tuning it around Swift first, then identify what general rules need to change.

## Result

The tree idea validates, but the Keystone security-locus split is too identity/auth-specific.

For Swift, the important locus is often not auth/token/credential. It is data-plane correctness:

```text
S3 request parsing, signatures, checksums, timestamps, object versioning,
ring placement, shard ranges, broker state, pickle/unmarshal, conditional writes,
object/container/account server behavior, EC/reconstructor behavior.
```

So the tree should keep the same structure, but the first split must be broader:

```text
security / vulnerability locus =
  auth boundary
  OR parser/input boundary
  OR data integrity boundary
  OR storage consistency boundary
  OR crypto/serialization boundary
  OR dependency/workflow boundary
```

That is generic enough to use outside Swift.

## Current Flat Score On Swift

Current review-risk summary:

| Metric | Value |
|---|---:|
| merged reviews scored | 447 |
| average risk score | 243.2 |
| max risk score | 822 |
| critical reviews | 19 |
| high reviews | 44 |

Top Swift rows are much better than Keystone. They are mostly real data-plane/S3/storage changes, not formatter/tooling noise.

Current top examples:

| Change | Score | Subject | Initial Read |
|---:|---:|---|---|
| 940791 | 822 | Provide some s3 helper methods for other middlewares | plausible high priority, middleware/S3 surface, huge churn |
| 930918 | 819 | proxy-logging real-time transfer bytes counters | likely over-ranked unless privacy/semantic impact |
| 908969 | 804 | cooperative tokens for shard range updates | high priority, concurrency/storage consistency |
| 890174 | 803 | memcached cooperative token mechanism | high priority, concurrency/cache/storage consistency |
| 939481 | 801 | labeled metrics to s3api | likely over-ranked unless privacy/semantic impact |
| 836755 | 743 | SigV4 streaming | strong high priority |
| 955225 | 738 | proxy-logging access_user_id | maybe high due privacy/access identity in logs |
| 682382 | 717 | Object Versioning mode | strong high priority |
| 972334 | 696 | tests: X-Timestamp headers valid | high signal but should not outrank code changes blindly |
| 988826 | 571 | Harden pickle unmarshalling | strong high priority despite lower flat rank |

## Partition Counts

Applying the Keystone tree literally:

| Keystone-tree partition | Count |
|---|---:|
| high locus / urgent compute | 31 |
| high locus / high-or-medium | 7 |
| medium locus / high compute | 27 |
| medium locus / medium-high | 6 |
| medium locus / medium-or-low | 66 |
| low locus / process smell watch | 84 |
| low locus / low priority | 226 |

Then adding a generic storage/data-integrity locus:

| Storage-aware partition | Count |
|---|---:|
| high locus / urgent compute | 43 |
| high locus / high-or-medium | 11 |
| medium locus / high compute | 37 |
| medium locus / medium-high | 12 |
| medium locus / medium-or-low | 71 |
| low locus / process smell watch | 48 |
| low locus / low priority | 225 |

Interpretation: the raw Keystone tree leaves too many Swift storage/data-plane reviews in `low/process_smell_watch`. Adding a generic data-integrity/storage locus moves many of them into the right branch. That is good.

But it also over-promotes observability/logging/metrics changes. That needs its own branch.

## What Validates Well

### SigV4 Streaming: `836755`

This should be urgent compute.

Signals:

- high S3 request/signature parsing locus
- author confidence thin: only 1 authored review in data
- 80 patch sets
- 325 human messages
- 5 unresolved comments
- review messages mention broken S3-compatible tests, AWS behavior, MinIO behavior, and signature handling

This is exactly the kind of change the system should select.

### Pickle Hardening: `988826`

This should be urgent or high compute.

Signals:

- serialization boundary
- explicit unsafe pickle/unmarshal surface
- review comments include proof-like arbitrary-code-execution discussion
- still using pickle, follow-up needed
- multiple expert reviewers

Flat score ranks it around the lower part of the top 50. Tree logic should lift it.

### Truncated AWS Chunked Input: `987957`

This should be urgent compute.

Signals:

- S3 parser/input boundary
- truncated streaming input
- strong implementation score
- unresolved comments
- multiple specialist reviewers

This is a better vuln-locus candidate than many metrics/logging rows above it.

### Checksums And Conditional Writes: `944073`, `952462`, `946141`, `949680`

These should be high priority.

Signals:

- checksum validation
- BadDigest behavior
- conditional writes
- S3/object data integrity
- direct request semantics

These are not auth bugs, but they are vulnerability-relevant storage/data-integrity loci.

### Object Versioning: `682382`

This should be high priority.

Signals:

- object versioning semantics
- 80 patch sets
- 272 human messages
- 5 negative votes
- weak author confidence

This validates the process-smell branch.

### Cooperative Tokens / Shard Updates: `908969`, `890174`

These should be high priority, but not because "token" means auth token.

Signals:

- concurrency/cache mechanism
- shard range update coordination
- high churn
- unresolved comments
- weak known author competence

This means the tree needs a concurrency/storage-consistency locus, not only auth-token matching.

## What The Tree Still Gets Wrong

### Metrics / Logging Rows Get Over-Promoted

Examples:

- `930918` proxy-logging real-time transfer bytes counters
- `909882` native labeled metrics
- `917711` labeled metrics to proxy-logging
- `939481` labeled metrics to s3api
- `944506` object-server labeled timing metrics
- `948548` object-server timing stats

These have huge churn and comment smell, so they are real process-smell rows. But they are often observability surface, not direct vuln-locus surface.

They should usually be:

```text
process_smell_watch
```

not:

```text
urgent_compute
```

Exception: logging/metrics should escalate if it includes privacy, identity, path/account/container/object exposure, credential fields, request bodies, auth headers, access IDs, or changes request behavior.

`955225` is a good example of a row that may still deserve higher priority because it creates `access_user_id` logging.

### Pure Test Rows Need A Separate Branch

Example:

- `972334` tests: assert X-Timestamp headers are valid

This may point at an important timestamp correctness issue, but a `tests:` subject should not automatically compete with direct implementation changes. It should be ranked as:

```text
evidence_of_locus
```

unless the same patch changes runtime code.

### Strong Reviewer Presence Is Not Enough To Suppress

Swift has many strong reviewers: Tim Burke, Alistair Coles, Clay Gerrard, Matthew Oliver, etc.

But in rows like SigV4 streaming and object versioning, strong reviewers did not settle the change quickly. High-quality reviewers plus 80 patch sets and hundreds of messages means the problem was hard. That should increase priority, not suppress it.

So reviewer logic should be:

```text
strong reviewers + low churn + low concern => suppress
strong reviewers + high churn + repeated concern => raise priority
```

## Swift-Specific Observations That Should Generalize

### Known Weak Author Is Different From Unknown Author

In Keystone, the risky author signal was often thin/unknown author evidence.

In Swift, several top rows have high confidence but low competence score:

- Yan Xiao: competence score 17, confidence 100%
- Jianjian Huo: competence score 22, confidence 100%
- ASHWIN A NAIR: competence score 27, confidence 100%

That validates the separate branches:

```text
weak_known
unknown_or_thin
```

They should not be treated the same.

Known weak + high churn + critical locus should be stronger than unknown + clean review.

### Data Integrity Is A Security Locus

Swift confirms that "security relevance" cannot mean only auth/credential/policy.

These should be first-class vulnerability loci:

- checksum verification
- timestamp validity
- object versioning
- object expiration
- conditional writes
- chunked input parsing
- pickle/unmarshal
- ring placement
- shard range updates
- broker state
- EC reconstruction / reconstructor behavior

The implementation should detect these through metadata categories, not hardcoded Swift names.

Suggested generic metadata categories:

```text
security_locus.auth_boundary
security_locus.parser_input_boundary
security_locus.data_integrity_boundary
security_locus.storage_consistency_boundary
security_locus.serialization_boundary
security_locus.privacy_logging_boundary
security_locus.concurrency_cache_boundary
security_locus.observability_only
```

## Revised Tree After Swift Validation

The tree should become:

```text
1. classify locus:
   high_auth_or_boundary
   high_data_integrity
   medium_consistency_or_availability
   observability_only
   mechanical_or_docs
   low

2. classify author:
   strong
   mixed_known
   weak_known
   mixed_thin
   unknown_or_thin

3. classify reviewer/review:
   strong_clean_review
   strong_but_struggled
   weak_or_missing_review
   contradicted_review

4. classify process smell:
   clean
   smelly
   highly_smelly

5. classify family:
   root
   riskiest_backport
   duplicate_backport

6. emit:
   urgent_compute
   high_compute
   important_security_review
   process_smell_watch
   suppressed_observability
   suppressed_mechanical
   low_priority
```

## Suggested Priority Rules

Keep Keystone rules, but add these Swift-validated rules:

```text
if locus is high_data_integrity and process is highly_smelly:
  urgent_compute

if locus is high_data_integrity and author is weak_known:
  urgent_compute

if locus is parser_input_boundary and implementation_score >= 80:
  urgent_compute

if locus is serialization_boundary:
  urgent_compute

if locus is observability_only and no privacy/user/path/credential exposure:
  process_smell_watch, not urgent_compute

if subject starts with tests: and no runtime code change:
  evidence_of_locus, not urgent_compute

if strong reviewers are present but patch_sets >= 20 or human_messages >= 100:
  reviewer_branch = strong_but_struggled
```

## Expected Swift Re-Ranking

Rows that should stay high or rise:

| Change | Why |
|---:|---|
| 836755 | SigV4 streaming, broken AWS/MinIO tests, weak author confidence, huge churn |
| 988826 | pickle hardening, serialization boundary, arbitrary-code-execution discussion |
| 987957 | truncated aws-chunked input, parser boundary |
| 682382 | object versioning, 80 patch sets, negative votes |
| 944073 | checksum validation on upload |
| 952462 | checksum verification on DeleteObjects |
| 946141 | crc64nvme checksum support |
| 949680 | conditional write semantics |
| 908969 | shard range update coordination / concurrency |
| 890174 | cooperative token/cache mechanism |
| 834261 | ring v2 format, 65 unresolved comments, storage placement critical |
| 938631 | unicode header handling in bufferedhttp |
| 887908 | cgi.parse_header removal / parser behavior |
| 861271 | tempauth fernet tokens |

Rows that should move down or be relabeled:

| Change | Why |
|---:|---|
| 930918 | metrics/logging churn; likely process-smell watch, not urgent vuln compute |
| 909882 | native metrics API; process-smell watch unless privacy/security fields exposed |
| 917711 | labeled metrics to proxy-logging |
| 939481 | labeled metrics to s3api |
| 944506 | object-server timing metrics |
| 948548 | object-server timing stats |
| 972334 | test-only timestamp validation signal; should point to related runtime code |
| 975591 | merge branch row; should be family/merge suppressed |

## Validation Conclusion

The decision-tree approach works better than flat weighting for Swift too, but the first partition must be domain-generic.

Keystone taught:

```text
auth/security boundary + competence/process smell
```

Swift adds:

```text
data integrity / parser / storage consistency boundary + competence/process smell
```

The main fix before coding this into the UX is to create a generic `security_locus` normalizer with multiple locus types, then run the tree on those normalized locus categories instead of raw keyword/file scores.

