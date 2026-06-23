# Swift Last 100 Gerrit Reviews: Security Candidate Comparison

Generated from the live Review Risk endpoint on 2026-06-08 using:

- repository: `repository-06371990ec35d808`
- project: `openstack/swift`
- source: last 100 Gerrit change raw records by updated time
- status filter: `ALL`
- date field: `updated`
- since: `2026-05-30T19:45:23`

## Summary

Manual review buckets:

| Manual bucket | Count |
|---|---:|
| High security-analysis candidate | 26 |
| Medium candidate | 49 |
| Low candidate | 25 |

System security-score buckets:

| System bucket | Count |
|---|---:|
| High | 26 |
| Medium | 23 |
| Low | 51 |

Alignment:

| Manual bucket | System high | System medium | System low |
|---|---:|---:|---:|
| High | 15 | 6 | 5 |
| Medium | 10 | 14 | 25 |
| Low | 1 | 3 | 21 |

Headline read:

- The system surfaces `21/26` manually high candidates if high+medium are treated as actionable.
- It strongly ranks `15/26` manually high candidates as high.
- It has `1/25` low candidate ranked high.
- Manual high reviews averaged `security_score=98.2`.
- Manual medium reviews averaged `security_score=55.2`.
- Manual low reviews averaged `security_score=15.5`.

## Best Current Security Candidates

| Change | Manual | Security | Total risk | Why it is interesting |
|---|---|---:|---:|---|
| 991516 | high | 240 | 434 | S3 API checksum persistence; integrity and request-path handling. |
| 990318 | high | 240 | 460 | S3 API server-side encryption behavior. |
| 927327 | high | 192 | 471 | EC timestamp collision handling. |
| 991167 | high | 162 | 326 | Invalid UTF-8 request params on S3 list_objects. |
| 990355 | high | 156 | 301 | Truncated aws-chunked S3 input. |
| 990262 | high | 156 | 250 | Same truncated aws-chunked input family. |
| 989591 | high | 140 | 224 | Oversized chunked S3 XML body rejection. |
| 990767 | high | 121 | 325 | Pickle unmarshalling hardening. |
| 989469 | high | 106 | 321 | Direct quarantining of directories. |
| 499260 | high | 81 | 380 | TLO middleware; request/API surface. |

These line up well with what should be reviewed first.

## High Candidates The System Still Underrates

| Change | Security | Total risk | Current bucket | What is missing |
|---|---:|---:|---|---|
| 989590 | 66 | 131 | medium | SLO manifest size/input parsing should score higher. |
| 984562 | 61 | 308 | medium | Hash-location mismatch quarantine should score higher as integrity risk. |
| 991519 | 59 | 275 | medium | Account DB truncation/quarantine should score higher. |
| 989592 | 56 | 178 | medium | Object POST metadata/timestamp validation should score higher. |
| 989593 | 52 | 163 | medium | Container PUT storage-policy validation should score higher. |
| 991513 | 51 | 161 | medium | PublicAccessBlock coverage is security-adjacent but test-only. |
| 991520 | 32 | 187 | low | Container DB truncation/quarantine is underweighted. |
| 991709 | 32 | 101 | low | Auditor quarantine regression tests are underweighted. |
| 989601 | 18 | 155 | low | Unicode successor / request-boundary validation is underweighted. |
| 991230 | 9 | 128 | low | Timestamp collision tests are underweighted. |
| 991231 | 9 | 119 | low | Timestamp collision tests are underweighted. |

The main gap is not ingestion anymore. The missing data was fixed. The current gap is scoring vocabulary and weighting for:

- quarantine
- truncation
- timestamp collision
- hash-location mismatch
- Unicode boundary validation
- SLO manifest request-body limits

## False Positives

| Change | Manual | Security | Total risk | Why it over-ranked |
|---|---|---:|---:|---|
| 990396 | low | 96 | 178 | Test-only encryption metadata terms over-triggered. |
| 990352 | low | 46 | 229 | CI dependency wording plus process risk. |
| 991446 | low | 36 | 121 | Timestamp/version-id terms but weak security case. |
| 990515 | low | 36 | 112 | Timestamp/version-id terms but weak security case. |

Only one low candidate was promoted to high, which is acceptable for this early scoring model.

## Notes On Total Risk

The UI sorts by total `risk_score`, not pure `security_score`.

That means medium-security but messy reviews can rank very high when they have:

- weak or unknown author competence
- high review friction
- many patch sets
- unresolved comments
- stale/open review state

That is intentional for Review Risk. For pure security triage, use `security_score`. For "which review should I worry about being mishandled", use `risk_score`.

## Current Assessment

The system is now useful for finding security-analysis candidates in the last 100 Swift Gerrit reviews.

It is no longer missing the obvious S3/checksum/chunked/pickle/security-sensitive-file cases after the raw metadata backfill. The remaining problem is tuning: several storage-integrity and boundary-validation phrases still score too low, especially when they appear in small focused reviews with little review friction.
