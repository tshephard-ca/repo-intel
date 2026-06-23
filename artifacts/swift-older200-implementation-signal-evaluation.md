# Swift Older 200: Proposed Implementation Signal Evaluation

This evaluates the proposed implementation-risk signals against the same older 200 merged Swift Gerrit reviews.

Important caveat: this uses manual security/process buckets as proxy labels. We do not have ground-truth "implementation was actually bad" labels.

## Signal Performance

| Signal | Hits | High hits | Medium hits | Low hits | High rate | Low rate | Lift high/low | Precision high+medium |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Concern density per touched file >= 1 | 69 | 21 | 28 | 20 | 0.538 | 0.169 | 3.18 | 0.71 |
| Repeated concerns on same file | 47 | 18 | 23 | 6 | 0.462 | 0.051 | 9.08 | 0.872 |
| Author response ratio >= 0.25 with >=3 concerns | 31 | 13 | 15 | 3 | 0.333 | 0.025 | 13.11 | 0.903 |
| Reviewer spread after first concern >= 3 | 21 | 12 | 8 | 1 | 0.308 | 0.008 | 36.31 | 0.952 |
| Patch sets after first concern >= 3 | 27 | 15 | 10 | 2 | 0.385 | 0.017 | 22.69 | 0.926 |
| Small change high friction | 23 | 4 | 10 | 9 | 0.103 | 0.076 | 1.34 | 0.609 |

## Composite

Simple composite = one point for each proposed signal that fires.

| Bucket | Avg proposed impl score |
|---|---:|
| High security-relevant | 2.13 |
| Medium security-relevant | 2.19 |
| Low security-relevant | 0.35 |

Rows with composite >= 3:

| Bucket | Count |
|---|---:|
| High | 20 |
| Medium | 21 |
| Low | 6 |

## What This Means

The proposed signals help, especially when combined. They are not vulnerability indicators by themselves; they are implementation weakness indicators.

Best individual indicators:

- author response ratio with several concerns
- reviewer spread after first concern
- patch-set churn after first concern
- repeated concerns on the same file

Noisy but still useful:

- concern density per touched file
- small-change high-friction

The signals are strongest for finding reviews that looked hard to get right. They do not catch quiet security-relevant patches, such as s3token/token-flow changes with little discussion.

## Top Implementation-Risk Rows By Proposed Composite

| Change | Score | Manual | Security | Risk | Subject |
|---|---:|---|---:|---:|---|
| 984723 | 6 | low | 30 | 156 | timestamps: make 'raw' a read-only property |
| 682382 | 5 | high | 182 | 481 | New Object Versioning mode |
| 939481 | 5 | high | 158 | 452 | Add labeled metrics to s3api |
| 988826 | 5 | high | 156 | 417 | Harden pickle unmarshalling |
| 975552 | 5 | medium | 81 | 322 | relinker: Prefix log messages with invoked action |
| 968740 | 5 | medium | 62 | 290 | timestamps: add NormalTimestamp for ShardRanges |
| 976288 | 5 | medium | 45 | 286 | tests: Stop using normalize_timestamp |
| 987957 | 5 | high | 73 | 257 | s3api: Error on truncated aws-chunked input |
| 985092 | 5 | high | 33 | 242 | timestamps: check offset is an integer during construction |
| 968236 | 5 | medium | 21 | 237 | Add a Timestamp.zero() method |
| 988093 | 5 | medium | 31 | 217 | s3api: Add functional test for aws-chunked truncation bug |
| 973272 | 5 | medium | 2 | 190 | s3api: do not set x-timestamp header |
| 930918 | 4 | high | 204 | 495 | proxy-logging: Add real-time transfer bytes counters |
| 940791 | 4 | high | 158 | 450 | Provide some s3 helper methods for other middlewares to use. |
| 937884 | 4 | high | 148 | 429 | proxy-logging: Add 'api' labels |

## Quiet Security-Relevant Rows These Signals Miss

| Change | Score | Security | Risk | Subject |
|---|---:|---:|---:|---|
| 966068 | 1 | 73 | 215 | s3token: Pass service auth token to Keystone |
| 966067 | 0 | 54 | 188 | s3token: Pass service auth token to Keystone |
| 966064 | 0 | 54 | 188 | s3token: Pass service auth token to Keystone |
| 966063 | 0 | 54 | 190 | s3token: Pass service auth token to Keystone |
| 972812 | 1 | 49 | 251 | AUTHORS/CHANGELOG for 2.37.0 |
| 966062 | 0 | 37 | 169 | s3token: Pass service auth token to Keystone |
| 988949 | 0 | 24 | 120 | test_sharder.py: pass timestamp strings to put_object |
| 951352 | 0 | 24 | 203 | s3token: Enable secret caching by default |
| 979938 | 0 | 18 | 117 | py314: Fix non-ascii header-name parsing |
| 966263 | 0 | 18 | 191 | s3token: Enable secret caching by default |
| 966262 | 0 | 18 | 171 | s3token: Enable secret caching by default |
| 989336 | 0 | 8 | 116 | Fix dsvm functional tests with keystonemiddleware 13.0.0 |
