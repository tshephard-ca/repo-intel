# Swift Older 200 Merged Reviews: Implementation-Risk Signals

Scope: same older 200 merged Swift Gerrit reviews as `swift-older200-merged-review-security-analysis.md`.

This pass ignores full conversation semantics and looks for review-native implementation weakness signals:

- author competence / unknown author history
- reviewer competence / weak approval survival
- reviewer confusion
- author struggle
- review churn
- high comment density
- many reviewers
- unresolved comments

## Signal Coverage

Across all 200 reviews:

| Signal | Count |
|---|---:|
| Unknown author competence | 77 |
| High author risk score | 78 |
| Reviewer risk score >= 20 | 39 |
| High friction | 27 |
| High rework | 38 |
| Patch sets >= 8 | 16 |
| Human reviewers >= 4 | 27 |
| High comment density per KLOC | 87 |
| Author reply/struggle count >= 5 | 24 |
| Reviewer concern count >= 5 | 29 |

Among the 39 high security-relevant reviews:

| Signal | Count |
|---|---:|
| High/unknown author risk | 10 |
| Reviewer risk score >= 20 | 3 |
| High friction | 11 |
| High rework | 16 |
| Patch sets >= 8 | 6 |
| Human reviewers >= 4 | 16 |
| High comment density per KLOC | 20 |
| Author reply/struggle count >= 5 | 13 |
| Reviewer concern count >= 5 | 15 |

Among the 118 low security-relevant reviews:

| Signal | Count |
|---|---:|
| High/unknown author risk | 58 |
| Reviewer risk score >= 20 | 32 |
| High friction | 3 |
| High rework | 7 |
| Patch sets >= 8 | 2 |
| Human reviewers >= 4 | 2 |
| High comment density per KLOC | 40 |
| Author reply/struggle count >= 5 | 0 |
| Reviewer concern count >= 5 | 0 |

## What Actually Helps

The strongest implementation-risk signals are not author/reviewer competence alone.

The useful signals are:

| Signal | Why it helps |
|---|---|
| Reviewer concern count >= 5 | Strongly separates hard reviews from low-risk reviews. |
| Author reply/struggle count >= 5 | Strong signal: appears in high/medium reviews, not low reviews. |
| High rework score | Good signal when paired with security relevance. |
| Human reviewers >= 4 | Good proxy for uncertainty/complexity. Rare in low-risk reviews. |
| High friction score | Good but can miss quiet dangerous reviews. |
| Patch sets >= 8 | Strong but sparse. |
| Comment density per KLOC | Useful but noisy; small changes inflate it. |

Weak by itself:

| Signal | Problem |
|---|---|
| Unknown/high author risk | Too common in low-risk rows. It is useful as an amplifier, not a selector. |
| Reviewer risk score | Also too common in low-risk rows and too sparse on high-risk rows. |
| Raw human comment count | Needs normalization by LOC and reviewer/author split. |

## Best Implementation-Risk Examples

| Change | Impl signal | Security | Risk | Why it stands out |
|---|---:|---:|---:|---|
| 930918 | 17 | 204 | 495 | 88 patch sets, 6 reviewers, 141 reviewer-concern messages, 16 author replies. |
| 682382 | 17 | 182 | 481 | 80 patch sets, object versioning, 84 reviewer concerns, 33 author replies. |
| 939481 | 17 | 158 | 452 | S3 metrics/labels, 49 patch sets, 67 reviewer concerns, 39 author replies. |
| 988826 | 16 | 156 | 417 | Pickle hardening plus reviewer concerns and follow-up coverage. |
| 987957 | 9 | 73 | 257 | Truncated aws-chunked input, 7 reviewers, high comment density. |
| 973672 | 12 | 46 | 277 | S3 object expiration, 4 reviewers, 5 concern messages, 8 author replies. |
| 956411 | 10 | 70 | 316 | Mixed response semantics, high friction/rework and many author replies. |

## Important Quiet Cases

These are security-relevant but do not look weak from process signals:

| Change | Security | Impl signal | Subject |
|---|---:|---:|---|
| 966068 | 73 | 2 | s3token: Pass service auth token to Keystone |
| 966067 | 54 | 2 | s3token: Pass service auth token to Keystone |
| 966064 | 54 | 2 | s3token: Pass service auth token to Keystone |
| 966063 | 54 | 2 | s3token: Pass service auth token to Keystone |
| 966062 | 37 | 0 | s3token: Pass service auth token to Keystone |
| 979938 | 18 | 2 | py314: Fix non-ascii header-name parsing |
| 990261 | 4 | 0 | s3api: Error on truncated aws-chunked input |

These prove implementation-risk signals cannot replace security relevance. They only identify when the implementation process looked strained.

## Similar Signals Worth Adding

These are still simple metadata signals, not semantic conversation classification:

- **Concern density per touched file**: concern messages divided by changed files.
- **Same-file concern recurrence**: multiple reviewer comments on the same file across patch sets.
- **Author response ratio**: author replies divided by reviewer concerns.
- **Reviewer spread after first concern**: new reviewers entering after concern/rework starts.
- **Patch-set churn after first human concern**: patch sets after first reviewer concern, not total patch sets.
- **Late file churn**: files changed after approval or after high concern density.
- **Weak approval coverage**: approval with few reviewers, low component history, or no reviewer history.
- **Concern-to-test ratio**: concerns answered only by tests versus code changes.
- **Review split-brain**: reviewers commenting on different files/components with little overlap.
- **Small-change high-friction flag**: high comment density on <=100 changed lines.

## Bottom Line

For the older 200 merged Swift reviews, the implementation-risk model should be:

```text
implementation_risk =
  reviewer_concern_count
  + author_reply_struggle
  + post-concern patch churn
  + reviewer spread
  + high comment density per KLOC
  + weak component/approval coverage
```

Author and reviewer competence should remain in the score, but they are not the highest implementation-risk selectors in this data. They are best used as multipliers once review confusion/churn is already present.
