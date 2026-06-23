# Keystone Review Risk Scoring Analysis

Generated: 2026-06-10

Scope: Keystone merged Gerrit reviews in the local Repointel database.

Goal: evaluate whether the current review-risk score is doing the intended job: not finding every vulnerability, and not acting like a generic security scanner, but ranking reviews where deeper analysis is worth compute because the change is security-relevant and the author/reviewer/process signals suggest higher implementation risk.

## Bottom Line

The current score is useful, but it is not yet succeeding at the core concept.

It still behaves too much like:

```text
security keyword/file score + generic churn
```

and not enough like:

```text
security-relevant locus gated by author competence,
reviewer competence, reviewer coverage, review confusion, and unresolved implementation concern
```

The strongest evidence is the current top-50 sample:

- 16 of 50 hit the security-score cap.
- 16 of 50 have high security score but almost no implementation concern.
- 11 of 50 look mechanical, documentation, formatting, migration, or tooling-related from the subject alone.
- 24 of 50 have no author line-survival data.
- 14 of 50 have low author competence confidence below 35%.
- 16 of 50 have strong implementation-risk score at or above 100.
- Only 1 of 50 has a negative vote captured.
- Only a small number have current approval-survival rows, so reviewer scoring is mostly fallback or missing.

That means the current model often ranks "security-looking" work above "competence/process-smelly" work. For this product, that is the wrong bias.

## What The Top 50 Shows

Current top-50 merged Keystone reviews by the existing score:

| Rank | Change | Score | Sec | Author Risk | Author Conf | Impl | Churn/Review Signal | Subject |
|---:|---:|---:|---:|---:|---:|---:|---|---|
| 1 | 860613 | 745 | 320 | 86 | 17% | 200 | 11 patch sets, 47 human msgs, 8 unresolved | OAuth 2.0 Mutual-TLS Support |
| 2 | 838108 | 745 | 320 | 84 | 8% | 194 | 4 patch sets, 52 human msgs, 5 unresolved | Add doc of OAuth2.0 Client Credentials Grant Flow |
| 3 | 830739 | 744 | 320 | 85 | 8% | 200 | 13 patch sets, 88 human msgs, 4 unresolved | OAuth2.0 Client Credentials Grant Flow Support |
| 4 | 739966 | 676 | 260 | 86 | 25% | 200 | 24 patch sets, 112 human msgs | Keystone to honor the domain attribute mapping rules |
| 5 | 966871 | 535 | 320 | 81 | 17% | 58 | backport conflict discussion | Add service user authentication to ec2 and s3 endpoints |
| 6 | 924132 | 507 | 132 | 84 | 25% | 171 | 10 patch sets, 46 human msgs | Implement the Domain Manager Persona for Keystone |
| 7 | 754404 | 494 | 215 | 83 | 8% | 84 | 4 patch sets, 11 human msgs | Accept STS and IAM services from Ceph Obj Gateway |
| 8 | 924522 | 481 | 320 | 44 | 100% | 26 | mechanical formatting | Blackify the keystone code base |
| 9 | 966069 | 472 | 320 | 44 | 100% | 38 | 2 unresolved | Add service user authentication to ec2 and s3 endpoints |
| 10 | 828595 | 469 | 148 | 50 | 100% | 153 | 15 patch sets, 20 human msgs | Force algo specific maximum length |
| 11 | 990485 | 466 | 320 | 44 | 100% | 6 | large security boundary, low process smell | Enforce delegation project boundary for delegated tokens |
| 12 | 967048 | 455 | 162 | 84 | 25% | 103 | 18 patch sets, cache/revocation uncertainty | Fix role assignment cache for federated users |
| 13 | 931959 | 447 | 320 | 44 | 100% | 0 | mechanical | Ruff the code |
| 14 | 924546 | 444 | 320 | 44 | 100% | 0 | mechanical | Re-join the strings after re-formatting |
| 15 | 990490 | 442 | 320 | 44 | 100% | 1 | backport of 990485 | Enforce delegation project boundary for delegated tokens |
| 16 | 885463 | 442 | 111 | 82 | 17% | 124 | 5 unresolved | sql: invalid unique constraint on external_id |
| 17 | 990495 | 436 | 320 | 44 | 100% | 0 | backport of 990485 | Enforce delegation project boundary for delegated tokens |
| 18 | 966073 | 424 | 319 | 44 | 100% | 1 | low process smell | Add service user authentication to ec2 and s3 endpoints |
| 19 | 924010 | 421 | 320 | 44 | 100% | 0 | mechanical | Enable pyupgrade |
| 20 | 925008 | 419 | 320 | 44 | 100% | 0 | mechanical | Replace deprecated in py312 datetime usages |
| 21 | 929686 | 416 | 86 | 76 | 75% | 142 | 18 patch sets, endpoint validation | Add JSON Schema to endpoint groups |
| 22 | 950157 | 414 | 320 | 44 | 100% | 0 | mechanical | Update pre-commit hook versions |
| 23 | 925031 | 414 | 320 | 44 | 100% | 0 | mechanical | Enable hacking check in pre-commit |
| 24 | 925517 | 413 | 125 | 76 | 75% | 119 | 20 patch sets | Add JSON Schema to application credentials |
| 25 | 987062 | 412 | 205 | 58 | 100% | 82 | small backport, weak mixed author history | Block restricted app creds via /credentials |
| 26 | 984715 | 411 | 320 | 44 | 100% | 0 | backport, low implementation signal | Add service user authentication to ec2 and s3 endpoints |
| 27 | 988237 | 409 | 289 | 38 | 100% | 31 | good reviewer coverage | Enforce app cred project boundary on EC2 credential paths |
| 28 | 932423 | 406 | 105 | 82 | 17% | 115 | 10 patch sets | Support emitting partial hash of invalid password |
| 29 | 902730 | 395 | 135 | 42 | 100% | 100 | RBAC phase work | Consistent and Secure RBAC Phase 1 |
| 30 | 982913 | 394 | 0 | 84 | 25% | 194 | 13 patch sets, 43 human msgs, negative vote | Fix LDAP pagination beyond page_size |
| 31 | 861232 | 392 | 201 | 50 | 100% | 44 | token expiration | Limit token expiration to app credential expiration |
| 32 | 863420 | 391 | 49 | 84 | 33% | 128 | 7 patch sets, 9 unresolved | Add default service role support |
| 33 | 966071 | 390 | 319 | 44 | 100% | 0 | duplicate backport-ish | Add service user authentication |
| 34 | 966070 | 390 | 319 | 44 | 100% | 0 | duplicate backport-ish | Add service user authentication |
| 35 | 927523 | 390 | 105 | 76 | 75% | 131 | 8 patch sets | Add JSON Schema to services |
| 36 | 862906 | 377 | 203 | 50 | 100% | 69 | related app credential expiration | Limit token expiration |
| 37 | 924085 | 373 | 279 | 44 | 100% | 0 | mechanical | Enable mypy |
| 38 | 930610 | 372 | 100 | 76 | 75% | 93 | 15 patch sets | Add JSON schema to service provider |
| 39 | 824781 | 369 | 278 | 36 | 100% | 0 | migration squash | sql: Squash queens migrations |
| 40 | 860928 | 368 | 195 | 86 | 17% | 0 | docs | Add doc of OAuth 2.0 Mutual-TLS Authenticate |
| 41 | 985804 | 363 | 283 | 50 | 100% | 0 | related backport | Enforce app cred project boundary |
| 42 | 890661 | 360 | 139 | 73 | 58% | 71 | bcrypt length trimming | Force algo specific maximum length |
| 43 | 965768 | 359 | 118 | 38 | 100% | 84 | branch metadata update | Update .gitreview for unmaintained/2024.1 |
| 44 | 953723 | 356 | 76 | 81 | 30% | 92 | trust schema | trust schema: do not require uuid user_id |
| 45 | 987476 | 346 | 289 | 38 | 100% | 0 | related backport | Enforce app cred project boundary |
| 46 | 986389 | 346 | 289 | 38 | 100% | 0 | related backport | Enforce app cred project boundary |
| 47 | 983597 | 346 | 181 | 44 | 100% | 44 | tiny auth policy patch | Prevent unauthorized EC2 credential creation/deletion |
| 48 | 914759 | 346 | 71 | 42 | 100% | 136 | domain admin roles | Allow domain admin to view roles |
| 49 | 822767 | 344 | 111 | 82 | 50% | 57 | stdlib token_bytes | Replace os.urandom with secrets.token_bytes |
| 50 | 966583 | 339 | 198 | 44 | 100% | 3 | token validation, strong author | Invalidate token of user disabled in readonly backend |

## Where The Current Score Works

It does surface some useful compute targets.

`967048` is a good hit. The author has weak local competence evidence: only 3 authored Keystone reviews in this data, no useful line-survival signal, and high historical review friction. The review itself had 18 patch sets and comments around whether token cache invalidation was sufficient. This is exactly the kind of review where deeper analysis is worth compute.

`982913` is also a good process-risk hit even though it has no security score. The review had 13 patch sets, 43 human messages, a negative vote, and very direct reviewer concerns: not convinced it works, conversion breakage, missing tests, and complexity. If this were on a stronger security boundary, it should be near the top.

`860613`, `830739`, and `739966` look like valid high-compute candidates. They combine security-sensitive surface, low author-confidence, many patch sets, many human messages, unresolved comments, and high implementation concern.

## Where The Current Score Fails

### 1. Security Score Dominates Too Much

Rows like `924522`, `931959`, `924546`, `924010`, `925008`, `950157`, `925031`, and `924085` rank high because they touch or mention security-relevant code and keywords. But their subjects are formatter/tooling/pre-commit/mypy/pyupgrade/mechanical work.

These are not all useless, but they are not the highest-value use of expensive deeper analysis. The current score lets security-looking metadata swamp competence and review-process signals.

The product goal is not "find every security-looking diff." It is "find reviews where security relevance plus human/process weakness suggests a higher chance of implementation mistakes."

### 2. Competent Authors Are Not Suppressing Noise Enough

Artem-owned rows are common in the top 50 even when author competence is strong:

- 120 authored reviews
- 89 merged
- exact Git identity match
- sampled line survival around 95.8%

Examples: `990485`, `990490`, `990495`, `966069`, `966073`, several mechanical tooling rows.

Some of those are security-important, but the score should say:

```text
Important review, lower competence concern.
```

Instead, they still rank near the top because security score is additive and capped late.

### 3. Unknown Author Is Treated Too Much Like Bad Author

Low author-confidence rows receive large author-risk points. That is useful only when paired with real process smell or high-security boundary. It is noisy for docs and mechanical work.

Unknown should be a multiplier on deeper-review priority only when other evidence says the change matters. It should not independently push low-value rows to the top.

### 4. Reviewer Coverage Is Too Weak

For many merged rows, positive votes and current approval-survival rows are sparse or missing. That makes reviewer competence weak as a ranking feature.

Current sample symptoms:

- Many top-50 rows have `positive_votes = 0` despite being merged.
- Most rows have no current approval-survival row.
- Reviewer history often falls back to a tiny sample.
- Missing reviewer evidence is often neutral instead of risky.

For this concept, reviewer competence is central. A security-sensitive change by a weak or unknown author should drop in priority if it had strong specialist review, and rise if review coverage was weak, generic, or contradicted.

### 5. Backports And Duplicate Patch Families Consume Too Many Slots

`990485`, `990490`, and `990495` are the same delegated token project-boundary patch across branches.

`966069`, `966073`, `966871`, `984715`, `966070`, and `966071` are the same service-user auth family across branches.

This is useful as a cluster, but bad as a top-50 list. Compute planning should group these into:

```text
root/master change + riskiest backport
```

The current top-50 spends too many slots on duplicated families.

### 6. Comment Smell Works, But It Needs More Authority

The implementation-risk signal is useful. It correctly highlights:

- `967048`: uncertainty over cache invalidation and revocation.
- `982913`: reviewer pushback, broken conversion concern, missing tests.
- OAuth mTLS work: many review concerns and unresolved comments.

But implementation risk is still not strong enough to overcome security-score dominance in the right way. `982913` ranks below many security-looking low-smell rows even though it has much stronger evidence of weak implementation process.

## Competence-First Interpretation Of The Earlier Keystone Cluster

The earlier cluster should be read differently when competence is centered.

| Cluster | Current Score Behavior | Competence-Centered Read |
|---|---|---|
| EC2/S3 service-user auth | High because security keywords and files | `966871` is worth review because author evidence is thin and the backport had conflict/missing-patch discussion. Artem-owned root/backports look less competence-risky. |
| Delegated token project boundary | High because security boundary | Security-important, but Artem author competence and Grzegorz review lower competence concern. Needs review because blast radius is high, not because process smells. |
| App credential / EC2 boundary | Mid-high | `987062` is worth checking because author/reviewer evidence is weaker. `983655` and `988237` have better author/reviewer signals. |
| Federated role cache `967048` | High but not top | Should be near the top. Low author evidence, 18 patch sets, cache/token revocation complexity, and reviewer uncertainty. |
| LDAP pagination `982913` | Mid-high despite zero security | Excellent process-smell example. If the touched subsystem were more security-sensitive, this should be top-tier. |
| Disabled user token invalidation `966583` | Mid | Strong author lowers concern. Worth light review only because token validation is sensitive. |

## What The Ranking Should Optimize

The ranking should be two-stage, not a flat additive score.

Stage 1: security relevance / locus eligibility.

This answers:

```text
Is this change near a vulnerability-relevant boundary?
```

Inputs:

- auth, token, credential, trust, federation, policy, cryptography, parsing, secrets, deserialization, dependency, workflow, exposed API paths
- files/components historically associated with security-sensitive work
- explicit security identifiers or bugs
- branch/backport/release propagation context

Stage 2: competence/process prioritization.

This answers:

```text
Given that the change is relevant, is this one worth spending deeper-analysis compute on?
```

Inputs:

- author competence confidence
- author line survival, self-rework, cross-author overwrite
- author historical review friction
- author experience with touched component/security surface
- reviewer competence and reviewer line-survival history
- reviewer component fit
- current approval coverage
- negative/contradicted votes
- unresolved comments
- patch-set churn after first concern
- concerns after approval
- repeated concerns on same file
- strong concern vocabulary in human comments

The current system partially has both stages, but it sums them too directly.

## Concrete Scoring Changes

### 1. Replace Flat Sum With A Gated Priority Score

Use a structure like:

```text
security_locus = normalized 0..100
process_risk = normalized 0..100
competence_uncertainty = normalized 0..100
reviewer_coverage_risk = normalized 0..100

deep_review_priority =
  security_locus * (0.55 + process_risk / 100)
  + competence_uncertainty * security_locus / 100 * 35
  + reviewer_coverage_risk * security_locus / 100 * 30
  + high_process_risk_bonus
```

This keeps security relevance necessary, but prevents pure security keywords from dominating.

### 2. Penalize Mechanical And Documentation Patterns Before Ranking

Detected patterns should reduce compute priority unless implementation-risk or auth-boundary code changes are also present:

- `Blackify`
- `Ruff`
- `pyupgrade`
- `pre-commit`
- `mypy`
- `hacking`
- `doc`
- `documentation`
- `re-formatting`
- pure release note
- migration squashes

Do not drop them to zero, but treat them as low compute-priority unless review-process smell is high.

### 3. Cluster Patch Families

Group by normalized subject plus Change-Id/cherry-pick lineage when available.

For each cluster, show:

- root/master change
- backports
- riskiest backport
- branch spread
- whether the riskiest backport has conflict/missing-patch discussion

Compute should inspect the root plus the riskiest backport, not every duplicate row.

### 4. Make Reviewer Evidence First-Class

A merged security-sensitive review with no captured positive vote or no approval-survival row should not be treated as neutral.

Add:

```text
reviewer_evidence_missing_penalty
reviewer_component_fit
reviewer_security_surface_fit
reviewer_current_approval_survival
reviewer_historical_approval_survival
reviewer_contradiction_after_approval
```

Missing reviewer evidence should be a risk factor when security_locus is high.

### 5. Separate Unknown Author From Weak Author

Use two fields:

```text
author_competence_risk
author_competence_uncertainty
```

Weak author with high confidence is a stronger signal than unknown author.

Unknown author should become high priority only when:

- security_locus is high, and
- reviewer coverage is weak, or
- review churn/comment smell is high.

### 6. Lift Strong Human Review Smell

Examples that should be more important than generic keyword hits:

- "not convinced this works"
- "things will break here"
- "not covered by tests"
- "this is tricky"
- "not sufficient"
- "weird"
- "monstrous"
- "workaround"
- "race"
- "conflict"
- "wrong"
- "unsafe"
- "bypass"

The system already extracts some of this. It needs more weight when paired with:

- security-sensitive files
- low author confidence
- reviewer disagreement
- patch-set churn after the concern

## Revised Priority For The Earlier Cluster

Using the intended concept, the priority should look more like:

1. `967048` - federated role cache. Best example of low author confidence plus hard-to-prove auth/cache behavior plus review uncertainty.
2. `982913` - LDAP pagination. Not clearly security, but very strong implementation/process smell. If LDAP availability or identity correctness matters, inspect.
3. `966871` - service-user auth backport. Thin author evidence plus conflict/missing-patch discussion.
4. `987062` - restricted app-cred EC2 backport. Direct auth boundary, weaker author/reviewer confidence than master.
5. `990485` - delegated token boundary. Very security-important, but less competence-smelly because author/reviewer signals are stronger.
6. `988237` - app cred project boundary. Important, but reviewer coverage looks stronger.
7. `983655` - master restricted app-cred fix. Direct vuln surface, but better author/reviewer signals.
8. `966583` - disabled user token invalidation. Sensitive code, but strong author lowers concern.

## What To Change In The UX

The Review Risk tab should show two rankings:

1. Security importance.
2. Competence-weighted deep-review priority.

The current single score mixes both and creates confusion.

The table should expose:

- security locus score
- author competence risk
- author confidence
- reviewer coverage risk
- reviewer competence
- process smell score
- churn-after-concern score
- mechanical/doc suppression flag
- cluster id / patch-family id

The "why this ranked" popup should say things like:

```text
High priority because:
security locus is high,
author evidence is weak,
reviewer coverage is thin,
review had 18 patch sets,
reviewer explicitly questioned correctness,
concerns persisted after patch set 7.
```

That is the product. Not another scanner.

## Immediate Next Steps

1. Add patch-family clustering for Gerrit changes.
2. Add a mechanical/doc/tooling suppression factor.
3. Split the score into `security_locus_score` and `deep_review_priority_score`.
4. Make missing reviewer evidence risky for high-security changes.
5. Reweight comment smell so strong implementation concern can outrank generic security keywords.
6. Recompute the top 50 and compare how many rows are actual compute-worthy reviews versus mechanical/security-keyword noise.

