# Keystone Candidate Decision Trees

Generated: 2026-06-10

Purpose: define explainable decision-tree style ranking rules for Keystone review-risk scoring, then validate the same rules against Swift.

The current flat score over-ranks security-looking mechanical changes and under-separates "important security work" from "worth expensive deeper analysis." The tree below keeps security relevance as the first partition, then uses author/reviewer competence and review-process smell inside that partition.

## Keystone Sample Signals

Sample: 500 merged Keystone Gerrit reviews from the local Repointel database.

Partition counts from the current scorer:

| Partition | Count |
|---|---:|
| high-security, low-smell, strong/known author | 23 |
| high-security, low-smell, currently still high-ranked | 16 |
| high-security with weak author or process smell | 11 |
| low-security but high process smell | 27 |
| high-security mechanical/docs/tooling-looking | 9 |
| high-security with weak author confidence | 7 |

This confirms the problem: the current score confuses security importance with deep-review priority.

## Tree 1: Security Locus Partition

First classify the review into a security locus bucket.

### High Security Locus

Assign `high` if any of these are true:

- auth/token/credential/trust/federation/policy/RBAC/OAuth/EC2/S3 service-auth surface
- `security_score >= 240`
- `security_sensitive_files >= 2`
- `attack_surface_files >= 2`
- security scenario hit involving auth, credential, token, crypto, deserialization, parser validation, privilege, or project/domain boundary

Keystone examples:

- `860613` OAuth mTLS
- `830739` OAuth client credentials
- `990485` delegated token project boundary
- `988237` app cred EC2 project boundary
- `966583` disabled user token invalidation

### Medium Security Locus

Assign `medium` if any of these are true:

- identity correctness that can affect auth behavior, availability, or stale permission state
- LDAP/federation/cache/role-assignment correctness
- DB schema or validation paths tied to authz-sensitive resources
- `security_score 80..239`
- `implementation_score >= 100` and the subject/files are identity/auth adjacent

Keystone examples:

- `967048` federated role cache
- `982913` LDAP pagination
- `885463` access rule uniqueness
- JSON schema validation around application credentials/services/endpoints

### Low Security Locus

Assign `low` if all of these are true:

- docs/tooling/formatting/pre-commit/mypy/pyupgrade/mechanical migration
- no auth/cache/token/credential/federation/policy touched path
- `security_score < 80`
- no strong implementation concern

Keystone examples that should usually suppress:

- `924522` Blackify
- `931959` Ruff
- `924010` pyupgrade
- `950157` pre-commit hook versions
- `925031` hacking check

## Tree 2: Deep Review Priority

After security locus is assigned, rank for compute priority.

### A. High Locus Branch

For `high` locus:

```text
if mechanical_or_docs and implementation_score < 60 and unresolved <= 1:
  priority = suppress
else if author_confidence < 0.35 and (implementation_score >= 80 or patch_sets >= 8 or unresolved >= 2):
  priority = urgent
else if implementation_score >= 120 or strong_concern_messages >= 4:
  priority = urgent
else if reviewer_evidence_missing and author_confidence < 0.50:
  priority = high
else if reviewer_history_strong and author_confidence >= 0.75 and implementation_score < 40:
  priority = important_but_lower_compute
else:
  priority = high_or_medium_by_score
```

Keystone results this should improve:

- `860613`, `830739`: urgent. High security plus weak author confidence plus strong review smell.
- `990485`: important but lower compute. High security, strong author, low implementation smell.
- `924522`, `931959`, `950157`: suppress. Security-looking mechanical/tooling work.
- `987062`: high. Direct auth/credential boundary and weaker author/reviewer confidence than the master fix.

### B. Medium Locus Branch

For `medium` locus:

```text
if implementation_score >= 150:
  priority = high
else if negative_votes > 0 and patch_sets >= 8:
  priority = high
else if author_confidence < 0.35 and human_messages >= 12:
  priority = high
else if unresolved >= 4 or patch_sets >= 12:
  priority = medium_high
else:
  priority = medium_or_low
```

Keystone results this should improve:

- `967048`: high. Federation/cache/token invalidation correctness, weak author evidence, 18 patch sets.
- `982913`: high or medium-high. LDAP correctness, negative vote, 13 patch sets, 43 human messages.
- `929686`, `925517`: medium-high if authz-sensitive validation; otherwise medium.

### C. Low Locus Branch

For `low` locus:

```text
if implementation_score >= 180 and human_messages >= 25:
  priority = medium
else if changed_real_code and strong_concern_messages >= 5:
  priority = medium
else:
  priority = low
```

This prevents docs/tooling noise from outranking actual auth/token work.

## Tree 3: Author Competence Branch

Author competence should not be a single additive penalty. Split it into known weakness and uncertainty.

```text
if author_confidence >= 0.75:
  if competence_score >= 75:
    author_branch = strong
  else if competence_score <= 55:
    author_branch = weak_known
  else:
    author_branch = mixed_known
else if author_confidence < 0.35:
  author_branch = unknown_or_thin
else:
  author_branch = mixed_thin
```

Use it conditionally:

- `weak_known` strongly boosts priority in high/medium locus.
- `unknown_or_thin` boosts priority only if review smell, weak reviewer coverage, or high locus is present.
- `strong` suppresses compute priority unless review smell is high or security locus is extreme.

Keystone examples:

- Artem rows: `strong`, should suppress clean/mechanical rows.
- Moutaz rows: `unknown_or_thin`, should boost `967048` and `982913` because review smell is strong.
- OAuth mTLS rows: `unknown_or_thin`, should stay high because review smell and locus are high.

## Tree 4: Reviewer Coverage Branch

Reviewer competence should be a gate, not just points.

```text
reviewer_evidence_missing =
  positive_votes == 0
  or approval_survival_approvals == 0
  or reviewer_history_count == 0

reviewer_coverage_strong =
  reviewer_history_count >= 2
  and reviewer_avg_line_survival_rate >= 0.97
  and human_reviewers >= 2

reviewer_coverage_weak =
  reviewer_evidence_missing
  and human_reviewers <= 1
```

Use it:

- high locus + weak author + weak reviewer coverage => high/urgent.
- high locus + strong author + strong reviewer coverage + low smell => lower compute priority.
- medium locus + strong reviewer disagreement/negative vote => raise priority.

Keystone examples:

- `990485`: strong author, Grzegorz review, low smell. Important but not top compute.
- `967048`: strong reviewers, but the comments show uncertainty. Reviewer strength does not suppress because review smell remains high.
- `982913`: strong reviewers plus negative vote/pushback. That increases concern rather than lowering it.

## Tree 5: Backport / Patch-Family Branch

Group related changes before final ranking.

```text
family_key =
  normalized_subject
  + original Change-Id when present
  + cherry-picked-from chain when present
```

For each family:

- show root/master change
- show riskiest backport
- collapse duplicate low-smell backports
- raise a backport if conflict/missing-patch language appears

Keystone examples:

- Service-user auth family: root/backports should collapse; `966871` remains visible because conflict/missing-patch discussion appears.
- Delegated-token family: `990485` root plus a compact backport list; `990490` and `990495` should not consume top-list slots.
- App-cred EC2 family: surface master plus branch with weakest author/reviewer/process evidence.

## Candidate Priority Labels

Use labels instead of only one numeric score:

| Label | Meaning |
|---|---|
| `urgent_compute` | high/medium locus plus weak author/reviewer/process smell |
| `important_security_review` | high locus but competent author/reviewer and low smell |
| `process_smell_watch` | medium/low locus but serious review smell |
| `cluster_backport_check` | duplicate family row, inspect only riskiest backport |
| `suppressed_mechanical` | security-looking but likely mechanical/docs/tooling |
| `low_priority` | low locus and low smell |

This makes the UI clearer than one "risk" number.

## Keystone Expected Re-Ranking

Expected top compute-priority rows after tree logic:

| Expected Priority | Change | Why |
|---:|---:|---|
| 1 | 860613 | high locus, weak author confidence, high implementation smell, many unresolved comments |
| 2 | 830739 | high locus, weak author confidence, high implementation smell, 13 patch sets |
| 3 | 739966 | medium/high locus, weak author confidence, 24 patch sets, very high review friction |
| 4 | 967048 | federation/cache/token invalidation, weak author evidence, 18 patch sets, reviewer uncertainty |
| 5 | 982913 | identity correctness, negative vote, 13 patch sets, strong reviewer pushback |
| 6 | 966871 | security backport, thin author evidence, conflict/missing-patch discussion |
| 7 | 987062 | direct credential boundary, weaker author/reviewer evidence than master |
| 8 | 885463 | access rule DB correctness, weak author confidence, unresolved comments |
| 9 | 828595 / 890661 | password hash length correctness, enough smell to inspect |
| 10 | 990485 | high security importance, but lower compute priority due strong author/review and low smell |

Expected demotions:

- `924522` Blackify
- `931959` Ruff
- `924010` pyupgrade
- `925008` py312 datetime
- `950157` pre-commit
- `925031` hacking check
- duplicate backports for `990485`
- duplicate backports for service-user auth except the conflicted one

## Swift Validation Plan

Do not tune on Swift first. Apply the Keystone tree as-is, then inspect failures.

Validation questions:

1. Does the tree suppress Swift mechanical/docs/tooling work better than the flat score?
2. Does it raise review-process-smelly auth/storage/erasure-coding/consistency changes?
3. Does it avoid ranking generic security keyword mentions above competence/process-smelly implementation changes?
4. Does patch-family clustering reduce duplicate backport noise?
5. Does weak/unknown author only matter when the change is security/identity/storage-critical or review-smelly?

Swift-specific areas should be detected through generic metadata, not hardcoded project names:

- auth/middleware/tempurl/slo/dlo/encryption/key/token/acl/container/account
- erasure coding/reconstructor/replicator/object-server/proxy-server
- consistency, corruption, quorum, fragment, timestamp
- parser/input/header/request/body/range
- credentials/secrets/tls/cert/signature
- dependency/workflow/CI paths

The rule remains generic:

```text
security/critical locus first,
then author/reviewer/process smell,
then cluster/backport suppression.
```

## Implementation Notes

The UX can keep current bucket details, but final classification should be tree-shaped:

```text
security_locus_bucket = high | medium | low
mechanical_suppression = true | false
author_branch = strong | mixed_known | weak_known | mixed_thin | unknown_or_thin
reviewer_branch = strong | weak | missing | contradicted
process_branch = clean | smelly | highly_smelly
patch_family_branch = root | duplicate_backport | riskiest_backport

priority_label = tree(...)
priority_score = numeric sort key inside label
```

This gives us explainability and avoids pretending we have labels for supervised ML.

