# Keystone Generalized Decision Tree V2

Generated: 2026-06-10

Purpose: redo the Keystone decision tree without overfitting to Swift or hardcoding repository-specific ideas. Swift remains a validation set, not a source of rules.

## Principle

Do not build repo-specific trees.

The first split should not be:

```text
Keystone auth terms
Swift storage terms
```

It should be generic vulnerability mechanisms:

```text
boundary enforcement
state freshness
input parsing / validation
data integrity
privilege / identity mapping
serialization
privacy exposure
dependency / runtime behavior
mechanical-only change
```

Those mechanisms show up differently in Keystone and Swift, but the tree should not care which repository produced them.

## Keystone Calibration Data

Sample: 500 merged Keystone Gerrit reviews.

Current score partitions:

| Partition | Count |
|---|---:|
| high security-looking mechanical/docs/tooling | 9 |
| high boundary-looking but clean/strong author | 23 |
| high boundary-looking with process smell | 10 |
| high boundary-looking with weak/thin author | 7 |
| low security score but high process smell | 27 |

The main failure is still the same: high security-looking rows rank high even when the competence/process signal says they should be lower compute priority.

## Generic Mechanism Tree

### Step 1: Classify Mechanism

Classify each review by generic mechanism. Multiple mechanisms can apply.

| Mechanism | Meaning | Keystone examples |
|---|---|---|
| `boundary_enforcement` | changes who can do what, or what project/domain/scope a token/credential applies to | `990485`, `988237`, `983655`, `983597`, `966583` |
| `state_freshness` | stale authz/authn/cache/revocation/group membership state | `967048`, `966583`, `990488` |
| `input_validation` | schema, parser, request validation, malformed input handling | `929686`, `925517`, `930610`, `927856` |
| `identity_mapping` | federation, LDAP, shadow users, domain/project mapping | `967048`, `982913`, `742235`, `970166` |
| `data_integrity` | hash length, credential blob integrity, token/credential data shape | `828595`, `890661`, `932423` |
| `privacy_exposure` | logs, messages, notifications, token/cert/credential detail exposure | `932423`, maybe `947861` if doc-only should suppress |
| `serialization_runtime` | pickle/unmarshal/deserialization/import/runtime behavior | less Keystone in top sample, but generic |
| `mechanical_only` | formatting, typing, pyupgrade, pre-commit, docs-only, release-note-only | `924522`, `931959`, `924010`, `925008`, `950157`, `925031`, `924085` |

Important: mechanism classification should come from normalized metadata, not subject strings alone.

Subject strings are acceptable as weak hints only when metadata is missing.

### Step 2: Classify Locus

Use mechanism to decide whether the review is in a plausible vulnerability locus.

```text
critical_locus:
  boundary_enforcement
  state_freshness affecting authz/authn
  serialization_runtime with untrusted data
  input_validation on externally supplied request data
  data_integrity on security-sensitive object/token/credential/state

important_locus:
  identity_mapping
  schema/validation for sensitive resources
  DB constraints for access-control resources
  cache/freshness for permission or identity state

process_only_locus:
  high churn or concern, but mechanism is not directly security/data/control relevant

suppressed_locus:
  mechanical_only with no runtime behavior change
```

This avoids saying "auth is special" or "storage is special." The question is whether the mechanism can create a security/data/control failure.

## Step 3: Classify Author Evidence

Keep the earlier split, but make the labels clearer.

```text
strong_known:
  confidence >= 0.75 and competence >= 75

weak_known:
  confidence >= 0.75 and competence <= 55

mixed_known:
  confidence >= 0.75 and 55 < competence < 75

thin_unknown:
  confidence < 0.35

thin_mixed:
  0.35 <= confidence < 0.75
```

Do not treat `thin_unknown` as automatically bad. It only becomes important when locus or process signals are also concerning.

Keystone calibration:

- Artem rows often become `strong_known`; clean rows should drop in compute priority.
- Moutaz rows are `thin_unknown`; they should rise only when process smell is strong, as in `967048` and `982913`.
- OAuth mTLS rows are `thin_unknown`; they should rise because both locus and process smell are strong.

## Step 4: Classify Reviewer Evidence

Reviewer quality should not be a simple positive or negative number.

```text
strong_clean_review:
  strong reviewer history
  enough reviewers
  low patch churn
  low unresolved comments
  few/no strong concerns

strong_but_struggled:
  strong reviewer history
  but high patch churn, repeated concerns, negative vote, or unresolved concern

weak_or_missing_review:
  too few human reviewers
  no positive approval metadata
  no approval survival data
  weak reviewer history

contradicted_review:
  negative votes, vote flips, or concerns after approval
```

This avoids the common bad interpretation:

```text
strong reviewers => safe
```

Actually:

```text
strong reviewers + struggle => hard problem, worth compute
strong reviewers + clean => lower compute priority
```

## Step 5: Classify Process Smell

Use generic review-process signals:

```text
highly_smelly:
  implementation_score >= 150
  or patch_sets >= 12
  or human_messages >= 40
  or unresolved >= 4
  or negative_votes > 0
  or repeated_concern_files >= 2

smelly:
  implementation_score >= 80
  or patch_sets >= 6
  or human_messages >= 12
  or unresolved >= 2
  or strong_concern_messages >= 2

clean:
  none of the above
```

The threshold values are still heuristic, but they are not repo-specific.

## Step 6: Family / Backport Handling

Before final ranking, group related changes.

```text
family_key:
  normalized subject
  + Change-Id lineage
  + cherry-pick lineage
```

For each family:

- keep root/master row
- keep riskiest backport
- collapse other duplicates
- raise backport if conflict/missing-patch/confusing cherry-pick language appears

This prevents one issue from consuming many top-list slots.

Keystone examples:

- `990485`, `990490`, `990495` should be one family.
- service-user auth rows should be one family, with `966871` kept because it has conflict/missing-patch discussion.
- app-credential EC2 rows should be clustered but not hidden because the master and backport/fix variants touch related but distinct boundaries.

## Final Priority Tree

Use labels first, numeric sorting second.

```text
if mechanism == mechanical_only and process != highly_smelly:
  suppressed_mechanical

else if locus == critical_locus:
  if process == highly_smelly:
    urgent_compute
  else if author == weak_known:
    urgent_compute
  else if author in [thin_unknown, thin_mixed] and reviewer in [weak_or_missing_review, contradicted_review, strong_but_struggled]:
    urgent_compute
  else if reviewer == strong_clean_review and author == strong_known:
    important_security_review
  else:
    high_compute

else if locus == important_locus:
  if process == highly_smelly:
    high_compute
  else if process == smelly and author in [weak_known, thin_unknown, thin_mixed]:
    high_compute
  else if reviewer in [contradicted_review, strong_but_struggled]:
    medium_high
  else:
    medium

else if locus == process_only_locus:
  if process == highly_smelly:
    process_smell_watch
  else:
    low_priority

else:
  low_priority
```

## Keystone Expected Outcome

### Should Rise Or Stay High

| Change | Why |
|---:|---|
| `860613` | critical boundary, thin author, high process smell |
| `830739` | OAuth client credentials, thin author, high churn/smell |
| `739966` | domain mapping rules, thin author, extreme churn |
| `967048` | state freshness / cache / revocation, thin author, strong reviewers struggled |
| `982913` | identity mapping / LDAP correctness, negative vote, high process smell |
| `966871` | boundary backport, thin author evidence, conflict/missing-patch discussion |
| `987062` | credential boundary, weaker author/reviewer confidence than master |
| `885463` | access-rule DB invariant, thin author, unresolved concerns |
| `828595` / `890661` | password/hash data integrity, process smell |

### Should Stay Important But Lower Compute

| Change | Why |
|---:|---|
| `990485` | critical boundary, but strong author and low process smell |
| `988237` | direct boundary, but stronger author/reviewer signals |
| `983655` | direct boundary, but cleaner process and good author evidence |
| `966583` | token validation/state freshness, but strong author and low implementation smell |

### Should Drop

| Change | Why |
|---:|---|
| `924522` | mechanical formatting |
| `931959` | linting/tooling |
| `924010` | pyupgrade |
| `925008` | datetime deprecation cleanup |
| `950157` | pre-commit hooks |
| `925031` | hacking/pre-commit |
| `924085` | mypy enablement |
| clean duplicate backports | cluster/family suppression |

## Anti-Overfit Rules

Do not add rules like:

```text
if project == swift and subject contains s3api
if project == keystone and subject contains token
```

Do add normalized mechanism metadata like:

```text
security_locus.boundary_enforcement
security_locus.state_freshness
security_locus.input_validation
security_locus.data_integrity
security_locus.identity_mapping
security_locus.serialization_runtime
security_locus.privacy_exposure
change_type.mechanical_only
change_type.docs_only
change_type.tests_only
```

Validation against Swift should ask only:

```text
Did the generic mechanisms transfer?
Which mechanism metadata was missing?
Which thresholds were too aggressive?
```

It should not create Swift-specific branches.

## What Changed From The Earlier Tree

Earlier tree:

```text
high = auth/token/credential/policy/etc.
```

V2 tree:

```text
high = generic mechanism capable of security/data/control failure.
```

That is the important correction.

The implementation should focus on better normalizers for mechanism classification, not on adding repo-specific lists.

