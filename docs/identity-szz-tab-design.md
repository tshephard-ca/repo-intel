# Outcome Evidence Tab Design

## Purpose

Add an operator-facing UI for ranking identities with SZZ analysis. The tab name should be **Outcome Evidence** rather than Identity SZZ because the UI is about historical outcome evidence, not a blame verdict. It should help answer:

- Which authors repeatedly appear as candidate bug-introducing identities?
- Which approvers/reviewers approved candidate-introducing reviews that later needed bug-fix commits?
- Which identities have enough evidence to deserve confidence, and which rankings are sparse/noisy?
- Which concrete SZZ candidates, fix reviews, files, and evidence lines explain each ranking?

The UI should be a decision-support surface, not an automated blame verdict. SZZ candidates are evidence with confidence, not proof of fault.

## Current System Shape

The SZZ execution path already exists.

- `frontplane.fp` exposes `SzzRuns`, including:
  - `GET /metadata-collection/szz-runs`
  - `GET /metadata-collection/szz-runs/{szz_run_id}`
  - `POST /metadata-collection/szz-analyses:search`
  - `POST /metadata-collection/szz-analyses:analyze-review`
  - `POST /metadata-collection/szz-analyses:analyze-batch`
- `tools/szz_review_analyze.py` performs the core SZZ-style Git diff/blame analysis.
- `tools/szz_frontplane_analyze.py` wraps that analyzer for Frontplane, looks up/backfills candidate Gerrit reviews, extracts approvers, and emits normalized `SzzCandidate` rows plus evidence hits.
- `ux/server.mjs` already proxies browser calls from `/api/metadata/*` to `/metadata-collection/*`.
- `ux/server.mjs` also exposes `/api/repointel-author-history`, which can enrich an identity with per-repository history and risk evidence.
- `ux/index.html` and `ux/app.js` currently expose Review Risk, repository/source management, ingestion jobs, and generic browser tooling, but no visible Outcome Evidence identity ranking view.

The existing batch artifact shape is already sufficient for UI ranking. A run contains `candidates`, and each candidate includes:

```json
{
  "type": "direct",
  "lines": 10,
  "score": 100.0,
  "confidence": "high",
  "candidate_commit": "f75b2865fe2aee3f6aefea8f08ce92e1d590ac98",
  "candidate_change_id": "I693980384df22b2fa581d8715f73c69b0598dd59",
  "author": {
    "name": "Ivan Pchelintsev",
    "email": "Ivan.Pchelintsev@dell.com",
    "identity_key": "email:ivan.pchelintsev@dell.com"
  },
  "candidate_review": {
    "change_number": "705176",
    "status": "MERGED",
    "subject": "Add support for VxFlex OS 3.5 to VxFlex OS driver",
    "url": "https://review.opendev.org/c/openstack/cinder/+/705176",
    "found_in_db": true,
    "backfilled": true
  },
  "approvers": [
    {
      "name": "Sean McGinnis",
      "email": "sean.mcginnis@gmail.com",
      "identity_key": "gerrit:11904"
    }
  ],
  "files": [
    "cinder/volume/drivers/dell_emc/powerflex/driver.py"
  ],
  "metadata": {
    "fix_review": "950546",
    "fix_commit": "63dc4c47e2995c786073efc8929479bf63cb2c15",
    "project": "openstack/cinder",
    "repository_id": "repository-9c252fb0eb2c08a6"
  }
}
```

## Frontplane Contract Notes

The design should treat `frontplane.fp` as the source of truth for paths, auth, and response envelopes.

Relevant structures:

- `SzzAnalysisSelector`
- `SzzAnalysisRequest`
- `SzzActor`
- `SzzCandidateReview`
- `SzzCandidate`
- `SzzAnalysisSummary`
- `SzzRun`
- `SzzRunPage`

Relevant auth policy:

- `reader`: authenticated users. Required for listing, getting, and searching SZZ runs.
- `writer`: `writer` or `admin` role. Required for `analyze-review` and `analyze-batch`.
- `admin`: required for deleting SZZ runs.

Relevant resource contract:

```frontplane
@resource(member: "szz_run", key: "szz_run_id", collection: "szz-runs", entity: SzzRun)
resource SzzRuns {
  @list(authz: reader, ...)
  @get(input: { szz_run_id: String }, authz: reader, ...)
  @delete(input: { szz_run_id: String }, authz: admin, ...)
  @collectionAction("search", method: "POST", path: "/szz-analyses:search", input: SearchRequest, authz: reader, ...)
  @collectionAction("analyze-review", method: "POST", path: "/szz-analyses:analyze-review", input: SzzAnalysisRequest, authz: writer, ...)
  @collectionAction("analyze-batch", method: "POST", path: "/szz-analyses:analyze-batch", input: SzzAnalysisRequest, authz: writer, ...)
}
```

This has one important UI consequence: SZZ search is **not** located at `/szz-runs:search`. It is located at `/szz-analyses:search`. Generic collection-browser search code must special-case `szz-runs` or avoid exposing search for that collection.

`SzzRunPage` responses follow the standard `items` plus `page` envelope. The tab should use `items(response)` or equivalent rather than assuming a raw array.

`SzzRun.evidence_hits` uses the normal `EvidenceHit` shape. When `SzzAnalysisRequest.commit_evidence` is true and `dry_run` is false, the runtime persists those hits to the local `evidence-hits` collection. Sending accepted SZZ evidence downstream still uses the existing `POST /metadata-collection/evidence-hits:commit` action, not a dedicated `SzzRuns` action.

## Recommended Approach

Create a new top-level **Outcome Evidence** tab. Do not fold this into Review Risk initially.

Reasons:

- Review Risk ranks reviews; Outcome Evidence ranks people/identities across historical SZZ outcomes.
- SZZ runs can be expensive to compute, while ranking saved SZZ runs is cheap.
- The score interpretation is different. Review Risk is a proposed-review prioritization score; Outcome Evidence is historical outcome evidence.
- A separate tab makes it easier to display raw SZZ evidence, role-specific rankings, and sparse-data warnings without overloading the Review Risk UI.

The first version should read saved `szz-runs` and aggregate in the browser. Do not run broad batch SZZ automatically from page load.

## Repository Group Scope

The UI must always be scoped to exactly one repository group. Authors and approvers from different groups must never be mixed into the same ranking table, chart, or summary cards.

Repository group is the first selector at the top of the tab. All other selectors are derived from it:

- SZZ run selector: show runs whose selector matches the group, a repository in the group, or an all-repository batch run that can be filtered by candidate repository/project.
- Repository selector: only repositories in the selected group.
- Summary cards, chart, ranked table, and identity detail: only candidates that resolve to repositories in the selected group. If a candidate has an explicit `repository_id`, treat that as authoritative.
- All-repository SZZ batch runs may appear under each group, but candidate rows are filtered to the selected group before any author/approver aggregation.

## Navigation And Layout

Add a nav button:

```html
<button data-tab="outcome-evidence">Outcome Evidence</button>
```

Add a corresponding tab with:

- Header: run status and refresh button.
- Filters:
  - Repository group selector, first and required.
  - SZZ run selector, default latest run available for the selected group.
  - Repository filter, constrained to repositories in the selected group.
  - Role selector: candidate authors, approvers, combined.
  - Candidate type selector: direct, context, both.
  - Minimum candidate score.
  - Minimum candidate rows.
  - Search text for identity name/email/key.
- Summary cards:
  - Candidates included.
  - Direct candidates.
  - Context candidates.
  - Ranked authors.
  - Ranked approvers.
  - Repositories covered.
  - Review coverage.
  - Visible identities.
- Main content:
  - Ranked identity table.
  - Horizontal bar chart for top identities.
  - Selected identity detail panel.

The layout should follow the current operator-console style: dense, table-first, minimal decorative UI.

## Data Loading

Use the metadata facade through the existing same-origin proxy:

```js
const page = await api("metadata", "GET", "/szz-runs");
const runs = items(page);
const run = await api("metadata", "GET", `/szz-runs/${encodeURIComponent(runId)}`);
```

For search/filtering saved runs:

```js
api("metadata", "POST", "/szz-analyses:search", {
  query: "",
  filters: {},
  limit: 100
})
```

Add `szz-runs` to `metadataCollections` in `ux/app.js` only if the generic browser gets a special case for search. The default generic browser behavior builds `/${collection}:search`, which would incorrectly call `/szz-runs:search`. For `szz-runs`, it should call `/szz-analyses:search`.

Do not call `POST /szz-analyses:analyze-batch` automatically. If the UI later gets an analysis action, it should be explicit and scoped:

- Single review analysis is acceptable from a selected review.
- Batch analysis should require an explicit form and clear progress/status.
- Batch analysis should be treated as backend work, not as a normal tab refresh.

## Identity Keys

Use `identity_key` when available. Fall back conservatively:

```js
function identityKey(actor) {
  if (actor?.identity_key) return actor.identity_key;
  if (actor?.account_id) return `gerrit:${actor.account_id}`;
  if (actor?.email) return `email:${actor.email.toLowerCase()}`;
  if (actor?.name) return `name:${actor.name.toLowerCase()}`;
  return "unknown";
}
```

Display name precedence:

1. `actor.name`
2. `actor.email`
3. `actor.username`
4. `identity_key`

Do not try to merge all Gerrit, Git, Launchpad, and email identities in the first version. The existing `author-history` endpoint can show likely related identities on drilldown, but the ranking table should make the raw identity key visible.

## Role-Specific Aggregates

Build separate aggregates for candidate authors and approvers.

### Candidate Author Row

One SZZ candidate contributes to the candidate author's row:

- `candidate_rows += 1`
- `direct_rows += 1` if `candidate.type === "direct"`
- `context_rows += 1` if `candidate.type === "context"`
- `total_lines += candidate.lines`
- `score_sum += candidate.score`
- `weighted_points += candidatePoints(candidate)`
- `fix_reviews.add(candidate.metadata.fix_review)`
- `candidate_commits.add(candidate.candidate_commit)`
- `projects.add(candidate.metadata.project)`
- `files.add(candidate.files[])`

### Approver Row

One SZZ candidate contributes to each approver, but the candidate points should be divided by approver count:

- `approval_candidate_rows += 1`
- `approved_candidate_commits.add(candidate.candidate_commit)`
- `approved_candidate_reviews.add(candidate.candidate_review.change_number)`
- `fix_reviews.add(candidate.metadata.fix_review)`
- `weighted_points += candidatePoints(candidate) / max(1, approvers.length)`

This prevents multi-approver reviews from multiplying the same SZZ outcome into several full-strength outcomes.

## Scoring

The UI ranking score should be transparent and easy to explain. Use the existing SZZ candidate `score` as the base evidence score; do not replace it.

Recommended first-pass candidate points:

```js
function candidatePoints(candidate) {
  const score = Number(candidate.score || 0);
  const lines = Math.max(0, Number(candidate.lines || 0));
  const typeWeight = candidate.type === "context" ? 0.45 : 1.0;
  const lineWeight = Math.log1p(lines);
  return score * typeWeight * lineWeight;
}
```

Recommended row ranking:

```js
identity_rank_score =
  weighted_points
  * confidenceMultiplier
  * evidenceBreadthMultiplier
```

Where:

- `confidenceMultiplier` is based on average SZZ candidate score and candidate count.
- `evidenceBreadthMultiplier` should be small, for example capped at `1.2`, so one broad project does not dominate solely by volume.

Keep the table sorted by `identity_rank_score`, but display raw supporting fields next to it:

- Rank score
- Candidate rows
- Direct rows
- Context rows
- Unique candidate commits
- Unique fix reviews
- Total lines
- Average SZZ score
- Projects

## Suggested Table Columns

Candidate Authors:

- Identity
- Rank
- Candidate rows
- Direct / context
- Avg SZZ score
- Lines
- Candidate commits
- Fix reviews
- Projects
- Top files

Approvers:

- Identity
- Rank
- Approved candidate rows
- Candidate reviews approved
- Candidate commits approved
- Avg SZZ score
- Fix reviews
- Projects
- Top files

Combined view:

- Identity
- Combined rank
- Candidate-author rank contribution
- Approver rank contribution
- Candidate rows
- Approved candidate rows
- Projects

## Detail Panel

Selecting an identity should show:

- Identity key and display fields.
- Role-specific metrics.
- Top candidate commits:
  - Candidate commit short SHA.
  - Candidate review link.
  - Fix review.
  - Project.
  - Type.
  - Lines.
  - Score/confidence.
  - Reason/subject.
- Top files touched by SZZ evidence.
- Evidence snippets from `candidate.evidence`.
- Approvers for candidate-author rows.
- Candidate author for approver rows.
- JSON details behind a collapsed `<details>` block.

Add an optional action:

```text
Open Author History
```

This should call `/api/repointel-author-history` with the best available identity:

- `gerrit_account_id` for `gerrit:<id>`
- `email` for `email:<email>`
- `q` or `name` for name-only identities
- `repository_id` or `project` when selected

Author history should be drilldown-only, not required for initial ranking.

## SZZ Run Management

The first version should support:

- Refresh saved runs.
- Select latest completed run by default.
- Select any saved run.
- Show run summary and errors.
- Show run selector metadata:
  - `id`
  - `mode`
  - `status`
  - `generated_at`
  - `summary.selected_reviews`
  - `summary.candidate_rows_kept`
  - `summary.rows_with_review`
  - `summary.rows_with_approver`

Later versions may add:

- Analyze single review.
- Analyze filtered batch.
- Delete stale SZZ run.
- Commit SZZ evidence hits.

Those actions should stay explicit and should use the auth level declared by `frontplane.fp`:

- Analyze review/batch: `writer`.
- Delete run: `admin`.
- Commit accepted SZZ evidence downstream: `writer` through `/evidence-hits:commit`.

## Non-Goals

Do not implement these in the first version:

- Full identity resolution across Git, Gerrit, Launchpad, and email aliases.
- Automatic rerunning of batch SZZ on page load.
- New persistent ranking schema.
- A new score catalog item unless a stable backend identity-ranking contract is required later.
- Replacing Review Risk author/reviewer competence scores with SZZ identity rank.

## Implementation Plan

1. Add `szz-runs` to the metadata browser collection list and special-case browser search to call `/szz-analyses:search`.
2. Add `Outcome Evidence` nav/tab markup in `ux/index.html`.
3. Add state in `ux/app.js`:
   - `identitySzzRequestId`
   - `identitySzzFilters`
   - selected run id
   - selected identity key
4. Add data loaders:
   - `refreshIdentitySzzRuns`
   - `refreshIdentitySzz`
5. Add aggregation helpers:
   - `identityKey`
   - `candidatePoints`
   - `aggregateSzzIdentities`
   - `filterIdentitySzzRows`
6. Add renderers:
   - summary cards
   - run selector
   - top-identity chart
   - ranking table
   - selected identity detail panel
7. Add event handlers:
   - refresh
   - filter submit/change
   - run selector change
   - table row select
   - open author history drilldown
8. Add CSS for the tab, reusing Review Risk table/detail styles where possible.

## Verification

Manual checks:

- Load the UI with `REPOINTEL_DATABASE_URL` and metadata facade configured.
- Open Outcome Evidence.
- Confirm latest completed SZZ run is selected.
- Confirm summary counts match the selected run summary.
- Switch role filters and candidate type filters.
- Select an identity and verify candidate rows are traceable to commits/reviews/evidence.
- Use a saved artifact-backed run and a live-analyzed run if both exist.

Automated checks:

- Unit-test aggregation helpers with a small fixture:
  - one direct candidate, one context candidate
  - one candidate with two approvers
  - one candidate missing `identity_key`
  - one candidate missing candidate review
- Verify approver points are divided across approvers.
- Verify direct rows rank above equal-score context rows.
- Verify filters do not mutate source candidate data.

## Future Backend Read Model

If SZZ runs grow too large for browser aggregation, add a gateway endpoint:

```http
GET /api/repointel-szz-identities?szz_run_id=...&role=author&project=...
```

The server-side aggregate should return the same row shape as the browser helper, so the UI does not change. Only move aggregation to the backend when saved runs become large enough to make browser ranking slow.

If the ranking endpoint needs to become part of the metadata-collection API rather than a UX gateway helper, add explicit Frontplane shapes instead of returning an untyped document. A likely shape set would be:

- `IdentitySzzRankRequest`
- `IdentitySzzRankRow`
- `IdentitySzzRankPage`

That new API should be read-only and `authz: reader`; analysis execution should remain on the existing writer-only SZZ actions.

## Recommended First Milestone

Ship the saved-run-only Outcome Evidence tab:

- No new Frontplane schema.
- No new database tables.
- No automatic SZZ execution.
- Ranking from saved `SzzRun.candidates`.
- Drilldown using existing evidence fields.
- Optional author-history enrichment behind a user action.

This gives a usable identity ranking UI quickly while keeping the SZZ evidence auditable and preserving Review Risk as the review-ranking surface.
