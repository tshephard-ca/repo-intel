# Repointel Metadata Collection Facade

Mission: see [MISSION.md](MISSION.md).

This is a separate Frontplane REST service for vulnerability-intelligence metadata collection. It does not import `RepointelRuntime` and does not own repositories, sources, raw records, arts, authors, metadata, or relationships. Those resources stay in `RepointelFacade`.

The `.fp` file declares downstream dependencies explicitly as REST provider calls:

- `RepointelFacade.search_sources`
- `RepointelFacade.search_raw_records`
- `RepointelFacade.search_arts`
- `RepointelFacade.search_authors`
- `RepointelFacade.bulk_upsert_metadata`
- `RepointelFacade.bulk_upsert_relationships`
- `RepointelAnalyticsProvider.*`
- `SzzAnalysisProvider.*`

At runtime, configure the downstream endpoint with:

```bash
export METADATACOLLECTIONFACADE_PROVIDER_ENDPOINTS_JSON='{
  "RepointelFacade": { "base_url": "http://127.0.0.1:18081" },
  "RepointelAnalyticsProvider": { "base_url": "http://127.0.0.1:18194" },
  "SzzAnalysisProvider": { "base_url": "http://127.0.0.1:18195" }
}'
```

The local persistence directory defaults to `.metadata-collection-data` and can be changed with:

```bash
export METADATA_COLLECTION_DATA_DIR=/var/lib/repointel/metadata-collection
```

`DownstreamServices` is an operator-visible catalog and connection-test surface.
Generated provider routing still comes from
`METADATACOLLECTIONFACADE_PROVIDER_ENDPOINTS_JSON`; saving a downstream-service
row does not dynamically retarget `Ncall` providers at runtime.

Configure bearer tokens explicitly. The facade does not accept role-name bearer
tokens such as `reader`, `writer`, or `admin`.

```bash
export METADATA_COLLECTION_AUTH_TOKENS_JSON='{
  "tokens": {
    "<metadata-facade-token>": {
      "subject_id": "operator-local",
      "handle": "operator-local",
      "roles": ["admin"]
    }
  }
}'
```

The token used when calling Repointel is required for provider calls that use
`RepointelFacade.*`:

```bash
export METADATA_COLLECTION_REPOINTEL_TOKEN='<repointel-bearer-token>'
```

The internal analytics and SZZ providers also require shared bearer tokens:

```bash
export REPOINTEL_ANALYTICS_PROVIDER_TOKEN='<analytics-provider-token>'
export METADATACOLLECTIONFACADE_REPOINTEL_ANALYTICS_PROVIDER_TOKEN='<analytics-provider-token>'
export REPOINTEL_SZZ_PROVIDER_TOKEN='<szz-provider-token>'
export METADATACOLLECTIONFACADE_REPOINTEL_SZZ_PROVIDER_TOKEN='<szz-provider-token>'
```

Configure SZZ provider dependencies explicitly. `REPOINTEL_GIT_ROOT` is only a
fallback; repository source records with `ingestion_policy.local_path` take
precedence. `REPOINTEL_GERRIT_URL` is required when SZZ backfills missing
candidate-review details from Gerrit. Batch SZZ analysis requires a repository,
review ids, a direct review/commit request, or `params.all = true`.

```bash
export REPOINTEL_GIT_ROOT=/srv/repointel/git
export REPOINTEL_GERRIT_URL=https://gerrit.example.org
```

## Built-In Profile

The service seeds `profile_vuln_intel_priority_v1` / `vuln_intel_priority_v1` and `bundle_vuln_intel_core_extractors` / version `1`.

Seed explicitly:

```http
POST /metadata-collection/profiles:seed-vuln-intel-priority-v1
Authorization: Bearer <metadata-facade-token>
```

The seed includes CVE/GHSA, suspected security fix, review concern, issue-fix, revert/cherry-pick, sensitive component, dependency manifest, workflow permission risk, silent fix candidate, and unresolved review concern scenarios.

## Relationship Boundary

This service converts external facts such as CVEs, GHSAs, issue ids, commit SHAs, file paths, package names, workflow triggers, and components into Repointel metadata nodes first. Relationships committed downstream may only target `metadata`, `art`, or `author`.

Cardinality is implicit: one-to-many, many-to-one, and many-to-many are represented by multiple relationship rows. No relationship row contains a cardinality field or arrays of endpoints.

## Generic Signal Capture

The normalizers are intended to emit generic metadata and relationship facts that later analytics can reuse across repositories and providers instead of hardcoding Swift-specific behavior. The currently captured signal families include:

- Review friction: patch sets, total comment counts, unresolved comment counts, review message events.
- Approval / review posture: approval votes, submit record labels, reviewer-to-approval links, approval-to-change links.
- Silent security-fix candidates: commit-message security signals without explicit CVE/GHSA identifiers.
- Review abandonment / instability: change status, submit type, patch sets, review messages, vote flips and removals.
- Change churn shape: insertions, deletions, changed file counts, binary file counts, review-side insertions/deletions.
- Component concentration: file paths, component names, change-to-file links, change-to-component links, authored-by links.
- File hotspots: art-linked file paths with repeated review coverage and repeated security-signal co-occurrence.
- Bug-thread exposure: bug ids, duplicate counts, message counts, heat, privacy, security-related flags, lifecycle timestamps.
- Sensitive-surface hotspots: component-level security-signal clustering and distinct security-signal kinds across reviewed changes.
- Sensitive review disagreement: changes that have both security-signal evidence and conflicting positive/negative review votes.
- Dependency-change exposure: dependency-manifest file paths, dependency file-role classifications, dependency risk scenarios.
- Workflow / CI risk exposure: workflow-related file paths, workflow risk scenarios, automated review messages.
- Human vs automated review ratio: code review automation flags and review message kinds.
- Cross-artifact convergence: commit-to-bug links, change-to-file links, change-to-component links, and security signals.

These are capture contracts, not final risk scores. Higher-level charts and vulnerability-locus models should be built on top of these generic facts.

## ONNX Security Sensitivity Scores

The local ONNX model in `onnx/` scores persisted text for security sensitivity. The bulk scorer writes one metadata row per scored art or raw record:

- `namespace = security.sensitivity`
- `key = score`
- `subject_type = art` or `raw_record`
- `value.score` is a `0..100` model score
- `value.label` is `low`, `medium`, or `high`

Run it after ingestion or normalization when new text has been persisted:

```bash
python3 onnx/score_repointel_text.py \
  --database-url postgres://repointel:repointel@127.0.0.1:15432/repointel \
  --batch-size 128 \
  --write-batch-size 1000
```

The Review Risk tab consumes these scores as part of the proposed-review security score.

## Score Catalog APIs

The metadata-collection facade exposes reusable score primitives and rollups:

- `GET /metadata-collection/scores`
- `GET /metadata-collection/scores/{score_id}`
- `POST /metadata-collection/scores/{score_id}/compute`
- `GET /metadata-collection/score_buckets`
- `GET /metadata-collection/score_buckets/{score_bucket_id}`
- `POST /metadata-collection/score_buckets/{score_bucket_id}/compute`

The built-in Review Risk catalog has atomic scores for security keywords, security sensitivity, file surface, author competence, reviewer survival, implementation concerns, review friction, review churn, changed lines, and staleness. `changed_lines_score` is a separate score item derived from insertions plus deletions; it is not part of author competence. The `review_risk_weighted_average` score bucket computes `sum(score * weight * confidence) / sum(weight * confidence)` over those items.

## Main Flow

1. `POST /metadata-collection/runs:plan` calls Repointel search endpoints and reports available work.
2. `POST /metadata-collection/runs` reads selected raw records and arts from Repointel over REST, runs local extractor rules, and persists evidence hits.
3. Analysts review hits with accept/reject or bulk review APIs.
4. `POST /metadata-collection/evidence-hits:commit` sends metadata first to `RepointelFacade /metadata:bulk-upsert`, maps local metadata refs to returned ids, validates relationship endpoints, then sends relationships to `RepointelFacade /relationships:bulk-upsert`.
5. Downstream calls are persisted as traces for auditability.

## Verification

```bash
cargo run -- check projects/repointel-metadata-collection/frontplane.fp
cargo run -- routes projects/repointel-metadata-collection/frontplane.fp
cargo run -- generate --input projects/repointel-metadata-collection/frontplane.fp --out projects/repointel-metadata-collection/generated
cargo build --manifest-path projects/repointel-metadata-collection/generated/Cargo.toml
cargo test --manifest-path projects/repointel-metadata-collection/generated/Cargo.toml
```

## Docker Packaging

The Docker packaging keeps the Frontplane boundaries as separate runtime roles:

- `postgres` in `docker-compose.yml` owns the Repointel database for the stack.
- `Dockerfile.repointel` builds the generated Repointel facade used as the
  downstream provider.
- `Dockerfile` builds the generated Rust metadata-collection facade.
- `Dockerfile.gateway` runs either the browser gateway or the internal analytics
  provider.
- `Dockerfile.szz-provider` runs the internal SZZ provider with `git` and
  `psql` available.
- `docker-compose.yml` wires the facade to `RepointelFacade`,
  `RepointelAnalyticsProvider`, and `SzzAnalysisProvider`.

Create local config and replace the placeholder tokens:

```bash
cp .env.docker.example .env
```

Then build and run:

```bash
docker compose up --build
```

The compose file exposes the browser gateway for remote access and keeps the
generated facades/Postgres local-only for inspection:

- Gateway: `http://<docker-host-ip>:18110` (`0.0.0.0:18110`)
- Metadata facade: `http://127.0.0.1:18102`
- Repointel facade: `http://127.0.0.1:18101`
- Postgres: `127.0.0.1:15432`

Service traffic stays inside the compose network: RepointelFacade uses
`postgres:5432`, the metadata facade calls `repointel-facade:18081`, and
analytics/SZZ read the same database. Analytics and SZZ provider ports are
internal to the compose network. Mount a local repository root with
`REPOINTEL_GIT_ROOT_HOST`; compose configures Git safe-directory handling for
the mounted `/git` tree inside the Repointel and SZZ containers.

For another machine on the same network, open
`http://<docker-host-ip>:18110`. The host firewall must allow inbound TCP
`18110`; no direct remote access to Postgres or the generated facades is needed
for the browser UI because the gateway proxies `/api/repointel/*` and
`/api/metadata/*` server-side.

## Debug Console

The verification UI is in `projects/repointel-metadata-collection/ux`. It is intentionally an operator console: it shows REST calls, resource trees, ingestion job member reads, normalizer tests, metadata-collection runs, evidence hits, downstream traces, and raw persisted collections.

The UI server is the single browser-facing gateway. The browser only calls same-origin paths:

- `/api/repointel/*`
- `/api/metadata/*`

Those paths are proxied server-side to the two local facades, so the Repointel and metadata-collection API ports can stay bound to `127.0.0.1` and do not need firewall exposure.

Aggregate analytics are declared in `frontplane.fp` under
`/metadata-collection/console/...` and served through
`RepointelAnalyticsProvider.*`. The Node process only exposes them in
`--analytics-provider` mode, where `REPOINTEL_DATABASE_URL` and an analytics
provider token are required. Browser callers should use `/api/metadata/console/...`;
the gateway does not expose separate `/api/repointel-*` analytics aliases.

The source tree is optimized for live data checks. Each source row has inline `Ingest`, `Test`, `GETs`, and `Collect` actions. These call the configured provider/source and persisted facade records only; the console does not create synthetic authors, arts, raw records, or metadata.

For optional OpenStack Swift testing, select the Swift repository and use `Swift Sources`. That configures real Launchpad and Gerrit/OpenDev sources:

- Launchpad bugs from `https://api.launchpad.net/1.0/swift`
- Gerrit reviews from `https://review.opendev.org` with `external_key = openstack/swift`

For adding another OpenStack repository without duplicating normalizer rules, see [Adding an OpenStack Repository](docs/add-openstack-repository.md).

The `Ingest` action enqueues an ingestion job. Repointel processes queued jobs on the server with a background scheduler; the Ingestion tab polls every few seconds only to show job status, counts, persisted raw records, arts, authors, and logs. Browser polling is not responsible for doing the ingestion work.

Repository rows also have `Sync Current`. It calls `POST /repositories/{repository_id}/enqueue-ingestion` once with `mode = repository-sync`; the server expands that to all enabled sources for the repository. Provider ingest normalizes new or changed raw records, arts, and authors inline. It does not re-run normalizers over the full persisted corpus unless the request explicitly sets `reprocess_all_normalizers`, `reprocess_all_metadata_normalizers`, or `run_metadata_normalizers_over_persisted_records`.

When `REPOINTEL_SENSITIVITY_SCORER_COMMAND` is configured, the same job can run the ONNX scorer after ingestion and records scorer output in ingestion logs. The scorer skips records already scored with the same model and text hash.

Current sync is newest-first:

- Git runs `git fetch --all --prune`, then reads `git log` newest first.
- Launchpad reads recently updated bug tasks first and stores `launchpad_updated_watermark` / `launchpad_cursor` in the source ingestion policy.
- Gerrit reads recently updated changes first and stores `gerrit_updated_watermark` / `gerrit_cursor` in the source ingestion policy.
- Gerrit and Launchpad replay 2 days before the stored watermark by default, configurable with `watermark_replay_days` on the job params/source ingestion policy or `REPOINTEL_WATERMARK_REPLAY_DAYS`; this rehydrates recently updated comments, reviewers, bug messages, and metadata without advancing the stored watermark backwards.
- `full` and `backfill` ignore source watermarks; normal sync/incremental resumes from them.

Start Repointel against Postgres and the metadata-collection facade on loopback-only ports, then run the gateway on the already exposed UI port:

```bash
REPOINTEL_DATABASE_URL='postgres://repointel:repointel@127.0.0.1:5432/repointel' \
REPOINTEL_STORAGE=postgres \
REPOINTEL_SENSITIVITY_SCORER_COMMAND='python3 onnx/score_repointel_text.py --database-url postgres://repointel:repointel@127.0.0.1:5432/repointel' \
REPOINTEL_IMPORT_JSON_DIR=/tmp/repointel-ux-smoke \
cargo run --manifest-path generated/repointel/Cargo.toml -- --host 127.0.0.1 --port 18101
```

`REPOINTEL_IMPORT_JSON_DIR` is only needed for migrating an existing JSON store into the `repointel_records` JSONB table. The import marker is persisted in Postgres, so normal restarts do not re-import.

```bash
REPOINTEL_BASE_URL=http://127.0.0.1:18101 \
METADATA_COLLECTION_BASE_URL=http://127.0.0.1:18102 \
node projects/repointel-metadata-collection/ux/server.mjs
```

The gateway binds to `0.0.0.0:18110` by default. Override it with either `PORT` or `REPOINTEL_DEBUG_UI_PORT` if the existing firewall-open port is different:

```bash
REPOINTEL_DEBUG_UI_HOST=0.0.0.0 PORT=8080 node projects/repointel-metadata-collection/ux/server.mjs
```
