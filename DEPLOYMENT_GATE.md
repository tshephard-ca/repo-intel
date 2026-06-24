# DEPLOYMENT_GATE

Status: Local Docker deployment proof complete; external production promotion is
still gated on target/secrets/approval.

The repository now carries a compose deployment that includes its database,
generated Repointel facade, generated metadata facade, gateway, analytics
provider, and SZZ provider. Local proof used project
`repointel-metadata-proof` with a temporary port override because the default
host ports were already occupied by local processes; the in-container service
graph stayed the same.

Docker/Keystone proof completed on June 23, 2026:

- `docker compose --env-file .env.docker.example config`: passed with
  `postgres`, `repointel-facade`, `metadata-facade`, `gateway`,
  `analytics-provider`, and `szz-provider`.
- `docker compose --env-file .env.docker.example build`: passed for all local
  images.
- Generated facade image build bug found and fixed: the Docker dependency-cache
  stub could be copied into the runtime image when generated source mtimes were
  older than the stub binary. `Dockerfile` and `Dockerfile.repointel` now remove
  the exact local crate artifact/fingerprint before the final release build.
- Fresh-clone self-containment gap found and fixed after the first proof:
  Repointel generated source is now vendored in `generated/repointel/`,
  compose builds only from in-repo contexts, and image tags use
  `ghcr.io/tshephard-ca/repo-intel/...:${REPO_INTEL_IMAGE_TAG:-latest}` rather
  than `:local`.
- CI clean-room coverage added in `.github/workflows/compose-smoke.yml`:
  render compose config, build all images, start the stack, and probe gateway,
  Repointel health, and metadata health.
- Gateway product-auth boundary added after the first deployment proof:
  unauthenticated browser/API traffic is redirected or rejected, local bootstrap
  login creates a signed HttpOnly SameSite session cookie, unsafe API calls
  require CSRF, RBAC is enforced before proxying, and service bearer tokens are
  injected only by the gateway.
- Authenticated Docker gateway proof after rebuild: `127.0.0.1:18110` returned
  unauthenticated session metadata, rejected unauthenticated API calls with 401,
  redirected `/` to `/login`, accepted bootstrap admin login, returned
  administrator RBAC plus CSRF token from `/auth/session`, rejected unsafe API
  calls without CSRF, and proxied authenticated metadata health with gateway-held
  credentials.
- Browser credential stripping proof: metadata health with a bogus browser
  `Authorization` header still returned 200 through the gateway because the
  proxy replaces browser credentials with its internal scoped credential.
- Remote-access proof after rebuild: host `192.168.1.86` reached
  `http://192.168.1.86:18110/auth/session` and `/` on the published gateway
  port.
- Compose-owned Postgres became healthy and Repointel created
  `repointel_records` / `repointel_store_meta`.
- Repointel ingested local OpenStack Keystone from `/git/keystone` using the
  generated API. Bounded proof job
  `ingestion-job-6915b27cde5b03ea` completed with 25 raw records, 25 arts, and
  25 authors.
- Postgres row counts after proof included 50 raw records, 50 arts, 10 authors,
  2 ingestion jobs, 10 ingestion logs, 1 repository group, 1 repository, and 2
  sources.
- Metadata facade `/metadata-collection/console/config` returned
  `analyticsAvailable:true`.
- Metadata facade `/metadata-collection/console/repointel-analytics` returned
  analytics from the provider over the declared Frontplane `Ncall`.
- Metadata facade `/metadata-collection/szz-analyses:analyze-review` returned
  SZZ candidates for Keystone commit
  `a9d6832ae70cbd06dadbbaeb9d4b18a7553fca3b` over the declared
  `SzzAnalysisProvider` route.

Host-side `curl` from this sandbox could not connect to Docker-published proof
ports even though `docker compose ps` and `ss -ltnp` showed listeners. The proof
therefore used the gateway container as the probe client for the compose
network. Browser access should use the normal compose-published gateway port in
a host environment where Docker port publishing is reachable.

Required external input:

- Production or staging deployment target for the generated metadata-collection
  facade.
- Provider endpoints for `RepointelFacade`, `RepointelAnalyticsProvider`, and
  `SzzAnalysisProvider`.
- Secret injection path for metadata facade tokens, Repointel provider token,
  analytics provider token, SZZ provider token, gateway session secret, OIDC
  client secret, and bootstrap-admin break-glass credential.
- Approval to deploy or restart the affected services.

Required live proof after input is available:

- Build/version identifier for the deployed generated facade.
- Config presence check without exposing secret values.
- Live health or representative metadata facade request.
- Live analytics provider request through generated
  `/metadata-collection/console/...`.
- Live SZZ provider request through generated
  `/metadata-collection/szz-analyses:analyze-review` or
  `/metadata-collection/szz-analyses:analyze-batch`.
- Logs showing no immediate provider/auth/routing errors.
- Browser login flow proof with HTTPS-backed Secure session cookies.
- Rollback path for the deployed services.
