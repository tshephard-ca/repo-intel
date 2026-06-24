# Fix To FP

Audit updated on 2026-06-23 after the Frontplane mission cleanup.

## Standard

- `../../mission_statement`: "Frontplane (FP) provides an IDL to quickly create a zero trust facade API that securely stitches together cloud products and services without having to expose them externally."
- `../../README.md`: "The core invariant is that outbound REST is part of the FP layer, not hidden runtime code."
- `MISSION.md`: "Stay generic across repositories and ecosystems; resist overfitting."

## Current Result

The repo now follows the Frontplane direction much more closely:

- Browser-facing product behavior is declared in `frontplane.fp`.
- The Node gateway is static/proxy infrastructure in normal mode.
- SQL-heavy console analytics run behind declared `RepointelAnalyticsProvider.*` REST provider calls.
- SZZ analysis runs behind declared `SzzAnalysisProvider.*` REST provider calls.
- Provider routes require explicit shared bearer tokens.
- The metadata facade rejects role-name bearer tokens such as `reader`, `writer`, and `admin`.
- The browser no longer holds, stores, or sends service bearer tokens.
- The gateway authenticates users with OIDC or a bootstrap administrator login,
  issues an HttpOnly SameSite session cookie, enforces product RBAC, and injects
  scoped internal credentials when proxying to facades/providers.
- OpenStack/Swift/OpenDev behavior is optional example configuration, not the generic default SZZ provider behavior.

## Gap Register

| ID | Mission phrase/source | Previous gap | Current state | Status |
| --- | --- | --- | --- | --- |
| FP-01 | "IDL to quickly create a zero trust facade API" and user instruction: all APIs should be in Frontplane | Product routes were split between `frontplane.fp` and Node. | `ConsoleReports`, `KeywordConfigs`, and `SzzAnalyses` are in `frontplane.fp`; browser calls use `/api/metadata/...`; Node normal mode serves static files and same-origin proxy paths. | Closed |
| FP-02 | "outbound REST is part of the FP layer, not hidden runtime code" | Analytics SQL routes were hidden Node product API. | `RepointelAnalyticsProvider.*` is declared as REST and invoked with generated `Ncall` steps; provider mode is separate from gateway mode. | Closed |
| FP-03 | "zero trust facade API" / "securely stitches together" | Auth accepted literal role-name bearer tokens. | The backing runtime requires an explicit token registry and rejects role-word tokens; provider tokens are explicit env config. | Closed |
| FP-04 | "outbound REST is part of the FP layer" | SZZ was a facade-local executable call that hid provider effects. | SZZ product actions now call `SzzAnalysisProvider.*` through generated `Ncall` steps. The provider no longer writes Gerrit backfill rows directly into Repointel records. | Closed |
| FP-05 | "securely stitches together cloud products and services" | Downstream service catalog implied dynamic routing that generated provider config did not use. | `test-connection` now validates that the saved row maps to the declared `RepointelFacade.health` edge before the `Ncall`; docs state provider routing is configured through generated endpoint settings. | Closed |
| FP-06 | User instruction: all APIs should be done in Frontplane | Local facade coordination state was undocumented. | `docs/state-ownership.md` documents which records are facade-owned coordination state and which records remain Repointel-owned provider state. | Closed |
| FP-07 | "Stay generic across repositories and ecosystems; resist overfitting." | SZZ defaulted to an OpenStack checkout, OpenDev Gerrit, and OpenStack-only review selection; seeded component rules included `keystone`. | SZZ uses `REPOINTEL_GIT_ROOT`, requires `REPOINTEL_GERRIT_URL` for Gerrit enrichment, requires an explicit selector or `params.all=true`, and generic dictionaries no longer include `keystone`. Generic Gerrit source defaults no longer prefill OpenDev. | Closed |
| FP-08 | "IDL" and "outbound REST is part of the FP layer" | Provider declarations used broad shapes. | Provider declarations are all in the main IDL and key downstream record shapes are typed. A separate `providers.fp` split is not required for the current generator path. | Not required |
| FP-09 | "telemetry, and audits can inspect it" from `../../README.md` | Downstream trace rows fabricated `200` for generated calls whose runtime status was unavailable to backing code. | Synthetic trace rows now use `status_code = 0` with an explicit "provider status/duration unavailable" message. Real health-test traces still record the actual successful provider result. | Closed |
| FP-13 | "zero trust facade API" / "without having to expose them externally" and user instruction: secure session cookie, OIDC, bootstrap admin, RBAC | Browser workflows collected service tokens, persisted config in `localStorage`, and sent bearer tokens directly to backend services. | `ux/server.mjs` is now a backend-for-frontend auth boundary: OIDC plus bootstrap admin login, signed sessions, HttpOnly SameSite cookies with configurable `Secure`, RBAC, CSRF, stripped browser credentials, and internal scoped service credentials. `ux/app.js` no longer persists or sends service tokens; `/debug` is administrator-only. | Closed |

## Runtime Shape

The intended local runtime is now:

1. `frontplane.fp` is the product API contract.
2. Generated Rust handles metadata-collection routes, authz, flow steps, provider calls, and manifests.
3. Node normal mode serves UI assets, authenticates product users, enforces RBAC,
   and proxies `/api/repointel/*` and `/api/metadata/*` with server-held
   credentials.
4. Node `--analytics-provider` mode is an internal provider for declared analytics calls.
5. `tools/szz_frontplane_analyze.py --provider` is an internal provider for declared SZZ calls.
6. Repointel remains owner of repositories, sources, raw records, arts, authors, metadata, and relationships.

## Verification To Keep Running

```bash
../../target/debug/frontplane check frontplane.fp
../../target/debug/frontplane generate --input frontplane.fp --out generated
cargo fmt --manifest-path generated/Cargo.toml
cargo test --manifest-path generated/Cargo.toml
node --check ux/server.mjs
node --check ux/app.js
python3 -m py_compile tools/szz_frontplane_analyze.py
docker compose --env-file .env.docker.example config
```

## Production Gate

Local mission cleanup is implemented and locally verifiable. Production closure
still requires a deployment target, live provider endpoints, secret injection
for metadata/provider/Repointel tokens, gateway session/OIDC secrets, HTTPS
cookie proof, and a live smoke test against the deployed facade.
