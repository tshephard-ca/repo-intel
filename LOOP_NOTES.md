# LOOP_NOTES

## Loop 1

- Focus: identify whether product API behavior remained outside Frontplane.
- Gaps found: Node product routes, analytics provider auth, role-word bearer auth,
  SZZ executable boundary, stale docs.
- Changes made: moved console/keyword/SZZ product behavior into `frontplane.fp`,
  declared analytics and SZZ provider calls, hardened auth, removed legacy
  analytics aliases, updated browser token behavior.
- Evidence: `frontplane check`, generator run, Rust tests, Node syntax checks,
  provider smoke tests.

## Loop 2

- Focus: challenge generic mission fit and hidden provider effects.
- Gaps found: SZZ defaulted to OpenStack/OpenDev, generic dictionaries included
  `keystone`, generic Gerrit UI defaults prefilled OpenDev, downstream-service
  health tests implied dynamic routing, SZZ provider wrote Repointel raw records
  directly.
- Changes made: SZZ now requires explicit selection or `params.all=true`, uses
  `REPOINTEL_GIT_ROOT` and `REPOINTEL_GERRIT_URL`, enriches candidate reviews
  without Repointel raw-record writes, generic dictionaries and UI defaults no
  longer bake in OpenStack/OpenDev, downstream-service health validation is
  explicit.
- Evidence: targeted `rg` scans and syntax checks.

## Loop 3

- Focus: align docs and audit artifacts with current implementation.
- Gaps found: `fix_to_fp.md` still described closed issues as remaining.
- Changes made: rewrote `fix_to_fp.md`, added `GAP_REGISTER.md`,
  `COMPLETION_AUDIT.md`, `DEPLOYMENT_GATE.md`, and
  `docs/state-ownership.md`.
- Evidence: final verification commands listed in `COMPLETION_AUDIT.md`.

## Loop 4

- Focus: remove browser-held service tokens and make the gateway a product
  authentication boundary.
- Gaps found: browser token inputs, token persistence in `localStorage`, raw
  call logging in ordinary workflows, unauthenticated gateway proxying, and no
  product RBAC before service calls.
- Changes made: added gateway sessions, OIDC login, bootstrap admin login, RBAC,
  CSRF checks, server-side scoped credential injection, a login page, and
  administrator-only debug diagnostics.
- Evidence: Node syntax checks, Compose config, and gateway curl smoke tests
  listed in `COMPLETION_AUDIT.md`.
