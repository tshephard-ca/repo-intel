# Git Line Survival Report

- Repo: `/media/tb/linux/home/tim/dev/openstack/swift`
- Branch: `master`
- Head: `f52988bb3f3bca035ea913643d71114d43ef43ac`
- Since: `2025-06-06T00:00:00+00:00`
- Max changed lines scored: `100`
- Commits replayed: `6528`
- Commits in window: `216`
- Commits scored: `157`
- Commits skipped by size: `59`
- Authors scored: `21`
- Tracked insertions: `3190`
- Surviving lines: `2962`
- Overall line survival rate: `0.9285`
- Overall cross-author overwrite rate: `0.0367`

## Authors By Cross-Author Overwrite Rate

| Author | Commits | Insertions | Surviving | Cross-author overwritten | Survival rate | Cross-author overwrite rate |
|---|---:|---:|---:|---:|---:|---:|
| ashnair | 1 | 47 | 5 | 42 | 10.64% | 89.36% |
| Matthew Oliver | 8 | 222 | 177 | 30 | 79.73% | 13.51% |
| Samuel Merritt | 1 | 31 | 27 | 3 | 87.10% | 9.68% |
| Wael Halbawi | 3 | 217 | 205 | 12 | 94.47% | 5.53% |
| Tim Burke | 46 | 578 | 533 | 17 | 92.21% | 2.94% |
| Alistair Coles | 50 | 1147 | 1083 | 11 | 94.42% | 0.96% |
| Clay Gerrard | 19 | 424 | 415 | 2 | 97.88% | 0.47% |
| Christian Ohanaja | 4 | 138 | 138 | 0 | 100.00% | 0.00% |
| John Dickinson | 4 | 124 | 124 | 0 | 100.00% | 0.00% |
| Yan Xiao | 1 | 80 | 80 | 0 | 100.00% | 0.00% |
| Christian Schwede | 1 | 40 | 40 | 0 | 100.00% | 0.00% |
| Christian Schwede | 4 | 35 | 31 | 0 | 88.57% | 0.00% |
| Takashi Kajinami | 5 | 33 | 30 | 0 | 90.91% | 0.00% |
| Nathaniel Martes | 1 | 26 | 26 | 0 | 100.00% | 0.00% |
| OpenStack Release Bot | 3 | 15 | 15 | 0 | 100.00% | 0.00% |
| Matthew Allen | 1 | 14 | 14 | 0 | 100.00% | 0.00% |
| Ade Lee | 1 | 13 | 13 | 0 | 100.00% | 0.00% |

## Commits By Cross-Author Overwrite Rate

| Commit | Author | Changed lines | Insertions | Cross-author overwritten | Survival rate | Subject |
|---|---|---:|---:|---:|---:|---|
| `1b0c11b68fe2` | Matthew Oliver | 20 | 10 | 10 | 0.00% | Updating the dockerhub secret (again^2) |
| `7f3e761295fd` | Alistair Coles | 1 | 1 | 1 | 0.00% | zuul: run py3.13 unit tests in the gate |
| `d353f15fac3a` | ashnair | 50 | 47 | 42 | 10.64% | account-broker: add resilient path property with lazy cache |
| `9b52363394c5` | Tim Burke | 23 | 12 | 10 | 0.00% | CI: Update dockerhub secret (again) |
| `41376fca5d9e` | Tim Burke | 18 | 9 | 4 | 55.56% | trivial: Use swob date-header helpers more |
| `3123422cdf46` | Matthew Oliver | 9 | 5 | 2 | 60.00% | test_relinker: cleanup Timestamp usage |
| `0862c231a28b` | Matthew Oliver | 54 | 52 | 16 | 67.31% | Recliam db_dir/*.tmp files |
| `74274ec8bccc` | Alistair Coles | 53 | 37 | 10 | 72.97% | checksum.py: fail gracefully if pyeclib is broken |
| `ee4237795d7e` | Wael Halbawi | 92 | 89 | 12 | 86.52% | relinker: Test cleaning up consecutive hashes in same suffix directory |
| `7b05356bd0bb` | Clay Gerrard | 25 | 16 | 2 | 56.25% | test: do not create timestamp collision unnecessarily |
| `5568dd09b5d1` | Samuel Merritt | 33 | 31 | 3 | 87.10% | Fix swift_dir setting in WSGI servers |
| `694d25bb1a87` | Tim Burke | 35 | 24 | 2 | 91.67% | Improved offset support in Timestamp.__invert__ |
| `9abd8ae71ec3` | Matthew Oliver | 63 | 47 | 2 | 95.74% | sharder: use correct Timestamp formats |
| `397f94c73bbf` | Tim Burke | 96 | 91 | 1 | 98.90% | diskfile: Fix UnboundLocalError during part power increase |
| `005d69d1a9f3` | Takashi Kajinami | 13 | 0 | 0 | 0.00% | Drop remaining skip check for Python < 3 |
| `02bc7e448033` | Alistair Coles | 42 | 24 | 0 | 87.50% | tests: pass Timestamps to date_header_format |
| `06a6329793de` | Christian Schwede | 90 | 40 | 0 | 100.00% | Fix recursion error in account_quota middleware |
| `06c182145163` | Alistair Coles | 1 | 0 | 0 | 0.00% | trivial: remove print statement in relinker unit test |
| `08f1eb9c9fdd` | Tim Burke | 9 | 9 | 0 | 100.00% | Fix rolling upgrade jobs |
| `0ab7285d14de` | Alistair Coles | 33 | 18 | 0 | 100.00% | test_relinker: simplify helper methods |
| `0ceff0fd5f43` | Alistair Coles | 56 | 40 | 0 | 82.50% | test_base.py: tighten up use of Timestamp |
| `0da44e9ea2ea` | Christian Schwede | 19 | 19 | 0 | 100.00% | s3api: Add functional test for aws-chunked truncation bug |
| `0f23c3a97d76` | Tim Burke | 5 | 2 | 0 | 100.00% | tests: Fix test_dry_run_and_yes_is_invalid on py314 |
| `111aca75ba15` | John Dickinson | 20 | 18 | 0 | 100.00% | Reject oversized chunked SLO manifests |
| `15a1c028728c` | Tim Burke | 9 | 8 | 0 | 100.00% | Update rolling-upgrade jobs |
| `1698fc324895` | Alistair Coles | 75 | 41 | 0 | 95.12% | OldestAsyncPendingTracker accepts Timestamp.internal |
| `18b861bd6ce4` | Alistair Coles | 12 | 8 | 0 | 100.00% | obj test_expirer.py and test_auditor.py: fix timestamp usage |
| `21325988dfe7` | Tim Burke | 14 | 0 | 0 | 0.00% | CI: Remove a bunch of unnecessary bindep profiles |
| `22605d21ee9c` | Alistair Coles | 81 | 43 | 0 | 93.02% | cli/test_info.py: cleanup Timestamp usage |
| `2ab76f7e07ef` | Tim Burke | 12 | 6 | 0 | 100.00% | trivial: Fix some typos |
