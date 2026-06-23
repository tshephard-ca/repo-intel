# Git Line Survival Report

- Repo: `/media/tb/linux/home/tim/dev/openstack/swift`
- Branch: `master`
- Head: `f52988bb3f3bca035ea913643d71114d43ef43ac`
- Max changed lines scored: `100`
- Commits seen: `6528`
- Commits scored: `4779`
- Commits skipped by size: `1749`
- Authors scored: `505`
- Tracked insertions: `86351`
- Surviving lines: `48520`
- Overall line survival rate: `0.5619`
- Overall cross-author overwrite rate: `0.0611`

## Authors By Cross-Author Overwrite Rate

| Author | Commits | Insertions | Surviving | Cross-author overwritten | Survival rate | Cross-author overwrite rate |
|---|---:|---:|---:|---:|---:|---:|
| Nguyen Hai | 4 | 103 | 18 | 81 | 17.48% | 78.64% |
| Pradeep Kumar Singh | 3 | 105 | 60 | 33 | 57.14% | 31.43% |
| Minwoo B | 5 | 178 | 65 | 51 | 36.52% | 28.65% |
| Doug Hellmann | 3 | 104 | 69 | 26 | 66.35% | 25.00% |
| Clark Boylan | 4 | 100 | 77 | 21 | 77.00% | 21.00% |
| Chuck Thier | 88 | 653 | 89 | 122 | 13.63% | 18.68% |
| Monty Taylor | 32 | 359 | 49 | 67 | 13.65% | 18.66% |
| Jay S. Bryant | 4 | 118 | 74 | 21 | 62.71% | 17.80% |
| Alex Gaynor | 35 | 332 | 119 | 59 | 35.84% | 17.77% |
| Juan J. Martinez | 3 | 107 | 12 | 19 | 11.21% | 17.76% |
| Andreas Jaeger | 18 | 127 | 71 | 22 | 55.91% | 17.32% |
| janonymous | 26 | 305 | 133 | 48 | 43.61% | 15.74% |
| Fabien Boucher | 8 | 255 | 13 | 40 | 5.10% | 15.69% |
| Florian Hines | 13 | 305 | 120 | 42 | 39.34% | 13.77% |
| Bill Huber | 7 | 204 | 120 | 28 | 58.82% | 13.73% |
| gholt | 7 | 192 | 38 | 26 | 19.79% | 13.54% |
| Daisuke Morita | 5 | 193 | 134 | 25 | 69.43% | 12.95% |
| Anne Gentle | 28 | 334 | 67 | 43 | 20.06% | 12.87% |
| Mike Barton | 22 | 439 | 196 | 55 | 44.65% | 12.53% |
| Greg Lange | 6 | 116 | 10 | 14 | 8.62% | 12.07% |
| Sean McGinnis | 4 | 149 | 46 | 17 | 30.87% | 11.41% |
| David Goetz | 68 | 1038 | 200 | 117 | 19.27% | 11.27% |
| David Goetz | 27 | 441 | 82 | 49 | 18.59% | 11.11% |
| Michael Barton | 82 | 1068 | 72 | 118 | 6.74% | 11.05% |
| FUJITA Tomonori | 22 | 247 | 4 | 27 | 1.62% | 10.93% |

## Commits By Cross-Author Overwrite Rate

| Commit | Author | Changed lines | Insertions | Cross-author overwritten | Survival rate | Subject |
|---|---|---:|---:|---:|---:|---|
| `4f9a3a334278` | Matthew Oliver | 31 | 25 | 25 | 0.00% | Fixed links in multi-server Swift documentation |
| `0a993437d1dd` | Tim Burke | 22 | 11 | 11 | 0.00% | Update install-guide URLs to point to stable/queens |
| `a8b80f0727bc` | Thiago da Silva | 22 | 11 | 11 | 0.00% | update urls to newton |
| `1b0c11b68fe2` | Matthew Oliver | 20 | 10 | 10 | 0.00% | Updating the dockerhub secret (again^2) |
| `350f10bf3be9` | Christian Schwede | 65 | 10 | 10 | 0.00% | Deprecate swift-temp-url |
| `c0035ed82e52` | CY Chiang | 11 | 9 | 9 | 0.00% | Update the bandit.yaml available tests list |
| `29b8d2da20bb` | Kota Tsuyuzaki | 16 | 8 | 8 | 0.00% | Avoid docs warning: Duplicate explicit target name |
| `3f00148c6b35` | Nguyen Phuong An | 8 | 8 | 8 | 0.00% | Config logABug feature for Swift api-ref |
| `55ebda9d65b0` | FUJITA Tomonori | 28 | 8 | 8 | 0.00% | s3api: use boto to get canonical string for signature |
| `68cb91097b75` | Tom Fifield | 11 | 8 | 8 | 0.00% | docfix apache2 now supports client chunked encodin |
| `af91eea63424` | John Dickinson | 11 | 8 | 8 | 0.00% | use specific hacking rules |
| `b7659bee269d` | Clay Gerrard | 11 | 8 | 8 | 0.00% | Add --quoted option to swift-temp-url |
| `643476c3b082` | Colin Nicholson | 12 | 7 | 7 | 0.00% | changed domain_remap to handle multiple reseller prefixes |
| `652f0f9da408` | Pete Zaitcev | 7 | 7 | 7 | 0.00% | Having said H, I, J, we ought to say K |
| `2c2ede22338d` | Chuck Thier | 8 | 6 | 6 | 0.00% | Fix logging issue when services stop on py26 |
| `79222e327f9d` | ChangBo Guo(gcb) | 11 | 6 | 6 | 0.00% | Fix AttributeError for LogAdapter |
| `346f518d6cd1` | Alistair Coles | 15 | 5 | 5 | 0.00% | Make arm jobs voting (but not the pipeline) |
| `47346f6490d7` | Thierry Carrez | 7 | 5 | 5 | 0.00% | Add missing files in tarball |
| `f63b37572df9` | Peter Portante | 8 | 5 | 5 | 0.00% | Update callback with proper bytes transferred |
| `401311ff6a2a` | Tim Burke | 4 | 4 | 4 | 0.00% | Have py35 tox env match py34 |
| `615d90b80d9c` | Chris Wedgwood | 9 | 4 | 4 | 0.00% | Show account names in output strings. |
| `8c596c06fbb9` | gholt | 8 | 4 | 4 | 0.00% | consync: updated class docs |
| `c3c5e5a3975c` | Jay Payne | 6 | 4 | 4 | 0.00% | Commit out the both calls |
| `d5ff5447be30` | Samuel Merritt | 6 | 4 | 4 | 0.00% | Install liberasurecode packages in SAIO. |
| `e56832c138bc` | Ilya Kharin | 8 | 4 | 4 | 0.00% | Fix format device |
