# Cyclone Scan parallel build status

Baseline: Run 13 native-integrity branch, commit d4667c169a3f1fc2475be940390ec69429c92b06.
These changes are additive review branches. They are not merged into main or released.

## Purpose
Build an affordable, understandable device-integrity SDK and scanner APK for developers.
The phone gathers evidence; the customer's server verifies evidence and applies policy.
The product should distinguish verified facts, weak signals, unavailable checks and
unmeasured claims so developers can protect customers without avoidable lockouts.
No check proves an entire phone is free of compromise. The APK operates within Android's
permissions and its own process. It does not inspect private data in other apps.

## Independent Codex implementation
| Run | Implemented | Remaining evidence |
| --- | --- | --- |
| 20 | Exact-byte signed enrollment transcript, Play request-hash binding, strict JSON, migration policy, cross-language test vector | Live Google/device exercise and protocol review |
| 21 | Own ELF executable-segment SHA-256 baseline, mapping checks, host byte/permission modification fixture, ABI checks | Physical multi-device behavior, race and crash assessment |
| 22 | Atomic minimal attestation snapshots, signed/reported provenance, conservative rollback comparisons | Claude lifecycle integration and real update/re-attestation exercises |
| 23 | Bounded anonymous lab recorder, exact revision/APK filtering, explicit not-run/failed states | Physical test matrix; no physical observations currently available |
| 24 | Offline policy proxy, distinct device counts, intervention/miss rates, descriptive intervals and latency | Representative reviewed dataset and approved acceptance criteria |
| 25 | Artifact manifest, fail-closed beta checklist, required review evidence and CI integration | Stable signing, live verification, Claude integration and human release review |

PR stack: Run20 #7 -> Run21 #9 -> Run22 #10 -> Run23 #11 -> Run24 #12 -> Run25.
Run20 bases on Run13. Claude's Run14 branch/PR #8 is separate.
All detector output retains its existing signal schema and trust limitations.
Run22 deliberately adds no competing key-rotation or re-attestation endpoint.

## Coordination with Claude
Runs 14–19 remain Claude-owned. Integrate the completed branches together on a separate
integration branch, resolve model/schema changes deliberately and rerun the whole suite.
The beta checklist specifically requires attestation compatibility, device lifecycle,
live Google verification, approved stable signing, privacy and dependency-license reviews.
Do not report those gates as passed because this independent stack compiles.
Signing/version changes and scanner report presentation remain integration concerns;
there is no claim that the scanner UI was redesigned in this stack.

## First beta acceptance sequence
1. Review and integrate both branch stacks; resolve conflicts and verify shared Python/Kotlin vectors.
2. Build the actual candidate APK with approved stable signing; retain CI and artifact evidence.
3. Record that APK's exact hash and actual tested revision from the attached manifest.
4. Run the physical matrix, including legitimate accessibility/VPN/support and no-GMS/offline fallbacks.
5. Review a representative labelled dataset, performance and false positives; approve policy limits.
6. Run the beta checklist, review underlying evidence and approve a limited beta distribution.

Until those dependencies are met, status is implementation ready for review with
physical testing, calibration and release approval outstanding.
