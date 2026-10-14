# Run 25: evidence-based beta review
Status: offline tooling implemented; distribution and production approval remain blocked.

Cyclone Scan helps app developers understand device integrity using hardware-signed facts,
Google verification and lower-trust on-device observations. Clear limits and reproducible
evidence make the product useful to small teams without promising impossible visibility.
An ordinary Android APK cannot inspect every other app or prove absence of compromise.
Native checks add independent observations; they do not create a trusted execution boundary.

## Candidate identity
CI attaches scanner-assurance-manifest.json beside the APK. It hashes the exact APK and
records the actual checked-out revision. A PR workflow commonly builds a synthetic merge
revision: use that tested revision for lab observations, not an assumed branch-head SHA.
The manifest deliberately reports signer verification as UNVERIFIED. A hash does not verify
a signer, an approved distribution key, Play recognition, or provenance by itself.
The current scanner uses test/debug signing until the signing work is independently verified.

Manual command:
```sh
python -m tools.assurance.artifact_manifest scanner.apk --revision ACTUAL_TESTED_40_HEX_REVISION
python -m tools.assurance.lab init lab.json
python -m tools.assurance.lab record lab.json observation.json
python -m tools.assurance.beta_gate lab.json review.json
```

## Review document
Strict schema 1 fields: revision, apk_sha256, approvals, policy.
Each approval is exactly {status, evidence_sha256}; status is PASS, FAIL or UNVERIFIED.
PASS requires the SHA-256 of an independently retained review evidence document.
Required approval keys are defined in beta_gate.APPROVALS: candidate_ci,
integrated_claude_runs, attestation_compatibility, device_lifecycle,
live_google_verification, stable_signing, protocol_review, privacy_retention,
dependency_licenses. All apply to the exact revision and APK named in this review.
Reviewers must verify each referenced document and its candidate identity outside this CLI.
Arbitrary declarations or hashes cannot authenticate evidence.

Policy fields are exactly: reviewed (boolean), allow_below, block_at (integers),
max_clean_intervention, max_altered_miss (rates 0..1), max_p95_ms (positive integer).
The reviewer must approve these acceptance limits before testing; the gate supplies no
production acceptance-rate or latency defaults. Score boundaries describe an offline proxy.
They do not replace backend action policy or alter production weights.

## Fail-closed decision
The gate recomputes lab coverage, accuracy and latency from validated raw observations.
Every defined lab case needs reviewed PHYSICAL evidence, except the emulator case,
which needs EMULATOR evidence. Synthetic fixtures cannot satisfy these gates.
Missing evidence, unknown approvals and inadequate sample size produce NO_GO.
Any declared non-synthetic crash in the selected candidate blocks review, including
unreviewed crash reports. A failed case remains visible even if another scan passes.

The pilot minimum is five clean-device aliases and three altered-device aliases.
These small, operator-declared samples are prerequisites for review, not statistical
assurance of production safety. Metrics include descriptive confidence intervals.
Operators must preserve stable anonymous aliases and document legitimate custom OS,
accessibility, VPN and authorized support configurations without labelling them malicious.

Exit 0 means READY_FOR_HUMAN_REVIEW. Exit 1 means NO_GO; exit 2 means invalid input.
All-pass does not publish, sign, merge or certify an APK. Approval records are declarations;
a malicious operator can fabricate them. Human review and trusted CI/signing systems
remain the release authority. Do not use this offline checklist as a server security boundary.

## Actual verification
The unit tests use explicitly synthetic in-memory fixtures to exercise both pass and
failure paths. No physical-device pass, live Google result, calibration dataset or release
approval has been manufactured. The connected-phone gateway returned DEVICE_DISCONNECTED.
Real-device tests and Claude-run integration are outstanding dependencies.
