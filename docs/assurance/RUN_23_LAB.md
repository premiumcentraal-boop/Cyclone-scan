# Run 23 — revision-bound lab evidence recorder

    python -m tools.assurance.lab init lab.json
    python -m tools.assurance.lab record lab.json observation.json
    python -m tools.assurance.lab report lab.json --revision <git-sha> --apk-sha256 <apk-sha256>

The standard-library recorder validates a fixed privacy-bounded schema, appends observations
atomically, rejects duplicates/unknown fields, and separates synthetic fixtures from operator-reviewed
physical/emulator evidence. Summary statuses are PASS/FAIL/UNREVIEWED/NOT_RUN per declared case.
They are not independent attestations of operator honesty or proof of ground truth.

Case catalog includes clean manufacturers/TEE, dedicated unlocked/rooted configurations, own-app
instrumentation, re-signed builds, emulator/custom OS, service absence, legitimate accessibility/VPN/
remote support, repeat scans and biometrics. Existing host native tests supply controlled own-library
mutation evidence, but never masquerade as phone results. Do not modify an everyday phone for this
matrix. Use designated authorized lab devices/configurations only.

Required observation keys are defined in tools/assurance/lab.py. Anonymous device aliases only;
no serial/IMEI/account/token/raw maps. Hash an original diagnostic export separately if retaining
a source evidence reference. COMPLETE means the declared mandatory evidence for that scenario was
evaluated; it must not mean every part of a phone was inspected. Set expectation_met only after
reviewing the actual report against the case's written expectation. An expected offline/incomplete
result can meet its scenario while remaining unsuitable for accuracy calibration.

Current physical execution: BLOCKED. The available Cyclone Gateway reported DEVICE_DISCONNECTED.
No physical observations have been created. Reconnect a designated test device to collect them.
This run delivers recorder/tests and a case catalog, not a completed adversarial device matrix.
