# Run 13 — native integrity evidence

Base: run-12-fleet-intelligence, f12704459b0535022b84957ea357f507e266c2d8.
Scanner: 0.6.0 (versionCode 3). Physical device: UNVERIFIED.

## Delivered

libdtnative packages arm64-v8a, armeabi-v7a and x86_64 in one APK. A single JNI call reports fixed root artifacts, own-process mounts/maps/TracerPid, accessible SELinux enforcement and changes to the first 16 bytes of three SDK-owned functions since JNI_OnLoad. File operations enter the kernel directly on each supported ABI. There are no sockets, writes, other-process reads, exploitation or attempts to disable anything.

Each native check has DETECTED, NOT_DETECTED, UNAVAILABLE or UNSUPPORTED status. Missing library, denied/malformed/truncated reads and allocation failures do not imply safety. Kotlin collection survives library-load/JNI errors. Memory reads are bounded to known owned functions whose sizes CI checks; no process-wide signal handlers or untrusted address probes are installed.

Native and Kotlin evidence is preserved separately. Maps-based Frida/Xposed/Zygisk and TracerPid are comparable only if independent Kotlin snapshots before/after native collection are stable. Java-only classes, stack frames, loopback ports and artifact checks without reliable Kotlin availability are excluded. A race wholly inside those snapshots remains possible; client evidence is low trust.

The server accepts the new version-1 additive schema with strict native state/type consistency. Overlapping checks produce the existing factor once, regardless of which collector detected it. New configurable factors are native_selinux_permissive (20), native_code_modified (60), native_kotlin_mismatch (40). These are experimental weights, not measured fraud probabilities. The shared Python/Kotlin vectors exercise native-only hits, agreement, unavailable evidence and score capping.

The scanner shows native results beside comparable Kotlin observations and exports coverage flags. A local green result no longer claims banking approval or official APK authenticity. Unavailable revocations and unallowlisted SELF_SIGNED boot fail local gates rather than silently producing a clean diagnostic.

Trusted attestation-key/cohort history now requires a fresh successful attestation. Invalid action signatures record action_attempt without a device identity, so they cannot inflate the many-devices signal. Failed enrollment network attempts still count by design; gateway rate limiting remains necessary.

## Limits and deferred work

The runtime baseline covers selected owned code, not every byte of the ELF/APK. It detects changes after load; already-modified initial code, modified comparators or a hostile kernel can evade it. App upgrades receive a new baseline; none is persisted across installs. Direct syscalls improve diversity, not cryptographic trust.

Fixed path probes are limited to known root artifacts; inaccessible paths are normal under Android sandboxing. The existing Kotlin loopback Frida probe is unchanged and is not reproduced in native.

The confirm-key boot/model comparisons do not prove that two keys live on one physical phone. The comment now states this narrower guarantee; a new pairing protocol is deferred. STEP_UP approval/account/tenant ownership, re-attestation, production stores/limits, official release signing, certificate-extension/legacy-validity compatibility and RKP topology generalization remain follow-up work. This is not a banking-ready deployment.

## Validation

CI runs the existing Python suite, SDK and scanner JVM tests, SDK lint and release assembly, plus native C host tests with ASan/UBSan, raw syscall smoke tests, all nine detector-disable mutations, APK ABI inspection and owned-code size checks. Native host tests call the actual C logic through a read-only probe seam; JVM tests cover aggregation, availability and parity. Shared vectors must be regenerated with:

    python testvectors/generate_risk_vectors.py

Native checks on a real Android phone, biometrics and live Play Integrity are UNVERIFIED. Run the clean/adversarial device matrix before customer enforcement. No test result should be inferred solely from this document; use the PR's latest CI evidence.
