# Run 22 — evidence provenance and history assurance

Preserves the hardware-attested verified-boot hash in service evidence (bounded to 64 bytes).
Successful registration stores a versioned minimal measurement snapshot atomically with the
device. Snapshot key identity must match the public key being registered. No raw token, IP,
action parameters, signal report or permanent phone identifiers are added.

The pure comparison library labels attested/reported sources separately, flags signed identity,
boot and patch regressions for REVIEW, and treats boot-image changes alone as informational:
legitimate updates change them. Patch precision differences do not invent day-level rollback.
Missing/invalid patch fields produce comparison-unavailable findings. A different public key
returns KEY_CONTINUITY_UNVERIFIED, never “same phone” based on model/boot properties.

Claude Run 17 owns the live refresh and authorized continuity protocol. This branch supplies its
comparison primitive and initial enrollment snapshots, not an externally callable re-attestation
or rotation endpoint. Do not record a purported refresh until that protocol has independently
validated freshness and continuity. No automatic new block factors or weights are introduced.
Current factory/RKP classification remains heuristic and subject to Claude Run 15's compatibility
work; neither it nor these comparisons guarantees detection of every shared/leaked key.
