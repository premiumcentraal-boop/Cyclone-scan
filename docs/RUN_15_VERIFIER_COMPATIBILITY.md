# Run 15 — Verifier compatibility and reference fixtures

Base: `run-14-report-coverage`, `63fd3bdaf47286359db4c005f4cce0372292e594` (PR #8, marked ready for review by the owner's instruction on 15 October 2026; not merged).
Branch: `run-15-verifier-compatibility`. Physical device: UNVERIFIED.

## Review sources

- Android developers, *Verify hardware-backed key pairs with key attestation* (developer.android.com/privacy-and-security/security-key-attestation, last updated 2026-07-09).
- Google's reference verifier `android/keyattestation` at commit `621149c4ebaeeea844d6f43098687c73c4d370a3` (the same commit our public fixtures come from): `KeyAttestationCertPath.kt`, `KeyAttestationCertPathValidator.kt`, `ConstraintConfig.kt`, `roots.json`.

## Findings and decisions

| Topic | Before | Guidance | Run 15 |
|---|---|---|---|
| Which certificate carries trusted attestation data | Leaf only; any other KeyDescription rejected | Docs: only the occurrence nearest the root is trustworthy; don't assume the leaf. Reference: target (leaf) only, any other occurrence rejected, ATTEST_KEY not supported | Unchanged rule (equals the reference). Documented that ATTEST_KEY chains are unsupported and rejected as `ATTESTATION_EXTENSION_MISPLACED`. |
| Provisioning-information extension | Ignored | Docs: if present, the KeyDescription must be in the immediately following certificate | New hard reason `PROVISIONING_INFO_MISPLACED` unless it is exactly on the certificate above the leaf. |
| Expired certificates in legacy factory chains | Every non-leaf certificate enforced → genuine older phones rejected | Docs: keep trusting chains to the RSA root `f92009e853b6b045` regardless of validity unless revoked; RKP validity must be checked. Reference: ignore expiry on factory chains only | Exemption only for a recognized FACTORY chain under that RSA root, expiry only (never not-yet-valid), revocation still checked. Policy `legacy_factory_validity_exemption` (default on). Reported as warning `LEGACY_FACTORY_VALIDITY_EXEMPT` and `evidence.legacy_validity_exemption`. |
| Chain provenance | RKP if exact Droid CA shape, otherwise silently FACTORY | Reference: FACTORY if the certificate under the root has a serialNumber, RKP if it is Droid CA2, else UNKNOWN | RKP (exact 5-certificate Droid CA shape), FACTORY (exact 4-certificate shape, serialNumber intermediate, no provisioning info), otherwise `UNRECOGNIZED` with warning `ATTESTATION_CHAIN_UNRECOGNIZED`. |
| Security level vs chain | Not compared | Reference `MATCHES_CERTIFICATE`: StrongBox keys need a StrongBox chain claim; TEE keys accept a TEE or no claim | New hard reason `SECURITY_LEVEL_CHAIN_MISMATCH` for recognized chain forms. |
| Enrolled public key | Leaf SPKI | The attested key is the one in the certificate carrying the KeyDescription | Unchanged; with the leaf-only rule the enrolled key is exactly the attested key. Regression test added. |
| Trust roots | RSA root + "Key Attestation CA1" | Docs and reference `roots.json`: the same two | Unchanged. Test asserts the two documented roots; keys match the reference `roots.json`. Update procedure stays `device-trust refresh-roots` plus review. |
| Revocation | Every certificate, any listed status | Docs: check each certificate; REVOKED or SUSPENDED | Unchanged (any listed entry fails closed); exempted legacy chains are still revocation-checked. |

**Reproduced before fixing:** the public Sony Xperia 10 III factory chain, verified as of 14 October 2026, returned `CERT_EXPIRED` — a genuine device rejected only because its factory certificates expired in May 2026. It now passes with the documented exemption; the public RKP chains of the same age still fail `CERT_EXPIRED`, as they must.

**Scores.** No weight changed. An `UNRECOGNIZED` chain keeps the same "not RKP" provenance factors that applied when it was labelled FACTORY (new shared vector `unrecognized_chain_on_pixel`, 60 risk vectors). The label change only stops calling it a factory keybox.

## Python/Kotlin parity

`testvectors/attestation_vectors.json` (14 cases: 7 public Google chains, each at capture time and on 14 October 2026) records the server verifier's chain form, validity, legacy exemption, security-level and placement outcomes. The scanner's `ChainVerifier` is tested against the same file (`AttestationVectorsTest`), mirrors the new checks (`provisioning_info`, `security_chain`, legacy validity detail, UNRECOGNIZED provenance) and `LocalRisk` keeps the same provenance-factor rule.

## Tests

- Python `test_verifier_compat.py`: chain-form classification of every public fixture, legacy exemption on/off, in-date factory without exemption, expired RKP rejected, not-yet-valid never exempt, revoked legacy chain rejected, enrolled key = attested leaf key, synthetic 4-certificate factory chain, exemption requires Google's RSA root and the factory form, StrongBox claim mismatch, misplaced provisioning info, second KeyDescription rejected, reference rule table, roots, risk-factor invariance.
- Python `test_attestation_vectors.py`: parity file is current.
- Existing tests updated where they asserted the old silent FACTORY label (now UNRECOGNIZED) and where synthetic 3-certificate test chains now carry the unrecognized-form warning.

## Limits

- ATTEST_KEY chains remain unsupported (as in the reference). Supporting them needs a reviewed design for which key is enrolled.
- Factory chains with more or fewer than four certificates are UNRECOGNIZED: accepted as before but without the legacy exemption, so expired ones still fail. Real-device data may show OEM shapes worth adding deliberately.
- Kotlin decodes certificate names through `X500Principal.getName(RFC2253, oidMap)` with a fallback for hex-encoded values; this is exercised by JVM tests on desktop Java, not yet on an Android device.
- No new fixtures were sourced: there is no public ATTEST_KEY, StrongBox factory or revoked real chain in the reference test data, so those paths use synthetic chains.
