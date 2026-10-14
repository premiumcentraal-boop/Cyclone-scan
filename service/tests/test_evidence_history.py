"""Run 22: signed-vs-reported sources and conservative history interpretation."""
import copy
import dataclasses
import pytest
from device_trust.evidence_history import compare, identity_sources, snapshot
from test_actions import Env

def baseline():
    return {"v": 1, "leaf_spki_sha256": "ab"*32, "device_locked": True,
            "verified_boot_state": "VERIFIED", "verified_boot_key_sha256": "cd"*32,
            "verified_boot_hash": "ef"*32, "os_patch_level": 202610,
            "vendor_patch_level": 20261005, "boot_patch_level": 20261005,
            "attested_ids": {"brand": "test", "model": "test-phone"}}

def test_identity_source_never_promotes_reported_model():
    result = identity_sources({}, {"model": "Pixel 9"})
    assert result["model"] == {"attested": None, "reported": "Pixel 9", "source": "REPORTED_ONLY"}

def test_new_key_is_not_assumed_same_phone():
    old, new = baseline(), baseline()
    new["leaf_spki_sha256"] = "00"*32
    assert compare(old,new) == [{"code": "KEY_CONTINUITY_UNVERIFIED", "level": "REVIEW", "field": "leaf_spki_sha256"}]

def test_expected_update_hash_change_is_informational():
    old,new=baseline(),baseline()
    new.update(os_patch_level=202611, verified_boot_hash="00"*32)
    assert compare(old,new) == [{"code":"BOOT_IMAGE_CHANGED","level":"INFO","field":"verified_boot_hash"}]

@pytest.mark.parametrize("field,value", [
    ("os_patch_level",202609), ("vendor_patch_level",20261001), ("boot_patch_level",20250901),
])
def test_patch_regression(field,value):
    old,new=baseline(),baseline();new[field]=value
    assert any(f["code"]=="PATCH_REGRESSION" and f["field"]==field for f in compare(old,new))

def test_patch_precision_and_missing_fields_do_not_manufacture_regression():
    old,new=baseline(),baseline()
    new["vendor_patch_level"]=202610
    new["boot_patch_level"]=None
    findings=compare(old,new)
    assert not any(f["code"]=="PATCH_REGRESSION" for f in findings)
    assert any(f["code"]=="PATCH_COMPARISON_UNAVAILABLE" for f in findings)

def test_identity_and_boot_changes_are_review_signals():
    old,new=baseline(),baseline()
    new["device_locked"]=False
    new["attested_ids"]={"brand":"test","model":"different"}
    assert {f["code"] for f in compare(old,new)} == {"BOOT_EVIDENCE_CHANGED","ATTESTED_IDENTITY_CHANGED"}

def test_verified_enrollment_creates_minimal_snapshot(policy):
    env=Env(policy);phone=env.phone()
    history=env.registry.assurance_history(phone.device_id)
    assert len(history)==1
    ev=history[0]["evidence"]
    assert ev["v"]==1 and "leaf_spki_sha256" in ev
    assert not {"signals","play_integrity_token","client_ip","params","serial","imei"} & set(ev)

def test_snapshot_rejects_substituted_key(policy):
    env=Env(policy);phone=env.phone()
    from device_trust.attestation import AttestationEvidence
    evidence=AttestationEvidence(**env.registry.get(phone.device_id).evidence)
    with pytest.raises(ValueError):
        snapshot(evidence,b"substituted-public-key")


def test_snapshot_records_verifier_metadata_and_old_snapshots_stay_comparable(policy):
    """Integration of Runs 15 and 22: additive v1 metadata; older snapshots lack it (unknown)."""
    from attestation_factory import DEVICE_IDS, NOW, make_chain
    from device_trust.attestation import AttestationVerifier
    from device_trust.evidence_history import VERIFIER_RULESET
    from device_trust.revocation import RevocationList
    from device_trust.roots import RootStore
    chain, pki, _ = make_chain()
    result = AttestationVerifier(policy, RootStore([pki.root]), RevocationList.static({})).verify(
        chain, b"challenge", DEVICE_IDS, now=NOW)
    snap = snapshot(result.evidence, result.leaf_public_key_spki)
    assert snap["v"] == 1
    assert snap["verifier_ruleset"] == VERIFIER_RULESET
    assert snap["legacy_validity_exemption"] is False
    old = {k: v for k, v in snap.items() if k not in ("verifier_ruleset", "legacy_validity_exemption")}
    assert compare(old, snap) == compare(snap, snap)
