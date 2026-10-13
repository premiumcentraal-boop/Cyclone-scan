import json

import pytest
from attestation_factory import explicit, integer, octets, seq

from device_trust.der import DerError, read_single
from device_trust.key_description import parse_key_description
from device_trust.revocation import RevocationList, RevocationUnavailable, serial_key


def test_high_tag_numbers_roundtrip():
    tlv = read_single(explicit(718, integer(20260905)))
    assert tlv.cls == 2 and tlv.tag == 718
    assert read_single(tlv.value).as_int() == 20260905


@pytest.mark.parametrize(
    "data",
    [b"", b"\x30", b"\x30\x05\x02\x01", b"\x30\x00\x00", b"\x04\x84\xff\xff\xff\xff", b"\xbf\x80\x80\x80\x80\x80"],
)
def test_malformed_der_raises(data):
    with pytest.raises(DerError):
        read_single(data)


@pytest.mark.parametrize("raw, expected", [(b"\x01\x01\xff", True), (b"\x01\x01\x00", False)])
def test_der_boolean(raw, expected):
    assert read_single(raw).as_bool() is expected


@pytest.mark.parametrize("raw", [b"\x01\x01\x01", b"\x01\x02\xff\xff", b"\x01\x00"])
def test_non_der_boolean_rejected(raw):
    with pytest.raises(DerError):
        read_single(raw).as_bool()


def test_key_description_rejects_wrong_field_count():
    with pytest.raises(DerError):
        parse_key_description(seq(integer(1), octets(b"x")))


def test_duplicate_authorization_tags_rejected():
    from attestation_factory import enumerated

    dup = seq(explicit(706, integer(202601)), explicit(706, integer(202609)))
    kd = seq(integer(300), enumerated(1), integer(300), enumerated(1), octets(b"c"), octets(b""), seq(), dup)
    with pytest.raises(DerError):
        parse_key_description(kd)


def test_serial_key_format():
    assert serial_key(0x1F4363F4ACEFDF83) == "1f4363f4acefdf83"


class FakeClock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def test_revocation_refresh_backoff_and_staleness():
    clock = FakeClock()
    calls = []
    doc = {"entries": {"abc": {"status": "REVOKED"}}}
    state = {"fail": False}

    def fetch(_url):
        calls.append(clock.t)
        if state["fail"]:
            raise OSError("down")
        return json.dumps(doc).encode()

    rl = RevocationList(fetch=fetch, clock=clock, refresh_seconds=3600, max_age_seconds=7200, retry_seconds=60)
    assert rl.status(0xABC) == {"status": "REVOKED"}
    assert rl.status(0xDEF) is None
    assert len(calls) == 1

    state["fail"] = True
    clock.t += 3600  # due for refresh, not yet stale: keep serving cached list
    assert rl.status(0xABC) is not None
    clock.t += 10
    rl.status(0xABC)
    assert len(calls) == 2  # backing off, no refetch within retry window

    clock.t += 3600  # now stale
    with pytest.raises(RevocationUnavailable):
        rl.status(0xABC)
    with pytest.raises(RevocationUnavailable):
        rl.status(0xABC)  # still fails closed during backoff

    state["fail"] = False
    clock.t += 61
    assert rl.status(0xABC) is not None


def test_revocation_rejects_bad_document():
    with pytest.raises(ValueError):
        RevocationList.static(None)  # type: ignore[arg-type]
