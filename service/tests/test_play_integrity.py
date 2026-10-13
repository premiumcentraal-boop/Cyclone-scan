import json
import urllib.parse

import pytest
from attestation_factory import PACKAGE, SIGNING_DIGEST
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from device_trust import reasons as R
from device_trust.play_integrity import (
    DecodeError,
    GoogleApiDecoder,
    b64url,
    b64url_decode,
    enrollment_request_hash,
    evaluate_payload,
)

NOW_MS = 1_760_000_000_000
REQUEST_HASH = enrollment_request_hash(b"n" * 32, b"spki")


def payload(**overrides) -> dict:
    p = {
        "requestDetails": {"requestPackageName": PACKAGE, "requestHash": REQUEST_HASH, "timestampMillis": str(NOW_MS - 5000)},
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
            "packageName": PACKAGE,
            "certificateSha256Digest": [b64url(SIGNING_DIGEST)],
            "versionCode": "42",
        },
        "deviceIntegrity": {
            "deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"],
            "recentDeviceActivity": {"deviceActivityLevel": "LEVEL_1"},
        },
        "accountDetails": {"appLicensingVerdict": "LICENSED"},
        "environmentDetails": {"playProtectVerdict": "NO_ISSUES", "appAccessRiskVerdict": {"appsDetected": ["KNOWN_INSTALLED"]}},
    }
    for path, value in overrides.items():
        section, key = path.split("__")
        p[section][key] = value
    return p


def test_request_hash_is_bound_to_nonce_and_key():
    a = enrollment_request_hash(b"n" * 32, b"key-a")
    assert a != enrollment_request_hash(b"n" * 32, b"key-b")
    assert a != enrollment_request_hash(b"m" * 32, b"key-a")
    assert len(b64url_decode(a)) == 32 and "=" not in a


def test_clean_payload_passes(policy):
    result = evaluate_payload(payload(), policy, REQUEST_HASH, NOW_MS)
    assert result.ok, result.reasons
    assert result.signals["device_recognition"] == ["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"]
    assert result.signals["device_activity_level"] == "LEVEL_1"


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"requestDetails__requestHash": "replayed"}, R.PLAY_INTEGRITY_REQUEST_MISMATCH),
        ({"requestDetails__requestPackageName": "com.evil"}, R.PLAY_INTEGRITY_REQUEST_MISMATCH),
        ({"requestDetails__timestampMillis": str(NOW_MS - 10 * 60_000)}, R.PLAY_INTEGRITY_STALE),
        ({"requestDetails__timestampMillis": str(NOW_MS + 10 * 60_000)}, R.PLAY_INTEGRITY_STALE),
        ({"requestDetails__timestampMillis": None}, R.PLAY_INTEGRITY_STALE),
        ({"appIntegrity__appRecognitionVerdict": "UNRECOGNIZED_VERSION"}, R.PLAY_APP_NOT_RECOGNIZED),
        ({"appIntegrity__packageName": "com.evil"}, R.PLAY_APP_NOT_RECOGNIZED),
        ({"appIntegrity__certificateSha256Digest": [b64url(b"\x00" * 32)]}, R.SIGNING_CERT_MISMATCH),
        ({"deviceIntegrity__deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY"]}, R.PLAY_DEVICE_INTEGRITY_FAILED),
        ({"deviceIntegrity__deviceRecognitionVerdict": []}, R.PLAY_DEVICE_INTEGRITY_FAILED),
    ],
)
def test_payload_failures(policy, overrides, reason):
    assert reason in evaluate_payload(payload(**overrides), policy, REQUEST_HASH, NOW_MS).reasons


def test_strong_integrity_alone_counts_as_device_integrity(policy):
    p = payload(deviceIntegrity__deviceRecognitionVerdict=["MEETS_STRONG_INTEGRITY"])
    assert evaluate_payload(p, policy, REQUEST_HASH, NOW_MS).ok


def test_empty_payload_fails_everything(policy):
    reasons = evaluate_payload({}, policy, REQUEST_HASH, NOW_MS).reasons
    assert {R.PLAY_INTEGRITY_REQUEST_MISMATCH, R.PLAY_INTEGRITY_STALE, R.PLAY_APP_NOT_RECOGNIZED,
            R.PLAY_DEVICE_INTEGRITY_FAILED} <= set(reasons)


@pytest.fixture
def service_account():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    return key, {"client_email": "verifier@proj.iam.gserviceaccount.com", "private_key": pem,
                 "token_uri": "https://oauth2.googleapis.com/token"}


def test_google_decoder_oauth_and_decode_flow(service_account):
    key, sa = service_account
    calls = []

    def post(url, body, headers):
        calls.append((url, body, headers))
        if url == sa["token_uri"]:
            form = urllib.parse.parse_qs(body.decode())
            header, claims, sig = form["assertion"][0].split(".")
            key.public_key().verify(b64url_decode(sig), f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
            claims = json.loads(b64url_decode(claims))
            assert claims["scope"] == "https://www.googleapis.com/auth/playintegrity"
            assert claims["iss"] == sa["client_email"] and claims["aud"] == sa["token_uri"]
            return json.dumps({"access_token": "at-1", "expires_in": 3600}).encode()
        assert url == f"https://playintegrity.googleapis.com/v1/{PACKAGE}:decodeIntegrityToken"
        assert headers["Authorization"] == "Bearer at-1"
        assert json.loads(body) == {"integrity_token": "tok"}
        return json.dumps({"tokenPayloadExternal": {"ok": True}}).encode()

    decoder = GoogleApiDecoder(sa, post=post, clock=lambda: 1000.0)
    assert decoder.decode(PACKAGE, "tok") == {"ok": True}
    assert decoder.decode(PACKAGE, "tok") == {"ok": True}
    assert sum(1 for c in calls if c[0] == sa["token_uri"]) == 1  # access token cached


def test_google_decoder_wraps_errors(service_account):
    _, sa = service_account

    def post(url, body, headers):
        if url == sa["token_uri"]:
            return b'{"access_token": "x"}'
        raise OSError("503")

    with pytest.raises(DecodeError):
        GoogleApiDecoder(sa, post=post).decode(PACKAGE, "tok")


def test_google_decoder_requires_fields():
    with pytest.raises(ValueError):
        GoogleApiDecoder({"client_email": "x"})
