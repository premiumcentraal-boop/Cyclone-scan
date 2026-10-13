import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from attestation_factory import PACKAGE, SIGNING_DIGEST  # noqa: E402

from device_trust.policy import TrustPolicy  # noqa: E402


@pytest.fixture
def policy() -> TrustPolicy:
    return TrustPolicy(package_name=PACKAGE, signing_cert_sha256=frozenset({SIGNING_DIGEST.hex()}))
