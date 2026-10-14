"""The shared attestation vectors must match the current server verifier (the
scanner's on-device ChainVerifier is tested against the same file)."""

import importlib.util
from pathlib import Path

GEN = Path(__file__).resolve().parents[2] / "testvectors" / "generate_attestation_vectors.py"


def test_attestation_vectors_are_current():
    spec = importlib.util.spec_from_file_location("gen_attestation_vectors", GEN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    current = (GEN.parent / "attestation_vectors.json").read_text(encoding="utf-8")
    assert module.render() == current, "run: python testvectors/generate_attestation_vectors.py"
