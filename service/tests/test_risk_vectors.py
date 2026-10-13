"""The shared risk vectors must match the current server engine (the Android
scanner's on-device engine is tested against the same file)."""

import importlib.util
from pathlib import Path

GEN = Path(__file__).resolve().parents[2] / "testvectors" / "generate_risk_vectors.py"


def test_risk_vectors_are_current():
    spec = importlib.util.spec_from_file_location("gen_risk_vectors", GEN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    current = (GEN.parent / "risk_vectors.json").read_text(encoding="utf-8")
    assert module.render() == current, "run: python testvectors/generate_risk_vectors.py"
