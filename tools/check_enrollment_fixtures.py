"""Check Kotlin-produced enrollment transcripts with the server's own parsers.

Run 14 (typed signal coverage) x Run 20 (signed enrollment transcript): the
SDK test EnrollmentCoverageFixtureTest writes maximum-size transcripts with
fully detected and fully unavailable signal reports. Each must parse under the
server's strict signed-JSON bounds, carry exactly the transcript fields, and
contain a signal report the signal validator accepts.

    PYTHONPATH=service python3 tools/check_enrollment_fixtures.py FILE...
"""

from __future__ import annotations

import sys
from pathlib import Path

from device_trust.enrollment_proof import _FIELDS, MAX_PROOF_BYTES
from device_trust.signals import coverage_summary, parse_client_signals
from device_trust.strict_json import strict_loads


def check(path: Path) -> str:
    data = path.read_bytes()
    doc = strict_loads(data, MAX_PROOF_BYTES)
    if not isinstance(doc, dict) or set(doc) != _FIELDS:
        raise ValueError(f"{path}: unexpected transcript fields")
    if doc["v"] != 1 or doc["purpose"] != "enrollment":
        raise ValueError(f"{path}: wrong version or purpose")
    signals = parse_client_signals(doc["signals"])
    if signals.get("signal_coverage_version") != 1:
        raise ValueError(f"{path}: coverage fields missing from the signed report")
    return f"{path.name}: {len(data)} bytes, coverage {coverage_summary(signals)}"


def main(paths: list[str]) -> int:
    if not paths:
        print("no transcripts given", file=sys.stderr)
        return 2
    for p in paths:
        print(check(Path(p)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
