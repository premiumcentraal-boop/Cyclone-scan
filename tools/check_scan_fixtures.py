"""Check Kotlin-produced Run 17 scan / key-rotation transcripts with the server's own parser.

The SDK test ScanEvidenceTest writes a maximum-size scan transcript (full detected
signal report, ten-certificate fresh chain, 128-character fields) and a key-rotation
transcript. Each must parse with ``device_trust.scan_evidence.parse`` for its purpose
(strict bounded JSON, exact field set) and the scan's signal report must pass the
server's signal validator.

    PYTHONPATH=service python3 tools/check_scan_fixtures.py SCAN_FILE ROTATION_FILE
"""

from __future__ import annotations

import sys
from pathlib import Path

from device_trust import scan_evidence
from device_trust.signals import coverage_summary, parse_client_signals


def check_scan(path: Path) -> str:
    data = path.read_bytes()
    doc = scan_evidence.parse(data, scan_evidence.PURPOSE_SCAN)
    signals = parse_client_signals(doc.signals)
    if signals.get("signal_coverage_version") != 1:
        raise ValueError(f"{path}: coverage fields missing from the signed report")
    if not doc.chain_sha256 or len(doc.chain_sha256) != 10:
        raise ValueError(f"{path}: expected a ten-certificate fresh chain digest list")
    return f"{path.name}: {len(data)} bytes of {scan_evidence.MAX_TRANSCRIPT_BYTES}, coverage {coverage_summary(signals)}"


def check_rotation(path: Path) -> str:
    data = path.read_bytes()
    doc = scan_evidence.parse(data, scan_evidence.PURPOSE_KEY_ROTATION)
    if not doc.chain_sha256 or doc.confirm_chain_sha256 is None:
        raise ValueError(f"{path}: expected new device and confirm chain digests")
    return f"{path.name}: {len(data)} bytes, purpose {doc.purpose}"


def main(paths: list[str]) -> int:
    if len(paths) != 2:
        print("usage: check_scan_fixtures.py SCAN_FILE ROTATION_FILE", file=sys.stderr)
        return 2
    print(check_scan(Path(paths[0])))
    print(check_rotation(Path(paths[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
