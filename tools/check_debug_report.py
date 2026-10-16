"""Check a Kotlin-produced Run 31 scanner debug report (schema cyclone-scan-debug-report v1).

    python3 tools/check_debug_report.py android/scanner/build/debug-report-sample.json

Validates the structure developers rely on, that every not-scanned item carries a state,
explanation and developer hint, and that no identifier fields, file paths or URLs leaked.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SECTIONS = {"schema", "schemaVersion", "generatedAt", "purpose", "app", "device", "summary", "notScanned",
            "errors", "phases", "localScan", "server", "biometric", "privacy"}
ITEM = {"kind", "id", "label", "state", "reason", "explanation", "developerHint"}
FORBIDDEN_KEYS = {"imei", "serial", "meid", "password", "token", "account", "serverurl"}
PATH = re.compile(r"(?:/[\w.@+\-]+){2,}")


def _keys(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _keys(value)
    elif isinstance(node, list):
        for value in node:
            yield from _keys(value)


def check(path: Path) -> str:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != "cyclone-scan-debug-report" or report.get("schemaVersion") != 1:
        raise ValueError("wrong schema")
    missing = SECTIONS - set(report)
    if missing:
        raise ValueError(f"missing sections: {sorted(missing)}")
    items = report["notScanned"]
    for item in items:
        if not ITEM <= set(item) or not item["explanation"] or not item["developerHint"]:
            raise ValueError(f"incomplete not-scanned item: {item.get('kind')}:{item.get('id')}")
    if report["summary"]["notScannedItems"] != len(items):
        raise ValueError("summary count does not match notScanned")
    leaked = {k.lower() for k in _keys(report)} & FORBIDDEN_KEYS
    if leaked:
        raise ValueError(f"identifier fields present: {sorted(leaked)}")
    for error in report["errors"]:
        text = str(error.get("message") or "")
        if PATH.search(text) or "://" in text:
            raise ValueError(f"unsanitized error message in {error.get('where')}")
    kinds = sorted({i["kind"] for i in items})
    return f"{path.name}: {len(items)} not-scanned items ({', '.join(kinds)}), {len(report['errors'])} errors"


def main(paths: list[str]) -> int:
    if not paths:
        print("usage: check_debug_report.py REPORT...", file=sys.stderr)
        return 2
    for p in paths:
        print(check(Path(p)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
