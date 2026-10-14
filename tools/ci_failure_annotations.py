"""Turn Gradle/JUnit failures into GitHub annotations.

Runs only after a failed Android step, so reviewers (and agents that cannot
download raw job logs) see compiler errors and failing tests on the check run.
Reads the tee'd Gradle log and JUnit XML reports; prints at most 10 errors.

    python3 tools/ci_failure_annotations.py /tmp/gradle.log android
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX = 10
_PATTERN = re.compile(r"^(e: .*|.*FAILED$|\* What went wrong:.*|Lint found .*errors.*)")


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")[:3000]


def main(log_path: str, root: str) -> int:
    messages: list[str] = []
    log = Path(log_path)
    if log.exists():
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines):
            if _PATTERN.match(line.strip()):
                messages.append("\n".join(lines[i:i + 4]))
    for report in sorted(Path(root).glob("**/build/test-results/**/*.xml")):
        try:
            suite = ET.parse(report).getroot()
        except ET.ParseError:
            continue
        for case in suite.iter("testcase"):
            for failure in list(case.iter("failure")) + list(case.iter("error")):
                text = (failure.get("message") or "") + "\n" + (failure.text or "")[:1500]
                messages.append(f"{case.get('classname')}.{case.get('name')}: {text}")
    seen: set[str] = set()
    printed = 0
    for m in messages:
        if m in seen or printed >= MAX:
            continue
        seen.add(m)
        printed += 1
        print(f"::error::{_escape(m)}")
    if not printed:
        print("::error::No compiler or test failure found in the Gradle log or JUnit reports")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
