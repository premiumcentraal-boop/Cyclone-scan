"""Record what was built, from which revision, with which toolchain and signer (Run 18).

    python -m tools.release.build_evidence --revision SHA --android-dir android \\
        --aar first.aar [--aar-rebuild second.aar] --apk scanner-release.apk [--sample-apk app.apk]

Hashes artifacts, reads toolchain versions from the build files, verifies the APK signer
with apksigner when available, and compares two independent AAR builds of the same tree.
Evidence of a build, not of its safety: it does not authenticate the revision it is given,
and "reproducible" means byte-identical rebuilds on that runner only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from . import check_signing

_REV = re.compile(r"^[0-9a-f]{40}$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _artifact(path: str | None) -> dict | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file() or p.stat().st_size == 0:
        raise ValueError(f"missing or empty artifact: {path}")
    return {"file": p.name, "sha256": sha256(p), "size": p.stat().st_size}


def _find(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text)
    return m.group(1) if m else None


def toolchain(android_dir: Path) -> dict:
    root = (android_dir / "build.gradle.kts").read_text(encoding="utf-8")
    sdk = (android_dir / "devicetrust" / "build.gradle.kts").read_text(encoding="utf-8")
    props = (android_dir / "gradle.properties").read_text(encoding="utf-8")
    wrapper = (android_dir / "gradle" / "wrapper" / "gradle-wrapper.properties").read_text(encoding="utf-8")
    return {
        "gradle": _find(r"gradle-([\d.]+)-(?:bin|all)\.zip", wrapper),
        "android_gradle_plugin": _find(r'id\("com\.android\.library"\) version "([^"]+)"', root),
        "kotlin": _find(r'id\("org\.jetbrains\.kotlin\.android"\) version "([^"]+)"', root),
        "compile_sdk": _find(r"compileSdk = (\d+)", sdk),
        "ndk": _find(r'ndkVersion = "([^"]+)"', sdk),
        "cmake": _find(r'version = "([\d.]+)"', sdk),
        "jvm_target": _find(r'jvmTarget = "([^"]+)"', sdk),
        "version": _find(r"cyclone\.version=(\S+)", props),
        "version_code": _find(r"cyclone\.versionCode=(\d+)", props),
    }


def _java_version() -> str | None:
    try:
        proc = subprocess.run(["java", "-version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    return _find(r'version "([^"]+)"', proc.stderr)


def evidence(revision: str, android_dir: str, aar: str, apk: str, aar_rebuild: str | None = None,
             sample_apk: str | None = None, apksigner: str | None = None, java: str | None = None) -> dict:
    if not _REV.match(revision or ""):
        raise ValueError("a concrete 40-hex tested revision is required")
    aar_a, apk_a = _artifact(aar), _artifact(apk)
    rebuilt = _artifact(aar_rebuild)
    try:
        signer = check_signing.evaluate(check_signing.signers(apk, apksigner), set())
        signing = {"verified_by": "apksigner", "identity": signer["identity"],
                   "signer_sha256": [s["sha256"] for s in signer["signers"]]}
    except (OSError, ValueError):
        signing = {"verified_by": None, "identity": "UNVERIFIED", "signer_sha256": []}
    return {
        "schema": 1,
        "tested_revision": revision,
        "artifacts": {"aar": aar_a, "scanner_apk": apk_a, "sample_apk": _artifact(sample_apk)},
        "aar_reproducible": None if rebuilt is None else rebuilt["sha256"] == aar_a["sha256"],
        "signing": signing,
        "toolchain": {**toolchain(Path(android_dir)), "java": java or _java_version()},
        "limitations": [
            "The revision is supplied by the caller; PR CI builds a synthetic merge revision.",
            "Re-signing or rebuilding with a different key or toolchain creates a different APK identity.",
            "TEST_DEBUG_KEY builds are for testing only and are not the approved distribution identity.",
            "Reproducibility was compared on one runner; other machines may differ.",
        ],
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--revision", required=True)
    p.add_argument("--android-dir", default="android")
    p.add_argument("--aar", required=True)
    p.add_argument("--aar-rebuild")
    p.add_argument("--apk", required=True)
    p.add_argument("--sample-apk")
    p.add_argument("--apksigner")
    args = p.parse_args(argv)
    try:
        result = evidence(args.revision, args.android_dir, args.aar, args.apk, args.aar_rebuild,
                          args.sample_apk, args.apksigner)
    except (OSError, ValueError) as exc:
        p.exit(2, f"{exc}\n")
    print(json.dumps(result, indent=2))
    # A rebuild that differs is a finding, not a crash: report it and fail the step.
    return 1 if result["aar_reproducible"] is False else 0


if __name__ == "__main__":
    raise SystemExit(main())
