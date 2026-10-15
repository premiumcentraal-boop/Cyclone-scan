"""Compare an APK's actual signer with the verification service's signing allowlist (Run 18).

    python -m tools.release.check_signing APK --policy policy.json [--apksigner PATH] [--allow-debug]

Uses the Android SDK's ``apksigner verify --print-certs`` (signature verified, not just read).
Exit 0: signed, every signer is allowed by ``signing_cert_sha256`` and (unless
--allow-debug) none is a debug key. Exit 1: mismatch or debug key. Exit 2: cannot verify.
Play App Signing re-signs uploads: then the allowlist must hold the *Play* app-signing
certificate, and this check applies to the APK Google distributes, not the upload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

DEBUG_DN = "C=US, O=Android, CN=Android Debug"
_LINE = re.compile(r"^Signer #(\d+) certificate (DN|SHA-256 digest): (.+)$")


def parse_apksigner(text: str) -> list[dict]:
    signers: dict[int, dict] = {}
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if m:
            entry = signers.setdefault(int(m.group(1)), {})
            entry["dn" if m.group(2) == "DN" else "sha256"] = m.group(3).strip().lower() \
                if m.group(2) != "DN" else m.group(3).strip()
    out = []
    for _, entry in sorted(signers.items()):
        if not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")):
            raise ValueError("apksigner output has no SHA-256 signer digest")
        out.append({"sha256": entry["sha256"], "dn": entry.get("dn"), "debug_key": entry.get("dn") == DEBUG_DN})
    if not out:
        raise ValueError("no signer found")
    return out


def default_apksigner() -> str:
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if home:
        tools = sorted((Path(home) / "build-tools").glob("*/apksigner"))
        if tools:
            return str(tools[-1])
    return "apksigner"


def signers(apk: str, apksigner: str | None = None) -> list[dict]:
    proc = subprocess.run([apksigner or default_apksigner(), "verify", "--print-certs", apk],
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
        raise ValueError(f"apksigner could not verify the APK signature: {detail[0][:200]}")
    return parse_apksigner(proc.stdout)


def evaluate(found: list[dict], allowed: set[str], allow_debug: bool = False) -> dict:
    allowed_all = all(s["sha256"] in allowed for s in found)
    debug = any(s["debug_key"] for s in found)
    return {"signers": found, "allowed_by_policy": allowed_all,
            "identity": "TEST_DEBUG_KEY" if debug else "NON_DEBUG_KEY",
            "ok": allowed_all and (allow_debug or not debug),
            "note": "A non-debug key is not thereby the approved production identity; the owner confirms that."}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("apk")
    p.add_argument("--policy", required=True)
    p.add_argument("--apksigner")
    p.add_argument("--allow-debug", action="store_true", help="accept a debug-signed test build")
    args = p.parse_args(argv)
    try:
        policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        allowed = {str(d).replace(":", "").strip().lower() for d in policy.get("signing_cert_sha256", ())}
        result = {"apk_sha256": _sha256(args.apk), **evaluate(signers(args.apk, args.apksigner), allowed, args.allow_debug)}
    except (OSError, ValueError) as exc:
        p.exit(2, f"{exc}\n")
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
