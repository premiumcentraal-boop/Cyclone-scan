"""Command line: ``device-trust serve | refresh-roots | check-revocation``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .attestation import AttestationVerifier
from .challenges import ChallengeStore
from .policy import TrustPolicy
from .registry import DeviceRegistry
from .revocation import GOOGLE_STATUS_URL, RevocationList, _http_fetch
from .roots import GOOGLE_ROOTS_URL, RootStore
from .service import DeviceTrustService


def build_service(args: argparse.Namespace) -> DeviceTrustService:
    policy = TrustPolicy.from_file(args.policy)
    roots = RootStore.from_json_file(args.roots) if args.roots else RootStore.bundled_google()
    revocations = RevocationList()
    revocations.refresh()  # fail at startup rather than on the first enrollment
    decoder = None
    if args.play_service_account:
        from .play_integrity import GoogleApiDecoder

        decoder = GoogleApiDecoder.from_file(args.play_service_account)
    elif policy.require_play_integrity:
        raise SystemExit("policy requires Play Integrity but --play-service-account was not given")
    return DeviceTrustService(
        policy,
        AttestationVerifier(policy, roots, revocations),
        ChallengeStore(policy.challenge_ttl_seconds),
        DeviceRegistry(args.db),
        decoder,
    )


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .api import create_app

    app = create_app(build_service(args), expose_reasons=args.expose_reasons)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def cmd_refresh_roots(args: argparse.Namespace) -> int:
    pems = json.loads(_http_fetch(GOOGLE_ROOTS_URL))
    store = RootStore.from_pem_list(pems)  # validates every PEM parses
    Path(args.out).write_text(json.dumps(pems, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(store)} root(s) to {args.out}")
    return 0


def cmd_check_revocation(_args: argparse.Namespace) -> int:
    rl = RevocationList()
    rl.refresh()
    print(f"{GOOGLE_STATUS_URL}: {len(rl)} revoked/suspended entries")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="device-trust")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the HTTP API")
    serve.add_argument("--policy", required=True, help="policy JSON file")
    serve.add_argument("--db", default="devices.sqlite", help="SQLite device registry path")
    serve.add_argument("--roots", help="attestation roots JSON (default: bundled Google roots)")
    serve.add_argument("--play-service-account", help="Google service-account JSON for Play Integrity decoding")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--expose-reasons", action="store_true",
                       help="return failure reasons to callers (development only)")
    serve.set_defaults(func=cmd_serve)

    refresh = sub.add_parser("refresh-roots", help="download Google attestation roots")
    refresh.add_argument("--out", default=str(Path(__file__).parent / "trust_anchors" / "google_roots.json"))
    refresh.set_defaults(func=cmd_refresh_roots)

    check = sub.add_parser("check-revocation", help="download and count the revocation list")
    check.set_defaults(func=cmd_check_revocation)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
