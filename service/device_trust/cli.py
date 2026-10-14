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

    admin_token = None
    if args.admin_token_file:
        admin_token = Path(args.admin_token_file).read_text(encoding="utf-8").strip()
        if len(admin_token) < 32:
            raise SystemExit("admin token must be at least 32 characters")
    gateway_token = None
    if args.gateway_token_file:
        gateway_token = Path(args.gateway_token_file).read_text(encoding="utf-8").strip()
        if len(gateway_token) < 32:
            raise SystemExit("gateway token must be at least 32 characters")
    service = build_service(args)
    if service.policy.require_principal and not gateway_token:
        raise SystemExit("policy requires a principal but --gateway-token-file was not given")
    app = create_app(service, expose_reasons=args.expose_reasons, admin_token=admin_token,
                     trust_forwarded_for=args.trust_forwarded_for, gateway_token=gateway_token)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    registry = DeviceRegistry(args.db)
    if not registry.revoke(args.device_id, args.reason):
        print(f"device {args.device_id} not found", file=sys.stderr)
        return 1
    print(f"revoked {args.device_id}")
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
    serve.add_argument("--gateway-token-file",
                       help="file with the shared secret the customer's authenticated backend sends as "
                            "X-Gateway-Authorization; enables principal ownership and /v1/devices endpoints")
    serve.add_argument("--admin-token-file",
                       help="file holding the bearer token for /v1/admin endpoints (disabled if omitted)")
    serve.add_argument("--trust-forwarded-for", action="store_true",
                       help="read the client IP from X-Forwarded-For (only behind a proxy that sets it)")
    serve.set_defaults(func=cmd_serve)

    revoke = sub.add_parser("revoke", help="revoke an enrolled device")
    revoke.add_argument("--db", required=True)
    revoke.add_argument("--device-id", required=True)
    revoke.add_argument("--reason", required=True)
    revoke.set_defaults(func=cmd_revoke)

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
