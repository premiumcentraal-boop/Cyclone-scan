"""Command line: ``device-trust serve | serve-admin | check-config | revoke | refresh-roots | check-revocation``."""

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


def build_service(args: argparse.Namespace, *, admin_only: bool = False) -> DeviceTrustService:
    policy = TrustPolicy.from_file(args.policy)
    roots = RootStore.from_json_file(args.roots) if args.roots else RootStore.bundled_google()
    revocations = RevocationList()
    revocations.refresh()  # fail at startup rather than on the first enrollment
    decoder = None
    if args.play_service_account:
        from .play_integrity import GoogleApiDecoder

        decoder = GoogleApiDecoder.from_file(args.play_service_account)
    elif policy.require_play_integrity and not admin_only:  # the admin API decodes no tokens
        raise SystemExit("policy requires Play Integrity but --play-service-account was not given")
    return DeviceTrustService(
        policy,
        AttestationVerifier(policy, roots, revocations),
        ChallengeStore(policy.challenge_ttl_seconds),
        DeviceRegistry(args.db),
        decoder,
    )


def _token(path: str | None, name: str) -> str | None:
    if not path:
        return None
    token = Path(path).read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise SystemExit(f"{name} token must be at least 32 characters")
    return token


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .api import create_app

    admin_token = _token(args.admin_token_file, "admin")
    gateway_token = _token(args.gateway_token_file, "gateway")
    if admin_token and admin_token == gateway_token:
        raise SystemExit("admin and gateway tokens must differ")
    service = build_service(args)
    if service.policy.require_principal and not gateway_token:
        raise SystemExit("policy requires a principal but --gateway-token-file was not given")
    app = create_app(service, expose_reasons=args.expose_reasons, admin_token=admin_token,
                     trust_forwarded_for=args.trust_forwarded_for, gateway_token=gateway_token)
    _start_retention_sweeper(service)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _start_retention_sweeper(service) -> None:
    """Run 29: the client process sweeps at startup and then every retention_sweep_interval_seconds."""
    import threading

    interval = service.policy.retention_sweep_interval_seconds

    def loop() -> None:
        stop = threading.Event()
        while not stop.is_set():
            try:
                service.retention_sweep()
            except Exception:  # noqa: BLE001 - a failed sweep must never stop the service
                logging.getLogger("device_trust.retention").exception("retention sweep failed")
            stop.wait(interval)

    threading.Thread(target=loop, name="retention-sweep", daemon=True).start()


def _offline_service(args: argparse.Namespace) -> DeviceTrustService:
    """Service for maintenance commands: policy and registry only, no network."""
    policy = TrustPolicy.from_file(args.policy)
    return DeviceTrustService(policy, None, ChallengeStore(policy.challenge_ttl_seconds), DeviceRegistry(args.db), None)


def cmd_purge(args: argparse.Namespace) -> int:
    print(json.dumps(_offline_service(args).retention_sweep(), sort_keys=True))
    return 0


def cmd_erase_account(args: argparse.Namespace) -> int:
    from .lifecycle import Principal

    erased = _offline_service(args).erase_account(Principal(args.tenant, args.account), actor="admin")
    print(json.dumps({"erasedDevices": erased}))
    return 0


def cmd_serve_admin(args: argparse.Namespace) -> int:
    """Admin-only API on its own (internal) listener, sharing the registry file."""
    import uvicorn

    from .api import create_app

    admin_token = _token(args.admin_token_file, "admin")
    service = build_service(args, admin_only=True)
    app = create_app(service, admin_token=admin_token, public=False)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    from .config_check import check

    result = check(args.policy, profile=args.profile, gateway_token_file=args.gateway_token_file,
                   admin_token_file=args.admin_token_file, play_service_account=args.play_service_account)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


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
                       help="file holding the bearer token for /v1/admin endpoints (disabled if omitted; "
                            "prefer serve-admin on a separate internal listener)")
    serve.add_argument("--trust-forwarded-for", action="store_true",
                       help="read the client IP from X-Forwarded-For (only behind a proxy that sets it)")
    serve.set_defaults(func=cmd_serve)

    admin = sub.add_parser("serve-admin", help="run the admin-only API on a separate internal listener")
    admin.add_argument("--policy", required=True, help="policy JSON file")
    admin.add_argument("--db", default="devices.sqlite", help="the same registry file the client API uses")
    admin.add_argument("--roots", help="attestation roots JSON (default: bundled Google roots)")
    admin.add_argument("--play-service-account", help=argparse.SUPPRESS)
    admin.add_argument("--admin-token-file", required=True, help="file holding the admin bearer token")
    admin.add_argument("--host", default="127.0.0.1", help="bind to an internal interface only")
    admin.add_argument("--port", type=int, default=8081)
    admin.set_defaults(func=cmd_serve_admin)

    cfg = sub.add_parser("check-config", help="check a deployment's local configuration (no network)")
    cfg.add_argument("--policy", required=True)
    cfg.add_argument("--profile", choices=("beta", "dev"), default="beta")
    cfg.add_argument("--gateway-token-file")
    cfg.add_argument("--admin-token-file")
    cfg.add_argument("--play-service-account")
    cfg.set_defaults(func=cmd_check_config)

    revoke = sub.add_parser("revoke", help="revoke an enrolled device")
    revoke.add_argument("--db", required=True)
    revoke.add_argument("--device-id", required=True)
    revoke.add_argument("--reason", required=True)
    revoke.set_defaults(func=cmd_revoke)

    purge = sub.add_parser("purge", help="run the retention sweep once (Run 29)")
    purge.add_argument("--policy", required=True)
    purge.add_argument("--db", required=True)
    purge.set_defaults(func=cmd_purge)

    erase = sub.add_parser("erase-account", help="erase every device of one tenant/account (Run 29)")
    erase.add_argument("--policy", required=True)
    erase.add_argument("--db", required=True)
    erase.add_argument("--tenant", required=True)
    erase.add_argument("--account", required=True)
    erase.set_defaults(func=cmd_erase_account)

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
