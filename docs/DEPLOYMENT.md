# Reference deployment (Run 18)

This is a single-customer reference: one verification service operated by the customer for their own app. It is **not** a reviewed multi-tenant hosted service. Fleet and keybox statistics are global to the database.

Files: [`deploy/reference/`](../deploy/reference): `policy.beta.json`, `compose.yaml`, `Caddyfile`. The image is built from [`service/Dockerfile`](../service/Dockerfile).

## Topology

```
phone ──TLS──▶ your backend ──TLS (+mTLS recommended)──▶ proxy :8443 ──▶ trust :8080   (client API)
                 │ authenticates the user;                                    │
                 │ adds X-Gateway-Authorization, X-Tenant-Id, X-Account-Id     ▼
                 │                                                     SQLite (volume)
operators ──VPN/SSH──▶ 127.0.0.1:8081 trust-admin (admin API only) ────────────┘
```

- **Phones never reach the service directly.**
  - Your backend authenticates the user, then forwards the app's requests with the gateway secret and the account principal (Run 16).
  - It executes only what the service returns for signed actions.
  - Exactly-once execution of a payment is your backend's job; a one-time signature does not deliver it.
- **The admin API runs as a separate process** (`device-trust serve-admin`, Run 18) on an internal listener. The client process is started without an admin token, so `/v1/admin/*` does not exist there. The proxy also refuses those paths.
- **TLS:** terminate TLS in front of the client API (Caddy in the reference). Use your own PKI, or `tls internal` with its CA trusted by the backend only. The service itself speaks plain HTTP on the internal network.

## Setup

1. Build the image: `docker build -t device-trust:0.9.0b1 service/`.
2. Create `deploy/reference/secrets/`. This directory is git-ignored; use mode 0600 files, or your orchestrator's secret store.
   - `policy.json`: copy `policy.beta.json`, then set:
     - `package_name`
     - `signing_cert_sha256`: the **Play app-signing** certificate if you use Play App Signing
     - `fleet_hash_key`: a random secret, so network history survives restarts
     - `policy_version`
   - `gateway_token` and `admin_token`: at least 32 random characters each, and different from each other, e.g. `openssl rand -hex 32`.
   - Optional `play_service_account.json`: a Google Cloud service-account key with the Play Integrity API enabled, linked to your app in Play Console. Then add `--play-service-account` to the `trust` command. Without it, Play results are reported as `UNAVAILABLE` and never as passed.
3. Check the configuration. This makes no network calls and prints no secrets:
   ```sh
   docker run --rm -v "$PWD/deploy/reference/secrets:/run/secrets:ro" device-trust:0.9.0b1 \
     check-config --policy /run/secrets/policy.json \
     --gateway-token-file /run/secrets/gateway_token --admin-token-file /run/secrets/admin_token
   ```
   - The shipped `policy.beta.json` fails on purpose (placeholder signer).
   - `beta` requires `require_principal`, `require_bound_enrollment` and `require_bound_device`, plus a gateway token.
4. Check the app identity: `python -m tools.release.check_signing app.apk --policy policy.json`. It verifies the APK signer with `apksigner` and compares it with the allowlist. A debug-key build fails unless `--allow-debug` is given.
5. Start the stack: `docker compose -f deploy/reference/compose.yaml up -d`.
   - At startup the service downloads Google's attestation revocation list, and fails rather than run without it.
   - Outbound HTTPS is needed to `android.googleapis.com`. With Play enabled it also needs `oauth2.googleapis.com` and `playintegrity.googleapis.com`.

## Storage, backup and retention

- **What is stored:** `devices.sqlite` in the `trust-data` volume, written in WAL mode and shared with the admin process. It holds:
  - device keys and minimal attested evidence
  - lifecycle events
  - decisions (reason codes and risk factors; no action params)
  - attestation-key uses
  - fleet events (keyed network hashes, never IPs)
  - assurance snapshots
- **What is not stored:** serial numbers, IMEIs, raw Play tokens, signal reports or action parameters.
- **Backups:**
  - Use `sqlite3 devices.sqlite ".backup backup.sqlite"` or a volume snapshot while the service is stopped. Copying the file alone during WAL writes is unsafe.
  - Encrypt backups. They contain account identifiers (tenant/account principals) and device public keys.
- **Retention:**
  - Refresh snapshots are bounded per device (`history_max_snapshots`).
  - Decisions, lifecycle events, fleet events and attestation-key uses are **not yet pruned automatically**. Schedule your own deletion according to your privacy policy, e.g. fleet events older than the longest risk window. This is a known gap.
- **Schema:** migrations run at startup. A database from a newer build is refused, so roll back with the matching backup.

## Logs

The decision logs (`device_trust.decisions`) are structured JSON. They contain decision IDs, reason codes, risk factor names and lifecycle transitions, and never action parameters, tokens or signals. Ship them to your log store with access control; support staff look reasons up by `decisionId`.

## Operational dependencies

| Dependency | Needed for | If unavailable |
|---|---|---|
| Google attestation revocation list | every attestation | startup fails; a stale list is refused (`REVOCATION_UNAVAILABLE`) |
| Google Play Integrity decode API + service account | Play verdicts | `PLAY_INTEGRITY_UNAVAILABLE` (warning, or blocking where policy requires Play) |
| Your backend's authentication | principals, ownership | requests without the gateway secret are refused (401) |

## Not covered by this reference

- High availability and horizontal scaling: the challenge store is in-memory per process, so it needs a shared store (see `challenges.py`).
- Automatic retention.
- A reviewed multi-tenant design.
- Penetration testing and certification.
