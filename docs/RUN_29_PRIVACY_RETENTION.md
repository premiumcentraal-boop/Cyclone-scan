# Run 29 — Privacy and retention

Base: `run-28-review-17-19` (PR #21). Branch: `run-29-privacy-retention`. Physical device: not needed.

## Why

Run 18's deployment guide listed automatic retention as a known gap. Decisions, lifecycle events, fleet events and attestation-key uses grew forever, and there was no way to erase a user's data. The beta gate's `privacy_retention` approval needs a documented data inventory and working deletion.

## Delivered

- **Policy:** `retention_decisions_days` (365), `retention_fleet_events_days` (30), `retention_key_uses_days` (90), `retention_lifecycle_events_days` (730), `retention_scan_snapshots_days` (365), `retention_sweep_interval_seconds` (3600). Startup refuses a period shorter than the risk window that reads the table (velocity, fleet, keybox), so pruning cannot weaken a risk factor.
- **Sweep:** `DeviceTrustService.retention_sweep` deletes rows past their period in one transaction and revokes pending enrollments older than `pending_ttl_seconds` (previously they only expired when someone retried). It runs in `serve` at startup and then on the interval; `device-trust purge` and `POST /v1/admin/retention-sweep` run it on demand. It never deletes device records, enrollment or rotation snapshots, or key tombstones.
- **Erasure:**
  - Owner, through the gateway: `DELETE /v1/devices/{id}` and `DELETE /v1/account/data`.
  - Admin: `DELETE /v1/admin/devices/{id}`, `POST /v1/admin/accounts/erasure`, and `device-trust erase-account`.
  - Effect: the device record, snapshots, decisions, lifecycle and fleet events are deleted. The key hashes go to `retired_keys` unlinked (`device_id = "erased"`), so the same hardware key can never enroll again.
- **Migration 4:** `created_at` indexes so the sweep does not scan whole tables (checked with `EXPLAIN QUERY PLAN`).
- **Docs:** [PRIVACY.md](PRIVACY.md) is the data inventory (what the SDK sends, every stored table, retention, deletion route, what erasure cannot reach). DEPLOYMENT.md and the service README are updated.

## Tests

`service/tests/test_retention.py` (15 tests) covers:
- defaults and window validation
- the sweep deleting only expired rows while keeping device records and anchor snapshots
- risk windows still seeing recent rows after a sweep
- pending expiry, and rotation continuity surviving the sweep
- admin erasure (data gone, tombstone unlinked, same key refused, a new key fine)
- erasure after rotation
- owner erasure scoped to the owner and isolated by tenant and account, and refused without the gateway secret
- admin account erasure and the sweep endpoint
- the migration-4 indexes
- the `purge` and `erase-account` CLI

Two migration tests were made version-agnostic (schema 4).

## Limits

- Logs, backups and data held by the customer's backend are outside the service. PRIVACY.md lists them as customer responsibilities.
- Revoked devices remain as records (status, key, minimal evidence) until erased, because they enforce "never revived".
- This is engineering input for `privacy_retention`, not the legal or privacy review the approval needs.
