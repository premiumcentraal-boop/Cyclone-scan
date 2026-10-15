# Data inventory, retention and erasure (Run 29)

This page describes what the SDK sends, what the verification service stores, how long it keeps each item and how it is deleted. It applies to the code as of Run 29. It is input for the customer's own privacy notice and data-protection review (`privacy_retention` in the beta gate). It is not legal advice and not that review.

## What the SDK sends

| Item | Content | Personal? |
|---|---|---|
| Attestation chains | Certificates for keys generated on the phone. The KeyDescription includes the challenge, security level, boot state, OS and patch levels, the app's package and signer, and, from Android 12, the attested brand, device, product, manufacturer and model. The SDK does not request serial or IMEI attestation. | Pseudonymous: device public keys are unique per installation. |
| Device fields | Build brand, device, product, manufacturer and model as the app sees them | Device type, not a person |
| Client signals (Run 14) | Booleans, check states and short identifiers: installer package, the app's own signing digest, short names of a fixed list of remote-access apps, the count of third-party accessibility services. No file contents, paths, memory maps, account data or app inventory beyond fixed lists. | No direct identifiers |
| Signed transcripts | The exact bytes of enrollment, scan, rotation and action requests. Actions contain whatever parameters the customer's app signs (e.g. payee, amount). | Action parameters can be personal |
| Play Integrity token | Google-encrypted verdict | Decoded by Google for the customer |
| Network address | Seen by the customer's backend and forwarded as `X-Forwarded-For` | Yes. The service keeps only a keyed hash of the /24 (IPv4) or /48 (IPv6) block. |

## What the service stores (SQLite)

| Table | Content | Retention (default) | Deleted by |
|---|---|---|---|
| `devices` | Device key and optional confirm key (public), minimal attested evidence, the enrollment's decoded Play verdict summary (labels only: device and app recognition, licensing, Play Protect, app-access-risk categories, device activity level, device-recall bits), owner tenant/account, status, binding, timestamps. No raw signals, tokens or IPs. | While the device exists; a revoked device stays as a record so its key can never enroll again | Erasure |
| `assurance_snapshots` | Minimal attested measurements per enrollment, rotation and scan refresh. No reported fields, signals or tokens. | Enrollment and rotation snapshots are kept while the device exists. Scan refreshes: at most `history_max_snapshots` per device, and `retention_scan_snapshots_days` (365). | Sweep (refreshes); erasure (all) |
| `decisions` | Decision ID, device ID, kind, action type, verdict, score, factor names and reason codes. No action parameters. | `retention_decisions_days` (365); must cover the velocity window | Sweep; erasure |
| `lifecycle_events` | Event, from/to status, actor, bounded reason code | `retention_lifecycle_events_days` (730) | Sweep; erasure |
| `fleet_events` | Kind, decision ID, device ID, keyed network hash, cohort (model, patch, provenance) | `retention_fleet_events_days` (30); must cover the fleet window | Sweep; erasure |
| `attestation_key_uses` | Hash of the attestation (keybox or RKP) key, decision ID, claimed model. Not per person. | `retention_key_uses_days` (90); must cover the keybox window (30 days) | Sweep |
| `retired_keys` | SHA-256 of device keys retired by rotation or erasure | Permanent; after erasure unlinked from any device (`device_id = "erased"`) | Not deleted: it stops a key enrolling again |

The policy is validated at startup. A retention period shorter than the risk window that reads the table is refused, so pruning cannot silently weaken a risk factor.

In memory only: outstanding challenges (single use, 120 s TTL by default). Not stored anywhere: raw attestation chains, Play tokens, signal reports, action parameters, IPs, serials and IMEIs.

## Retention sweep

- `device-trust serve` runs the sweep at startup and then every `retention_sweep_interval_seconds` (3600). The admin process does not, so two processes never sweep the same file at the same moment.
- `device-trust purge --policy … --db …` runs it once (cron, maintenance) and prints the deleted row counts.
- `POST /v1/admin/retention-sweep` runs it on demand.
- The sweep also revokes pending enrollments older than `pending_ttl_seconds`, which nobody completed or retried.

## Erasure

| Request | Route | Effect |
|---|---|---|
| A user removes one device | `DELETE /v1/devices/{id}` (gateway; the owner only, 404 otherwise) | That device's record, snapshots, decisions, lifecycle and fleet events are deleted. The key hash is kept as an unlinked tombstone. |
| A user closes their account | `DELETE /v1/account/data` (gateway) | The same for every device of the authenticated tenant and account |
| Support / admin | `DELETE /v1/admin/devices/{id}`, `POST /v1/admin/accounts/erasure {tenant, account}`, `device-trust erase-account` | The same |

An erased key can never enroll again (`KEY_ALREADY_ENROLLED`). A reinstall produces a new key and enrolls normally. Erasure is logged as an event without the device ID.

Erasure does not reach:

- **Structured logs.** Decision logs carry decision and device IDs, reason codes and factor names; set the log store's retention to match your policy.
- **Backups.** Rotate them within your retention period.
- **Attestation-key use rows.** They hold no device or account identifier and age out.
- **Data the customer's backend holds.**

## Customer responsibilities

- Publish a privacy notice covering the table above, including the legal basis for fraud prevention.
- Set retention periods that match the notice. Shortening below a risk window is refused; turn the risk factor off first if that is what you need.
- Call the erasure route from the account-deletion process.
- Encrypt backups; they contain account identifiers.
