# Run 16 — Enrollment and device lifecycle

Base: `run-15b-integrate-20-25`, `04996b51fc7f691e43e3412f1ce7b7abb6a5bac9` (Run 15 + Runs 20–25, PR #15).
Branch: `run-16-device-lifecycle`. Physical device: UNVERIFIED.

## States and transitions

| From | Event | To | Who |
|---|---|---|---|
| (new) | `enrolled` | `active` (ALLOW) or `pending` (STEP_UP; or unbound by policy) | system |
| pending | `step_up_completed` | active | gateway (owner) or admin |
| pending | `revoked` / `pending_expired` | revoked | gateway (owner), admin, system (TTL) |
| active | `revoked` | revoked | gateway (owner) or admin |

Every other transition is refused atomically. `revoked` is terminal.

- **STEP_UP enrollments are now `pending`.** Before this run they were registered as active and could act immediately. Pending devices get no action challenge (404, same as unknown). A direct verify attempt returns `DEVICE_PENDING`.
- **Step-up completion** is an authenticated interface:
  - `POST /v1/devices/{id}/step-up-completion` from the customer's backend for the owning principal.
  - `POST /v1/admin/devices/{id}/step-up-completion` for support staff.
  - `method` is one of OTP, PASSWORD, BIOMETRIC_ACCOUNT, SUPPORT_VERIFIED, DOCUMENT_CHECK.

  It does not manufacture device-key proof that an enrollment lacked, and every later action is still scored on its own.
- **Pending expiry:** a pending device older than `pending_ttl_seconds` (default 7 days) is revoked on the next completion attempt (HTTP 410); the user enrolls again.
- **Reset, reinstall and key loss** produce a new attested key, so the server sees a *new* device: a new record with its own state.
  - The old record is untouched until it is revoked; the owner can do that with `POST /v1/devices/{id}/revoke` and a reason of LOST, USER_REQUEST, SUSPECTED_COMPROMISE, ACCOUNT_CLOSED or OTHER.
  - Re-enrolling the same attested key is refused with `KEY_ALREADY_ENROLLED`, so a revoked identity is never revived.
- **Same phone is not established.** Model or boot facts never establish that two keys belong to one phone. Lifecycle decisions are always about one enrolled key; a physical key-pairing protocol remains a separate design and review task.

## Ownership

- **Gateway mode** (`create_app(gateway_token=...)` / `serve --gateway-token-file`): the customer's authenticated backend forwards each request with three headers: `X-Gateway-Authorization: Bearer <secret>`, `X-Tenant-Id` and `X-Account-Id`.
  - Only these become the principal. Without the gateway token, account headers are ignored.
  - Enrollment challenges are bound to the principal. A challenge issued to one account cannot be used by another.
  - Devices record `owner_tenant` / `owner_account`. Status, step-up, revoke, action challenges and action verification all require the same tenant *and* account. Not-owned devices look exactly like unknown ones.
- **Development mode** (no gateway token): no principal is trusted and devices are ownerless, as before.
  - A principal never claims an ownerless device, so devices enrolled before gateway mode must enroll again under an account.
  - `require_principal` refuses anonymous requests (`PRINCIPAL_REQUIRED`), and `serve` refuses to start with it but without a gateway token.

## Evidence binding (with Run 20)

Each device records `binding`:
- `BOUND`: a Run 20 proof was verified.
- `LEGACY_UNBOUND`: enrolled without a proof in legacy mode.
- `UNKNOWN`: enrolled before Run 16.

Policy options:
- `require_bound_enrollment` (Run 20) rejects unbound enrollments.
- `unbound_enrollment_state: "pending"` holds new unbound enrollments for step-up.
- `require_bound_device` quarantines `LEGACY_UNBOUND`/`UNKNOWN` devices with `DEVICE_REBINDING_REQUIRED` until they enroll again with binding. This is a runtime rule, not a data change, so it is reversible.

Defaults keep legacy behaviour. The recommended beta settings are `require_principal`, `require_bound_enrollment` and `require_bound_device`, all true.

## Audit events

`lifecycle_events` stores the event, from/to status, actor (`system` / `gateway` / `admin`) and a bounded reason code (≤64 characters: the step-up method or revoke reason). It stores no action parameters, signals, tokens or secrets. The admin device view shows them with the owner and binding; the owner view shows only the status, binding and whether a confirm key exists.

## Migrations

Migrations use one ordered `PRAGMA user_version` mechanism, which replaces the previous `CREATE IF NOT EXISTS` and column-patching initializer:
1. **Migration 1** adopts any earlier database. Phase 1, Run 13 and Run 22 databases are all at version 0. It creates missing tables without dropping rows, adds the pre-versioning columns, and keeps `assurance_snapshots`.
2. **Migration 2** adds the owner, binding and state-time columns, the owner index and `lifecycle_events`. Existing devices keep their status, with binding `UNKNOWN` and no owner.

Each step runs in its own transaction together with its version bump, so a failure rolls back completely. A database from a newer build is refused (`SchemaVersionError`).

## Scanner and SDK

`EnrollmentResult.deviceStatus` is a new optional field ("active" / "pending"; null from older servers). The scanner's Server tab stops after enrollment when the device is pending and explains that the app's backend must complete the step-up. It shows no backend reasons.

## Tests

- `service/tests/test_lifecycle.py` (18 tests) covers:
  - states, the pending action refusal, authenticated completion, double completion and unknown methods
  - revocation as terminal, no revival by re-enrolling the same key, a new key becoming a new device
  - pending expiry and bounded events
  - principal rules and tenant isolation, gateway secret enforcement, ignored client account headers, owner-only status/completion/revoke/challenge/verify, principal-bound enrollment challenges, `require_principal`, unbound-pending and quarantine, policy validation
  - migrations: fresh, Phase 1 upgrade, Run 22 upgrade with snapshots retained, repeat startup, transactional rollback, newer schema refused
- `test_provenance.py` is updated: a leaked-keybox STEP_UP enrollment is now pending; after an admin completion, its action is still blocked by risk.
- SDK: `deviceStatus` parsing.

## Limits

- The gateway secret authenticates the customer's backend, not the end user. User authentication, session security and account recovery stay in that backend.
- Multi-tenant isolation is enforced on every device lookup, but the reference deployment (Run 18) is single-customer. Fleet and keybox statistics remain global by design.
- Ownerless (pre-Run-16) devices are not migrated to accounts automatically: claiming them safely needs an authenticated re-enrollment.
- Key rotation and continuity (old key authorizing a new one) belong to Run 17 and are not implemented here.
