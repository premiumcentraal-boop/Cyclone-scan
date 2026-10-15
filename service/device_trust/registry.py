"""Enrolled-device registry (SQLite).

Stores the attested device key (and optional biometric-bound confirm key) so
signed actions can be verified against the same hardware. Only privacy-safe
attestation evidence is stored: no serial, IMEI, MEID or raw tokens.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .attestation import AttestationEvidence
from .evidence_history import SOURCE_ENROLLMENT, SOURCE_KEY_ROTATION, snapshot
from .lifecycle import (
    BINDING_UNKNOWN,
    EVENT_ENROLLED,
    EVENT_KEY_ROTATED,
    STATUS_ACTIVE,
    STATUS_PENDING,
    STATUS_REVOKED,
    TRANSITIONS,
)

__all__ = ["DeviceRegistry", "DeviceRecord", "DuplicateDeviceKey", "SchemaVersionError",
           "STATUS_ACTIVE", "STATUS_PENDING", "STATUS_REVOKED", "SCHEMA_VERSION", "MIGRATIONS"]

# Base schema as of Runs 13/22. Migration 1 adopts databases created by any earlier
# build (all at PRAGMA user_version 0) without assuming they are empty.
_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id        TEXT PRIMARY KEY,
    public_key_spki  BLOB NOT NULL,
    spki_sha256      TEXT NOT NULL UNIQUE,
    enrolled_at      INTEGER NOT NULL,
    evidence_json    TEXT NOT NULL,
    play_signals_json TEXT
);
CREATE TABLE IF NOT EXISTS assurance_snapshots (
    device_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS assurance_snapshots_device_time ON assurance_snapshots(device_id, created_at);
CREATE TABLE IF NOT EXISTS decisions (
    decision_id   TEXT PRIMARY KEY,
    device_id     TEXT,
    kind          TEXT NOT NULL,           -- 'enrollment' | 'action'
    action_type   TEXT,
    decision      TEXT NOT NULL,
    risk_score    INTEGER,
    factors_json  TEXT NOT NULL,
    reasons_json  TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_device_time ON decisions (device_id, created_at);
-- Which attestation key (factory keybox or RKP key) each enrollment attempt
-- used, and which model it claimed: a leaked keybox shows up as one key with
-- many models or too many enrollments.
CREATE TABLE IF NOT EXISTS attestation_key_uses (
    key_sha256  TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    model       TEXT,
    created_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS attestation_key_uses_key_time ON attestation_key_uses (key_sha256, created_at);
-- Fleet events (Run 12): network block (keyed hash, never the IP) and cohort
-- of every enrollment attempt and action, for burst detection.
CREATE TABLE IF NOT EXISTS fleet_events (
    kind        TEXT NOT NULL,          -- 'enrollment' | 'action'
    decision_id TEXT NOT NULL,
    device_id   TEXT,
    network     TEXT,
    cohort      TEXT,
    created_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS fleet_events_network ON fleet_events (network, kind, created_at);
CREATE INDEX IF NOT EXISTS fleet_events_cohort ON fleet_events (cohort, kind, created_at);
"""

# Columns added after Phase 1, before versioned migrations existed.
_LEGACY_COLUMNS = (
    ("confirm_key_spki", "BLOB"),
    ("confirm_evidence_json", "TEXT"),
    ("status", f"TEXT NOT NULL DEFAULT '{STATUS_ACTIVE}'"),
    ("revoked_at", "INTEGER"),
    ("revoke_reason", "TEXT"),
    ("last_action_at", "INTEGER"),
)


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_columns(conn: sqlite3.Connection, table: str, columns) -> None:
    existing = _columns(conn, table)
    for column, decl in columns:
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _migrate_1_adopt(conn: sqlite3.Connection) -> None:
    """Adopt Phase 1, Run 13 and Run 22 databases (all user_version 0) or create fresh."""
    for statement in _BASE_SCHEMA.split(";"):
        if statement.strip():
            conn.execute(statement)
    _add_columns(conn, "devices", _LEGACY_COLUMNS)


def _migrate_2_lifecycle(conn: sqlite3.Connection) -> None:
    """Run 16: ownership, evidence binding and lifecycle events. Existing rows keep their status."""
    _add_columns(conn, "devices", (
        ("owner_tenant", "TEXT"),
        ("owner_account", "TEXT"),
        ("binding", f"TEXT NOT NULL DEFAULT '{BINDING_UNKNOWN}'"),
        ("state_changed_at", "INTEGER"),
    ))
    conn.execute("CREATE INDEX IF NOT EXISTS devices_owner ON devices (owner_tenant, owner_account)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS lifecycle_events ("
        " event_id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL, event TEXT NOT NULL,"
        " from_status TEXT, to_status TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT, created_at REAL NOT NULL)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS lifecycle_events_device ON lifecycle_events (device_id, event_id)")


def _migrate_3_continuity(conn: sqlite3.Connection) -> None:
    """Run 17: keys retired by rotation, and a snapshot source column for bounded retention.

    Existing snapshots keep source NULL: they were all written at enrollment and are
    never pruned.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS retired_keys ("
        " spki_sha256 TEXT PRIMARY KEY, device_id TEXT NOT NULL, retired_at REAL NOT NULL)"
    )
    _add_columns(conn, "assurance_snapshots", (("source", "TEXT"),))


# Ordered, append-only. Each step runs in its own transaction together with the
# user_version bump, so a failure leaves the previous version intact.
MIGRATIONS = ((1, _migrate_1_adopt), (2, _migrate_2_lifecycle), (3, _migrate_3_continuity))
SCHEMA_VERSION = MIGRATIONS[-1][0]


class SchemaVersionError(RuntimeError):
    """The database was written by a newer build; refuse rather than guess."""


class DuplicateDeviceKey(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceRecord:
    device_id: str
    public_key_spki: bytes
    confirm_key_spki: bytes | None
    status: str
    enrolled_at: int
    evidence: dict
    confirm_evidence: dict | None
    play_signals: dict | None
    owner_tenant: str | None = None
    owner_account: str | None = None
    binding: str = BINDING_UNKNOWN
    state_changed_at: int | None = None

    @property
    def active(self) -> bool:
        return self.status == STATUS_ACTIVE


class DeviceRegistry:
    def __init__(self, path: str | Path = ":memory:", clock=time.time):
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._clock = clock
        with self._lock:
            self._migrate()

    def _migrate(self) -> None:
        conn = self._conn
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise SchemaVersionError(f"database schema {version} is newer than this build ({SCHEMA_VERSION})")
        previous = conn.isolation_level
        conn.isolation_level = None  # explicit transactions: DDL and the version bump commit together
        try:
            for target, step in MIGRATIONS:
                if target <= version:
                    continue
                conn.execute("BEGIN IMMEDIATE")
                try:
                    step(conn)
                    conn.execute(f"PRAGMA user_version = {int(target)}")
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                version = target
        finally:
            conn.isolation_level = previous

    def schema_version(self) -> int:
        with self._lock:
            return self._conn.execute("PRAGMA user_version").fetchone()[0]

    def register(
        self,
        public_key_spki: bytes,
        evidence: AttestationEvidence,
        play_signals: dict | None,
        confirm_key_spki: bytes | None = None,
        confirm_evidence: AttestationEvidence | None = None,
        *,
        status: str = STATUS_ACTIVE,
        owner_tenant: str | None = None,
        owner_account: str | None = None,
        binding: str = BINDING_UNKNOWN,
    ) -> str:
        if status not in (STATUS_ACTIVE, STATUS_PENDING):
            raise ValueError("a new device is pending or active")
        measurement = snapshot(evidence, public_key_spki)
        device_id = "dev_" + secrets.token_urlsafe(18)
        now = self._clock()
        try:
            with self._lock, self._conn:
                if self._retired(evidence.leaf_spki_sha256):
                    raise DuplicateDeviceKey("attested key was retired by a rotation")
                self._conn.execute(
                    "INSERT INTO devices (device_id, public_key_spki, spki_sha256, enrolled_at, evidence_json,"
                    " play_signals_json, confirm_key_spki, confirm_evidence_json, status, owner_tenant,"
                    " owner_account, binding, state_changed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        device_id,
                        public_key_spki,
                        evidence.leaf_spki_sha256,
                        int(self._clock()),
                        json.dumps(asdict(evidence), sort_keys=True),
                        json.dumps(play_signals, sort_keys=True) if play_signals is not None else None,
                        confirm_key_spki,
                        json.dumps(asdict(confirm_evidence), sort_keys=True) if confirm_evidence else None,
                        status,
                        owner_tenant,
                        owner_account,
                        binding,
                        int(now),
                    ),
                )
                self._insert_snapshot(device_id, measurement, now)
                self._event(device_id, EVENT_ENROLLED, None, status, "system", binding, now)
        except sqlite3.IntegrityError as exc:
            raise DuplicateDeviceKey("attested key already enrolled") from exc
        return device_id

    def get(self, device_id: str) -> DeviceRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT device_id, public_key_spki, confirm_key_spki, status, enrolled_at, evidence_json,"
                " confirm_evidence_json, play_signals_json, owner_tenant, owner_account, binding,"
                " state_changed_at FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
        if row is None:
            return None
        return DeviceRecord(
            device_id=row[0],
            public_key_spki=row[1],
            confirm_key_spki=row[2],
            status=row[3],
            enrolled_at=row[4],
            evidence=json.loads(row[5]),
            confirm_evidence=json.loads(row[6]) if row[6] else None,
            play_signals=json.loads(row[7]) if row[7] else None,
            owner_tenant=row[8],
            owner_account=row[9],
            binding=row[10] or BINDING_UNKNOWN,
            state_changed_at=row[11],
        )

    def _event(self, device_id, event, from_status, to_status, actor, reason, now) -> None:
        """Caller holds the lock and an open transaction."""
        self._conn.execute(
            "INSERT INTO lifecycle_events (device_id, event, from_status, to_status, actor, reason, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (device_id, event, from_status, to_status, actor, (reason or "")[:64] or None, now),
        )

    def transition(self, device_id: str, event: str, actor: str, reason: str | None = None) -> str | None:
        """Apply one legal lifecycle transition atomically.

        Returns the new status, or None when the device is unknown or its current
        status does not allow ``event`` (nothing is changed then).
        """
        allowed_from, to_status = TRANSITIONS[event]
        now = self._clock()
        with self._lock, self._conn:
            row = self._conn.execute("SELECT status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if row is None or row[0] not in allowed_from:
                return None
            extra = ", revoked_at = ?, revoke_reason = ?" if to_status == STATUS_REVOKED else ""
            params = [to_status, int(now)] + ([int(now), (reason or event)[:200]] if extra else []) + [device_id, row[0]]
            cur = self._conn.execute(
                f"UPDATE devices SET status = ?, state_changed_at = ?{extra} WHERE device_id = ? AND status = ?",
                params,
            )
            if cur.rowcount != 1:
                return None
            self._event(device_id, event, row[0], to_status, actor, reason, now)
        return to_status

    def revoke(self, device_id: str, reason: str, actor: str = "admin") -> bool:
        """Permanently revoke a device. True if it is now revoked; False if it does not exist."""
        if self.transition(device_id, "revoked", actor, reason) is not None:
            return True
        record = self.get(device_id)
        return record is not None and record.status == STATUS_REVOKED

    def lifecycle_events(self, device_id: str, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT event, from_status, to_status, actor, reason, created_at FROM lifecycle_events"
                " WHERE device_id = ? ORDER BY event_id DESC LIMIT ?", (device_id, max(1, min(limit, 200))),
            ).fetchall()
        return [{"event": r[0], "from": r[1], "to": r[2], "actor": r[3], "reason": r[4], "at": r[5]} for r in rows]

    def devices_for(self, tenant: str, account: str, limit: int = 50) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT device_id FROM devices WHERE owner_tenant = ? AND owner_account = ?"
                " ORDER BY enrolled_at DESC LIMIT ?", (tenant, account, max(1, min(limit, 200))),
            ).fetchall()
        return [r[0] for r in rows]

    def touch(self, device_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE devices SET last_action_at = ? WHERE device_id = ?", (int(self._clock()), device_id)
            )

    def record_decision(
        self,
        decision_id: str,
        device_id: str | None,
        kind: str,
        action_type: str | None,
        decision: str,
        risk_score: int | None,
        factors: list[tuple[str, int]],
        reasons: list[str],
    ) -> None:
        """Audit trail of every decision (no action params, no raw signals)."""
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (decision_id, device_id, kind, action_type, decision, risk_score,
                 json.dumps(factors), json.dumps(reasons), self._clock()),
            )

    def count_recent_actions(self, device_id: str, window_seconds: float) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM decisions WHERE device_id = ? AND kind = 'action' AND created_at >= ?",
                (device_id, self._clock() - window_seconds),
            ).fetchone()[0]

    def decisions_for(self, device_id: str, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT decision_id, kind, action_type, decision, risk_score, factors_json, reasons_json, created_at"
                " FROM decisions WHERE device_id = ? ORDER BY created_at DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
        return [
            {"decision_id": r[0], "kind": r[1], "action_type": r[2], "decision": r[3], "risk_score": r[4],
             "factors": [tuple(f) for f in json.loads(r[5])], "reasons": json.loads(r[6]), "created_at": r[7]}
            for r in rows
        ]

    def record_attestation_key(self, key_sha256: str, decision_id: str, model: str | None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO attestation_key_uses VALUES (?, ?, ?, ?)",
                (key_sha256, decision_id, model, self._clock()),
            )

    def attestation_key_stats(self, key_sha256: str, window_seconds: float) -> dict:
        """{"enrollments": attempts in the window, "models": distinct models ever seen}."""
        with self._lock:
            enrollments = self._conn.execute(
                "SELECT COUNT(*) FROM attestation_key_uses WHERE key_sha256 = ? AND created_at >= ?",
                (key_sha256, self._clock() - window_seconds),
            ).fetchone()[0]
            models = [r[0] for r in self._conn.execute(
                "SELECT DISTINCT model FROM attestation_key_uses WHERE key_sha256 = ? AND model IS NOT NULL",
                (key_sha256,),
            )]
        return {"enrollments": enrollments, "models": sorted(models)}

    def record_fleet_event(self, kind: str, decision_id: str, device_id: str | None,
                           network: str | None, cohort: str | None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO fleet_events VALUES (?, ?, ?, ?, ?, ?)",
                (kind, decision_id, device_id, network, cohort, self._clock()),
            )

    def fleet_counts(self, network: str | None, cohort: str | None, window_seconds: float) -> dict:
        """Recent activity around one request's network block and cohort."""
        since = self._clock() - window_seconds
        out = {"network_enrollments": 0, "network_devices": 0, "cohort_enrollments": 0}
        with self._lock:
            if network:
                out["network_enrollments"] = self._conn.execute(
                    "SELECT COUNT(*) FROM fleet_events WHERE network = ? AND kind = 'enrollment' AND created_at >= ?",
                    (network, since),
                ).fetchone()[0]
                out["network_devices"] = self._conn.execute(
                    "SELECT COUNT(DISTINCT device_id) FROM fleet_events"
                    " WHERE network = ? AND kind = 'action' AND device_id IS NOT NULL AND created_at >= ?",
                    (network, since),
                ).fetchone()[0]
            if cohort:
                out["cohort_enrollments"] = self._conn.execute(
                    "SELECT COUNT(*) FROM fleet_events WHERE cohort = ? AND kind = 'enrollment' AND created_at >= ?",
                    (cohort, since),
                ).fetchone()[0]
        return out

    def fleet_summary(self, window_seconds: float, limit: int = 10) -> dict:
        """Busiest network blocks, cohorts and attestation keys in the window."""
        since = self._clock() - window_seconds
        with self._lock:
            networks = self._conn.execute(
                "SELECT network, SUM(kind = 'enrollment'), COUNT(DISTINCT device_id) FROM fleet_events"
                " WHERE network IS NOT NULL AND created_at >= ? GROUP BY network"
                " ORDER BY 2 DESC, 3 DESC LIMIT ?",
                (since, limit),
            ).fetchall()
            cohorts = self._conn.execute(
                "SELECT cohort, COUNT(*) FROM fleet_events WHERE kind = 'enrollment' AND cohort IS NOT NULL"
                " AND created_at >= ? GROUP BY cohort ORDER BY 2 DESC LIMIT ?",
                (since, limit),
            ).fetchall()
            keys = self._conn.execute(
                "SELECT key_sha256, COUNT(*), COUNT(DISTINCT model) FROM attestation_key_uses WHERE created_at >= ?"
                " GROUP BY key_sha256 ORDER BY 3 DESC, 2 DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        return {
            "windowSeconds": window_seconds,
            "networks": [{"network": n, "enrollments": e, "devices": d} for n, e, d in networks],
            "cohorts": [{"cohort": c, "enrollments": e} for c, e in cohorts],
            "attestationKeys": [{"key": k[:16], "enrollments": e, "models": m} for k, e, m in keys],
        }

    def assurance_history(self, device_id: str, limit: int = 20) -> list[dict]:
        """Newest first. Ties (same clock tick) are ordered by insertion."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT snapshot_json, created_at FROM assurance_snapshots WHERE device_id = ? "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?", (device_id, max(1, min(limit, 100))),
            ).fetchall()
        return [{"evidence": json.loads(row[0]), "at": row[1]} for row in rows]

    # --- Run 17: refresh snapshots, key continuity --------------------------------

    def _retired(self, spki_sha256: str) -> bool:
        """Caller holds the lock."""
        return self._conn.execute(
            "SELECT 1 FROM retired_keys WHERE spki_sha256 = ?", (spki_sha256,)).fetchone() is not None

    def key_known(self, spki_sha256: str) -> bool:
        """True if this key is, or was, a device key here (enrolled or retired by rotation)."""
        with self._lock:
            return self._retired(spki_sha256) or self._conn.execute(
                "SELECT 1 FROM devices WHERE spki_sha256 = ?", (spki_sha256,)).fetchone() is not None

    def _insert_snapshot(self, device_id: str, measurement: dict, now: float, keep: int | None = None) -> None:
        """Caller holds the lock and an open transaction.

        Retention: enrollment and key-rotation snapshots (the continuity chain) are never
        pruned; at most ``keep`` scan-refresh snapshots are kept per device.
        """
        self._conn.execute(
            "INSERT INTO assurance_snapshots (device_id, snapshot_json, created_at, source) VALUES (?, ?, ?, ?)",
            (device_id, json.dumps(measurement, sort_keys=True), now, measurement.get("source")),
        )
        if keep is not None:
            self._conn.execute(
                "DELETE FROM assurance_snapshots WHERE device_id = ? AND source = 'scan_refresh' AND rowid NOT IN"
                " (SELECT rowid FROM assurance_snapshots WHERE device_id = ? AND source = 'scan_refresh'"
                "  ORDER BY created_at DESC, rowid DESC LIMIT ?)",
                (device_id, device_id, max(1, int(keep))),
            )

    def record_snapshot(self, device_id: str, measurement: dict, keep: int) -> None:
        """Store a verified scan-refresh snapshot for an existing device."""
        if measurement.get("source") in (SOURCE_ENROLLMENT, SOURCE_KEY_ROTATION):
            raise ValueError("enrollment and rotation snapshots are written with their registry change")
        with self._lock, self._conn:
            self._insert_snapshot(device_id, measurement, self._clock(), keep)

    def rotate_key(
        self,
        device_id: str,
        old_spki_sha256: str,
        public_key_spki: bytes,
        evidence: AttestationEvidence,
        confirm_key_spki: bytes | None,
        confirm_evidence: AttestationEvidence | None,
    ) -> bool:
        """Replace the device key the old key authorised, atomically.

        Compare-and-swap on (device, current key, active): of concurrent rotations from
        one old key exactly one succeeds. The old key is retired forever. Returns False
        when the device is no longer active with that key.
        Raises DuplicateDeviceKey if the new key is or was enrolled anywhere.
        """
        measurement = snapshot(evidence, public_key_spki, source=SOURCE_KEY_ROTATION,
                               authorized_by_sha256=old_spki_sha256)
        now = self._clock()
        try:
            with self._lock, self._conn:
                if self._retired(evidence.leaf_spki_sha256):
                    raise DuplicateDeviceKey("attested key was retired by a rotation")
                cur = self._conn.execute(
                    "UPDATE devices SET public_key_spki = ?, spki_sha256 = ?, evidence_json = ?,"
                    " confirm_key_spki = ?, confirm_evidence_json = ?"
                    " WHERE device_id = ? AND spki_sha256 = ? AND status = ?",
                    (public_key_spki, evidence.leaf_spki_sha256, json.dumps(asdict(evidence), sort_keys=True),
                     confirm_key_spki,
                     json.dumps(asdict(confirm_evidence), sort_keys=True) if confirm_evidence else None,
                     device_id, old_spki_sha256, STATUS_ACTIVE),
                )
                if cur.rowcount != 1:
                    return False
                self._conn.execute("INSERT INTO retired_keys VALUES (?, ?, ?)", (old_spki_sha256, device_id, now))
                self._insert_snapshot(device_id, measurement, now)
                self._event(device_id, EVENT_KEY_ROTATED, STATUS_ACTIVE, STATUS_ACTIVE, "system", None, now)
        except sqlite3.IntegrityError as exc:
            raise DuplicateDeviceKey("attested key already enrolled") from exc
        return True

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
