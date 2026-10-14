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
from .evidence_history import snapshot

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"

_SCHEMA = """
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

# Columns added after Phase 1; applied in place to existing databases.
_MIGRATIONS = (
    ("confirm_key_spki", "BLOB"),
    ("confirm_evidence_json", "TEXT"),
    ("status", f"TEXT NOT NULL DEFAULT '{STATUS_ACTIVE}'"),
    ("revoked_at", "INTEGER"),
    ("revoke_reason", "TEXT"),
    ("last_action_at", "INTEGER"),
)


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

    @property
    def active(self) -> bool:
        return self.status == STATUS_ACTIVE


class DeviceRegistry:
    def __init__(self, path: str | Path = ":memory:", clock=time.time):
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._clock = clock
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)
            existing = {row[1] for row in self._conn.execute("PRAGMA table_info(devices)")}
            for column, decl in _MIGRATIONS:
                if column not in existing:
                    self._conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {decl}")

    def register(
        self,
        public_key_spki: bytes,
        evidence: AttestationEvidence,
        play_signals: dict | None,
        confirm_key_spki: bytes | None = None,
        confirm_evidence: AttestationEvidence | None = None,
    ) -> str:
        measurement = snapshot(evidence, public_key_spki)
        device_id = "dev_" + secrets.token_urlsafe(18)
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    "INSERT INTO devices (device_id, public_key_spki, spki_sha256, enrolled_at, evidence_json,"
                    " play_signals_json, confirm_key_spki, confirm_evidence_json, status)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        device_id,
                        public_key_spki,
                        evidence.leaf_spki_sha256,
                        int(self._clock()),
                        json.dumps(asdict(evidence), sort_keys=True),
                        json.dumps(play_signals, sort_keys=True) if play_signals is not None else None,
                        confirm_key_spki,
                        json.dumps(asdict(confirm_evidence), sort_keys=True) if confirm_evidence else None,
                        STATUS_ACTIVE,
                    ),
                )
                self._conn.execute("INSERT INTO assurance_snapshots VALUES (?, ?, ?)",
                                   (device_id, json.dumps(measurement, sort_keys=True), self._clock()))
        except sqlite3.IntegrityError as exc:
            raise DuplicateDeviceKey("attested key already enrolled") from exc
        return device_id

    def get(self, device_id: str) -> DeviceRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT device_id, public_key_spki, confirm_key_spki, status, enrolled_at, evidence_json,"
                " confirm_evidence_json, play_signals_json FROM devices WHERE device_id = ?",
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
        )

    def revoke(self, device_id: str, reason: str) -> bool:
        """Permanently revoke a device. Returns False if it does not exist."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE devices SET status = ?, revoked_at = ?, revoke_reason = ? WHERE device_id = ?",
                (STATUS_REVOKED, int(self._clock()), reason[:200], device_id),
            )
        return cur.rowcount == 1

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
        with self._lock:
            rows = self._conn.execute(
                "SELECT snapshot_json, created_at FROM assurance_snapshots WHERE device_id = ? "
                "ORDER BY created_at DESC LIMIT ?", (device_id, max(1, min(limit, 100))),
            ).fetchall()
        return [{"evidence": json.loads(row[0]), "at": row[1]} for row in rows]

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
