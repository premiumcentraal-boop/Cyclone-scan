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

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
