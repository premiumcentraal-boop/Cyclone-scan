"""Enrolled-device registry (SQLite).

Stores the attested public key so Phase 2 can verify per-action signatures
from the same hardware key. Only privacy-safe attestation evidence is stored:
no serial, IMEI, MEID or raw tokens.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from dataclasses import asdict
from pathlib import Path

from .attestation import AttestationEvidence

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


class DuplicateDeviceKey(RuntimeError):
    pass


class DeviceRegistry:
    def __init__(self, path: str | Path = ":memory:"):
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)

    def register(
        self,
        public_key_spki: bytes,
        evidence: AttestationEvidence,
        play_signals: dict | None,
    ) -> str:
        device_id = "dev_" + secrets.token_urlsafe(18)
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    "INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        device_id,
                        public_key_spki,
                        evidence.leaf_spki_sha256,
                        int(time.time()),
                        json.dumps(asdict(evidence), sort_keys=True),
                        json.dumps(play_signals, sort_keys=True) if play_signals is not None else None,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateDeviceKey("attested key already enrolled") from exc
        return device_id

    def get(self, device_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT device_id, public_key_spki, enrolled_at, evidence_json, play_signals_json "
                "FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "device_id": row[0],
            "public_key_spki": row[1],
            "enrolled_at": row[2],
            "evidence": json.loads(row[3]),
            "play_signals": json.loads(row[4]) if row[4] else None,
        }

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
