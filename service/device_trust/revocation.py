"""Google attestation certificate revocation list (CRL-like JSON status list).

Format: ``{"entries": {"<lowercase hex serial>": {"status": "REVOKED", "reason": ...}}}``.
Leaked keyboxes used by attestation spoofers end up here, so a stale list must
fail closed rather than silently accepting everything.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Callable

GOOGLE_STATUS_URL = "https://android.googleapis.com/attestation/status"


class RevocationUnavailable(RuntimeError):
    """The revocation list could not be loaded or is older than allowed."""


def serial_key(serial_number: int) -> str:
    return format(serial_number, "x")


def _http_fetch(url: str, timeout: float = 15.0) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
        return resp.read()


class RevocationList:
    def __init__(
        self,
        *,
        url: str = GOOGLE_STATUS_URL,
        refresh_seconds: int = 3600,
        max_age_seconds: int = 48 * 3600,
        retry_seconds: int = 60,
        fetch: Callable[[str], bytes] = _http_fetch,
        clock: Callable[[], float] = time.time,
    ):
        self._url = url
        self._refresh_seconds = refresh_seconds
        self._max_age_seconds = max_age_seconds
        self._retry_seconds = retry_seconds
        self._next_attempt = 0.0
        self._fetch = fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = {}
        self._loaded_at: float | None = None

    @classmethod
    def static(cls, entries: dict[str, dict]) -> "RevocationList":
        """A fixed list (tests, air-gapped deployments with an external refresher)."""
        rl = cls(fetch=lambda _url: b"", refresh_seconds=10**12, max_age_seconds=10**12)
        rl.load_document({"entries": entries})
        return rl

    def load_document(self, document: dict) -> None:
        entries = document.get("entries")
        if not isinstance(entries, dict):
            raise ValueError("revocation document has no 'entries' object")
        normalized = {str(k).lower().lstrip("0") or "0": v for k, v in entries.items()}
        with self._lock:
            self._entries = normalized
            self._loaded_at = self._clock()

    def refresh(self) -> None:
        self.load_document(json.loads(self._fetch(self._url)))

    def _ensure_fresh(self) -> None:
        now = self._clock()
        loaded = self._loaded_at
        stale = loaded is None or now - loaded >= self._max_age_seconds
        due = loaded is None or now - loaded >= self._refresh_seconds
        if not due:
            return
        if now < self._next_attempt:
            # Back off after a failed fetch instead of hitting Google on every request.
            if stale:
                raise RevocationUnavailable("revocation list unavailable or stale")
            return
        try:
            self.refresh()
        except Exception as exc:  # network/JSON failure
            self._next_attempt = now + self._retry_seconds
            if stale:
                raise RevocationUnavailable("revocation list unavailable or stale") from exc

    def status(self, serial_number: int) -> dict | None:
        """Return the entry for a revoked/suspended serial, else None."""
        self._ensure_fresh()
        with self._lock:
            return self._entries.get(serial_key(serial_number))

    def __len__(self) -> int:
        return len(self._entries)
