"""Single-use, short-lived attestation challenges.

In-memory store for a single instance. For multiple instances, back this with
a shared store (e.g. Redis ``SET NX EX`` + ``GETDEL``) behind the same API.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

NONCE_BYTES = 32


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    nonce: bytes
    expires_at: float


class ChallengeCapacityExceeded(RuntimeError):
    pass


class ChallengeStore:
    def __init__(self, ttl_seconds: int, *, max_outstanding: int = 100_000, clock: Callable[[], float] = time.time):
        self._ttl = ttl_seconds
        self._max = max_outstanding
        self._clock = clock
        self._lock = threading.Lock()
        self._items: dict[str, Challenge] = {}

    def _purge(self, now: float) -> None:
        expired = [k for k, c in self._items.items() if c.expires_at <= now]
        for k in expired:
            del self._items[k]

    def issue(self) -> Challenge:
        now = self._clock()
        challenge = Challenge(secrets.token_urlsafe(24), secrets.token_bytes(NONCE_BYTES), now + self._ttl)
        with self._lock:
            if len(self._items) >= self._max:
                self._purge(now)
                if len(self._items) >= self._max:
                    raise ChallengeCapacityExceeded("too many outstanding challenges")
            self._items[challenge.challenge_id] = challenge
        return challenge

    def consume(self, challenge_id: str) -> bytes | None:
        """Return the nonce once; unknown, reused or expired IDs return None."""
        with self._lock:
            challenge = self._items.pop(challenge_id, None)
        if challenge is None or challenge.expires_at <= self._clock():
            return None
        return challenge.nonce
