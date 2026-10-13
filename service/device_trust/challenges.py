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
    # None for enrollment challenges; the device ID for action challenges, so a
    # nonce issued to one device (or for enrollment) cannot be used elsewhere.
    bound_to: str | None = None


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

    def issue(self, bound_to: str | None = None, ttl_seconds: int | None = None) -> Challenge:
        now = self._clock()
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        challenge = Challenge(secrets.token_urlsafe(24), secrets.token_bytes(NONCE_BYTES), now + ttl, bound_to)
        with self._lock:
            if len(self._items) >= self._max:
                self._purge(now)
                if len(self._items) >= self._max:
                    raise ChallengeCapacityExceeded("too many outstanding challenges")
            self._items[challenge.challenge_id] = challenge
        return challenge

    def consume(self, challenge_id: str, bound_to: str | None = None) -> bytes | None:
        """Return the nonce once; unknown, reused, expired or mis-bound IDs return None.

        A challenge is removed on any lookup, even a mis-bound one, so it can
        never be retried.
        """
        with self._lock:
            challenge = self._items.pop(challenge_id, None)
        if challenge is None or challenge.expires_at <= self._clock() or challenge.bound_to != bound_to:
            return None
        return challenge.nonce
