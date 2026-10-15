"""Device lifecycle (Run 16): states, legal transitions and the account principal.

States
    pending  -- enrolled but not yet trusted for protected actions: a STEP_UP
                enrollment awaiting authenticated step-up completion, or (by
                policy) an enrollment without Run 20 evidence binding.
    active   -- may request action challenges and perform protected actions.
    revoked  -- terminal. Never revived; the same attested key cannot enroll
                again (its SPKI stays unique), a new key is a new device.

Legal transitions (anything else is refused)::

    (new) --enrolled--> pending | active
    pending --step_up_completed--> active
    pending --revoked | pending_expired--> revoked
    active  --revoked--> revoked
    active  --key_rotated--> active   (Run 17: old key signed for the new key)

The principal (tenant + account) comes only from the authenticated gateway
context that the customer's backend supplies; a client-supplied account
identifier is never trusted on its own. A device enrolled without a principal
is "ownerless": usable only in principal-less (development) deployments.
Matching model or boot facts never proves two keys share one phone, so
lifecycle decisions are always about one enrolled key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"
STATUSES = frozenset({STATUS_PENDING, STATUS_ACTIVE, STATUS_REVOKED})

BINDING_BOUND = "BOUND"                    # Run 20 enrollment proof verified
BINDING_LEGACY_UNBOUND = "LEGACY_UNBOUND"  # enrolled without a proof in legacy mode
BINDING_UNKNOWN = "UNKNOWN"                # enrolled before Run 16 recorded binding

# Lifecycle event vocabulary (bounded; no action parameters or secrets).
EVENT_ENROLLED = "enrolled"
EVENT_STEP_UP_COMPLETED = "step_up_completed"
EVENT_REVOKED = "revoked"
EVENT_PENDING_EXPIRED = "pending_expired"
# Run 17: the enrolled key authorised a new attested key (active -> active).
# Not a status transition, so it is not in TRANSITIONS; the registry applies it
# as one compare-and-swap on the current key.
EVENT_KEY_ROTATED = "key_rotated"

TRANSITIONS: dict[str, tuple[frozenset[str], str]] = {
    EVENT_STEP_UP_COMPLETED: (frozenset({STATUS_PENDING}), STATUS_ACTIVE),
    EVENT_REVOKED: (frozenset({STATUS_PENDING, STATUS_ACTIVE}), STATUS_REVOKED),
    EVENT_PENDING_EXPIRED: (frozenset({STATUS_PENDING}), STATUS_REVOKED),
}

ACTORS = frozenset({"system", "gateway", "admin"})
STEP_UP_METHODS = frozenset({"OTP", "PASSWORD", "BIOMETRIC_ACCOUNT", "SUPPORT_VERIFIED", "DOCUMENT_CHECK"})
REVOKE_REASONS = frozenset({"LOST", "USER_REQUEST", "SUSPECTED_COMPROMISE", "ACCOUNT_CLOSED", "ADMIN", "OTHER"})

_ID = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")


@dataclass(frozen=True)
class Principal:
    """Server-side ownership context, set by the authenticated gateway."""

    tenant: str
    account: str

    def __post_init__(self) -> None:
        if not _ID.match(self.tenant or "") or not _ID.match(self.account or ""):
            raise ValueError("invalid principal identifier")

    @property
    def binding_key(self) -> str:
        """Challenge binding for enrollment challenges issued to this principal."""
        return f"enroll:{self.tenant}/{self.account}"


def owns(principal: Principal | None, owner_tenant: str | None, owner_account: str | None) -> bool:
    """True if the request may see/act on a device with this owner.

    Ownerless devices are reachable only without a principal (development
    mode); owned devices only by the same tenant *and* account. A principal
    never claims an ownerless device.
    """
    if principal is None:
        return owner_account is None and owner_tenant is None
    return owner_tenant == principal.tenant and owner_account == principal.account
