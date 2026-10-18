"""Compatibility imports for the quarantine FailureCapsule contract."""

from secmind.quarantine import (
    CAPSULE_STORE_VERSION,
    DEFAULT_MAX_CAPSULE_BYTES,
    DEFAULT_MAX_PAYLOAD_BYTES,
    SCHEMA_VERSION,
    CapsuleConflictError,
    CapsuleError,
    CapsuleIntegrityError,
    FailureCapsule,
    FailureCapsuleError,
    FailureCapsuleStore,
    capture_failure_capsule,
    scrub_failure_payload,
)

__all__ = [
    "CAPSULE_STORE_VERSION",
    "DEFAULT_MAX_CAPSULE_BYTES",
    "DEFAULT_MAX_PAYLOAD_BYTES",
    "SCHEMA_VERSION",
    "CapsuleConflictError",
    "CapsuleError",
    "CapsuleIntegrityError",
    "FailureCapsule",
    "FailureCapsuleError",
    "FailureCapsuleStore",
    "capture_failure_capsule",
    "scrub_failure_payload",
]
