"""Compatibility facade for content-addressed failure capsules."""

from secmind.quarantine import (
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
    "CapsuleConflictError",
    "CapsuleError",
    "CapsuleIntegrityError",
    "FailureCapsule",
    "FailureCapsuleError",
    "FailureCapsuleStore",
    "capture_failure_capsule",
    "scrub_failure_payload",
]
