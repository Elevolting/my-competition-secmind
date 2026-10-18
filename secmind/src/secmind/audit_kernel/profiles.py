from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AuditProfileName = Literal["core", "extended"]


@dataclass(frozen=True, slots=True)
class AuditCapabilityProfile:
    """Frozen capability scope shared by Direct and integrated audit arms."""

    name: AuditProfileName
    target_cwes: tuple[int, ...]
    gain_cwes: tuple[int, ...]


CORE_TARGET_CWES = (22, 78, 79, 89)
EXTENDED_TARGET_CWES = (22, 78, 79, 89, 90, 327, 328, 330, 501, 614)

_PROFILES: dict[AuditProfileName, AuditCapabilityProfile] = {
    "core": AuditCapabilityProfile(
        name="core",
        target_cwes=CORE_TARGET_CWES,
        gain_cwes=CORE_TARGET_CWES,
    ),
    "extended": AuditCapabilityProfile(
        name="extended",
        target_cwes=EXTENDED_TARGET_CWES,
        gain_cwes=EXTENDED_TARGET_CWES,
    ),
}


CWE_REVIEW_GUIDANCE: dict[int, str] = {
    22: "untrusted path reaches a filesystem operation without effective containment",
    78: "untrusted data controls an operating-system command or command argument",
    79: "untrusted data reaches an HTML response without context-appropriate encoding",
    89: "untrusted data changes SQL structure instead of a bound parameter",
    90: "untrusted data changes an LDAP search filter without LDAP escaping",
    327: "a deprecated or broken cipher is selected for a security operation",
    328: "a weak one-way hash such as MD5 or SHA-1 is selected for security use",
    330: "predictable randomness is used where an unpredictable security value is required",
    501: "untrusted data crosses into a trusted session or server-side trust boundary",
    614: "a security-sensitive cookie is explicitly transmitted without the Secure flag",
}


def resolve_audit_profile(name: AuditProfileName | str) -> AuditCapabilityProfile:
    try:
        return _PROFILES[name]  # type: ignore[index]
    except KeyError as exc:
        raise ValueError(f"unknown audit capability profile: {name!r}") from exc
