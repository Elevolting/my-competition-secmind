"""Usage aggregation that preserves provider-vs-conservative provenance."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from secmind.model_gateway.budget import merge_usage
from secmind.model_gateway.contracts import ProviderAttempt, RawModelResponseReceipt
from secmind.schemas import ModelUsage


@dataclass(frozen=True, slots=True)
class UsageProvenance:
    settled: ModelUsage = field(default_factory=ModelUsage)
    provider_reported: ModelUsage = field(default_factory=ModelUsage)
    conservative_reserved: ModelUsage = field(default_factory=ModelUsage)
    unknown_attempts: int = 0

    @classmethod
    def from_attempts(cls, attempts: Iterable[ProviderAttempt]) -> UsageProvenance:
        values = tuple(attempts)
        return cls(
            settled=merge_usage(*(item.usage for item in values)),
            provider_reported=merge_usage(*(item.provider_reported_usage for item in values)),
            conservative_reserved=merge_usage(*(item.conservative_reserved_usage for item in values)),
            unknown_attempts=sum(item.unknown_usage for item in values),
        )

    @classmethod
    def from_receipt(cls, receipt: RawModelResponseReceipt) -> UsageProvenance:
        if receipt.schema_version == "1.0":
            return cls(
                settled=receipt.usage,
                conservative_reserved=receipt.usage,
                unknown_attempts=receipt.usage.provider_requests,
            )
        return cls(
            settled=receipt.usage,
            provider_reported=receipt.provider_reported_usage,
            conservative_reserved=receipt.conservative_reserved_usage,
            unknown_attempts=receipt.unknown_usage_attempts,
        )

    def merge(self, other: UsageProvenance) -> UsageProvenance:
        return UsageProvenance(
            settled=merge_usage(self.settled, other.settled),
            provider_reported=merge_usage(self.provider_reported, other.provider_reported),
            conservative_reserved=merge_usage(
                self.conservative_reserved,
                other.conservative_reserved,
            ),
            unknown_attempts=self.unknown_attempts + other.unknown_attempts,
        )


__all__ = ["UsageProvenance"]
