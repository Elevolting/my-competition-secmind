"""Internal model-gateway building blocks.

The public compatibility surface remains :mod:`secmind.llm`.  This package
contains the small, dependency-directed pieces used by that facade: durable
contracts, response recovery, budget accounting, diagnostics, and provider
transport helpers.
"""

from secmind.model_gateway.contracts import (
    DurableReceiptError,
    ModelAttemptSummary,
    ModelCallMeta,
    ModelGatewayError,
    ModelGatewayFailure,
    ModelReadIdleTimeout,
    ModelResponseTooLargeError,
    ProviderAttempt,
    RawModelResponseReceipt,
    RetryableModelError,
)

__all__ = [
    "DurableReceiptError",
    "ModelAttemptSummary",
    "ModelCallMeta",
    "ModelGatewayError",
    "ModelGatewayFailure",
    "ModelReadIdleTimeout",
    "ModelResponseTooLargeError",
    "ProviderAttempt",
    "RawModelResponseReceipt",
    "RetryableModelError",
]
