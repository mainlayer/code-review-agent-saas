"""Mainlayer per-review billing.

Each call to a paid endpoint triggers a charge via the Mainlayer API.
The module reads MAINLAYER_API_KEY from the environment and delegates to
the MainlayerClient defined in mainlayer.py.
"""

from __future__ import annotations

import logging
import os

from .mainlayer import (
    MainlayerClient,
    PaymentRequiredError,
    PaymentResult,
    get_client,
)

logger = logging.getLogger(__name__)

MAINLAYER_API_KEY = os.getenv("MAINLAYER_API_KEY", "")


async def charge_review(
    *,
    token: str,
    amount_usd: float,
    endpoint: str,
) -> PaymentResult:
    """Charge the caller for a review endpoint.

    In production, `token` is a Mainlayer payment token passed in the
    ``x-mainlayer-token`` header. The function delegates to the async
    Mainlayer client and re-raises ``PaymentRequiredError`` on failure so
    that the FastAPI layer can return a clean 402 response.

    When MAINLAYER_API_KEY is absent (dev / test) the charge is skipped and
    a synthetic PaymentResult is returned.
    """
    if not MAINLAYER_API_KEY:
        logger.debug("Dev mode: skipping charge of $%.4f for %s", amount_usd, endpoint)
        return PaymentResult(
            transaction_id=f"dev-{endpoint.replace('/', '-')}",
            amount_usd=amount_usd,
            endpoint=endpoint,
            status="approved",
        )

    client = get_client()
    try:
        result = await client.require_payment_async(
            amount_usd=amount_usd,
            endpoint=endpoint,
            caller_id=token,
            metadata={"token": token[:12] + "..."},
        )
        logger.info("Charged $%.4f for %s txn=%s", amount_usd, endpoint, result.transaction_id)
        return result
    except PaymentRequiredError:
        raise  # caller converts to HTTP 402
