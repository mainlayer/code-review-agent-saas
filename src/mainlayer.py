"""
Mainlayer payment integration for the Code Review Agent SaaS.

Mainlayer is the monetisation layer for AI agents. Every paid endpoint
calls `require_payment` before serving the response. The function raises
`PaymentRequiredError` when the caller has insufficient credits, letting
FastAPI return a clean 402 response.

Base URL: https://api.mainlayer.xyz
Auth:     Authorization: Bearer <api_key>
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

MAINLAYER_BASE_URL = os.getenv("MAINLAYER_BASE_URL", "https://api.mainlayer.xyz")
MAINLAYER_API_KEY = os.getenv("MAINLAYER_API_KEY", "")

# Price catalogue (USD)
PRICE_CODE_REVIEW = 0.05   # POST /review
PRICE_PR_REVIEW = 0.10     # POST /review/pr
PRICE_FILE_REVIEW = 0.05   # POST /review/file


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class MainlayerError(Exception):
    """Base class for Mainlayer integration errors."""


class PaymentRequiredError(MainlayerError):
    """Raised when the caller has insufficient credits or the payment fails."""

    def __init__(self, message: str, amount_usd: float, endpoint: str) -> None:
        super().__init__(message)
        self.amount_usd = amount_usd
        self.endpoint = endpoint


class MainlayerAuthError(MainlayerError):
    """Raised when the Mainlayer API key is invalid or missing."""


class MainlayerUnavailableError(MainlayerError):
    """Raised when the Mainlayer service cannot be reached."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class PaymentResult:
    transaction_id: str
    amount_usd: float
    endpoint: str
    status: str  # "approved" | "refunded"


@dataclass
class UsageRecord:
    caller_id: str
    endpoint: str
    amount_usd: float
    transaction_id: str


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class MainlayerClient:
    """
    Thin HTTP client wrapping the Mainlayer agent-monetisation API.

    All network calls are synchronous (via httpx) so they integrate cleanly
    with FastAPI's thread-pool for sync route handlers. Async usage is
    supported via `require_payment_async`.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._api_key = api_key or MAINLAYER_API_KEY
        self._base_url = (base_url or MAINLAYER_BASE_URL).rstrip("/")
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        if not self._api_key:
            raise MainlayerAuthError(
                "MAINLAYER_API_KEY is not set. "
                "Set it in your environment or .env file."
            )
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": "code-review-agent-saas/1.0",
        }

    def _handle_response(self, response: httpx.Response, amount_usd: float, endpoint: str) -> PaymentResult:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 402:
                raise PaymentRequiredError(
                    f"Payment of ${amount_usd:.2f} required for {endpoint}. "
                    "Top up your Mainlayer balance at https://mainlayer.xyz/dashboard",
                    amount_usd=amount_usd,
                    endpoint=endpoint,
                ) from exc
            if status in (401, 403):
                raise MainlayerAuthError(
                    "Invalid or missing Mainlayer API key."
                ) from exc
            raise MainlayerUnavailableError(
                f"Mainlayer returned HTTP {status}: {exc.response.text[:200]}"
            ) from exc

        data = response.json()
        return PaymentResult(
            transaction_id=data.get("transaction_id", str(uuid.uuid4())),
            amount_usd=amount_usd,
            endpoint=endpoint,
            status=data.get("status", "approved"),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def require_payment(
        self,
        amount_usd: float,
        endpoint: str,
        caller_id: str | None = None,
        metadata: dict | None = None,
    ) -> PaymentResult:
        """
        Charge the caller `amount_usd` for access to `endpoint`.

        Raises `PaymentRequiredError` if the charge cannot be completed.
        """
        payload = {
            "amount": amount_usd,
            "currency": "usd",
            "endpoint": endpoint,
            "caller_id": caller_id or "anonymous",
            "metadata": metadata or {},
        }
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    f"{self._base_url}/v1/charge",
                    json=payload,
                    headers=self._headers(),
                )
        except httpx.TimeoutException as exc:
            raise MainlayerUnavailableError(
                "Mainlayer payment service timed out. Please retry."
            ) from exc
        except httpx.RequestError as exc:
            raise MainlayerUnavailableError(
                f"Could not reach Mainlayer: {exc}"
            ) from exc

        return self._handle_response(response, amount_usd, endpoint)

    def get_balance(self, caller_id: str | None = None) -> float:
        """Return the current USD balance for the given caller."""
        params = {}
        if caller_id:
            params["caller_id"] = caller_id
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.get(
                    f"{self._base_url}/v1/balance",
                    params=params,
                    headers=self._headers(),
                )
                response.raise_for_status()
        except httpx.RequestError as exc:
            raise MainlayerUnavailableError(str(exc)) from exc

        return response.json().get("balance_usd", 0.0)

    def refund(self, transaction_id: str) -> PaymentResult:
        """Refund a previous transaction."""
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    f"{self._base_url}/v1/refund",
                    json={"transaction_id": transaction_id},
                    headers=self._headers(),
                )
                response.raise_for_status()
        except httpx.RequestError as exc:
            raise MainlayerUnavailableError(str(exc)) from exc

        data = response.json()
        return PaymentResult(
            transaction_id=transaction_id,
            amount_usd=data.get("amount_usd", 0.0),
            endpoint=data.get("endpoint", ""),
            status="refunded",
        )

    async def require_payment_async(
        self,
        amount_usd: float,
        endpoint: str,
        caller_id: str | None = None,
        metadata: dict | None = None,
    ) -> PaymentResult:
        """Async variant of `require_payment`."""
        payload = {
            "amount": amount_usd,
            "currency": "usd",
            "endpoint": endpoint,
            "caller_id": caller_id or "anonymous",
            "metadata": metadata or {},
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._base_url}/v1/charge",
                    json=payload,
                    headers=self._headers(),
                )
        except httpx.TimeoutException as exc:
            raise MainlayerUnavailableError(
                "Mainlayer payment service timed out. Please retry."
            ) from exc
        except httpx.RequestError as exc:
            raise MainlayerUnavailableError(str(exc)) from exc

        return self._handle_response(response, amount_usd, endpoint)


# ---------------------------------------------------------------------------
# Module-level convenience helpers
# ---------------------------------------------------------------------------

_default_client: MainlayerClient | None = None


def get_client() -> MainlayerClient:
    """Return the module-level singleton client."""
    global _default_client
    if _default_client is None:
        _default_client = MainlayerClient()
    return _default_client


def require_payment(
    amount_usd: float,
    endpoint: str,
    caller_id: str | None = None,
    metadata: dict | None = None,
) -> PaymentResult:
    """Convenience wrapper around the default client."""
    return get_client().require_payment(
        amount_usd=amount_usd,
        endpoint=endpoint,
        caller_id=caller_id,
        metadata=metadata,
    )
