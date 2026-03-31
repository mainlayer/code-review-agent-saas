"""Code Review Agent SaaS — FastAPI application.

Endpoints
---------
POST /review          — review a raw code snippet ($0.05/call)
POST /review/pr       — review a unified diff ($0.10/call)
POST /review/file     — review an uploaded file ($0.05/call)
GET  /capabilities    — supported languages and focus areas (free)
GET  /health          — health probe (free)
"""

from __future__ import annotations

import logging
import os
import uuid

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .billing import charge_review
from .models import (
    CapabilitiesResponse,
    CodeReviewRequest,
    CodeReviewResponse,
    ErrorDetail,
    FileReviewRequest,
    FileReviewResponse,
    LanguageCapability,
    PRReviewRequest,
    PRReviewResponse,
    ReviewFocus,
)
from .reviewer import (
    SUPPORTED_LANGUAGES,
    review_code,
    review_file,
    review_pr,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("code-review-agent")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Code Review Agent SaaS",
    description=(
        "AI-powered code review API with per-call billing via Mainlayer. "
        "Detects security issues, performance problems, and style violations."
    ),
    version="1.0.0",
    contact={"name": "Mainlayer", "url": "https://mainlayer.fr"},
    license_info={"name": "MIT"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Payment dependency
# ---------------------------------------------------------------------------

PRICE_CODE_REVIEW = float(os.getenv("PRICE_CODE_REVIEW", "0.05"))
PRICE_PR_REVIEW = float(os.getenv("PRICE_PR_REVIEW", "0.10"))
PRICE_FILE_REVIEW = float(os.getenv("PRICE_FILE_REVIEW", "0.05"))


async def _require_payment(
    amount_usd: float,
    endpoint: str,
    x_mainlayer_token: str = "",
) -> None:
    """Raise 402 if no payment token is present."""
    if not x_mainlayer_token:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={"error": "payment_required", "info": "mainlayer.fr", "amount_usd": amount_usd},
        )
    await charge_review(token=x_mainlayer_token, amount_usd=amount_usd, endpoint=endpoint)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.post(
    "/review",
    response_model=CodeReviewResponse,
    tags=["Review"],
    summary=f"Review a code snippet (${PRICE_CODE_REVIEW}/call)",
    responses={402: {"model": ErrorDetail, "description": "Payment required"}},
)
async def review_code_endpoint(
    body: CodeReviewRequest,
    x_mainlayer_token: str = Header(default="", alias="x-mainlayer-token"),
) -> CodeReviewResponse:
    """Review a raw source-code snippet.

    Supply `x-mainlayer-token` in the request header. The token is charged
    $0.05 per call. Specify `focus` to narrow the analysis to security,
    performance, or style.
    """
    await _require_payment(PRICE_CODE_REVIEW, "/review", x_mainlayer_token)

    request_id = str(uuid.uuid4())
    result = review_code(
        code=body.code,
        language=body.language,
        focus=body.focus,
        request_id=request_id,
    )

    logger.info(
        "review: request_id=%s language=%s issues=%d score=%.1f",
        request_id,
        body.language,
        result["summary"].total_issues,
        result["summary"].score,
    )

    return CodeReviewResponse(
        request_id=result["request_id"],
        language=result["language"],
        focus=result["focus"],
        issues=result["issues"],
        summary=result["summary"],
        recommendations=result["recommendations"],
        positive_aspects=result["positive_aspects"],
    )


@app.post(
    "/review/pr",
    response_model=PRReviewResponse,
    tags=["Review"],
    summary=f"Review a pull-request diff (${PRICE_PR_REVIEW}/call)",
    responses={402: {"model": ErrorDetail, "description": "Payment required"}},
)
async def review_pr_endpoint(
    body: PRReviewRequest,
    x_mainlayer_token: str = Header(default="", alias="x-mainlayer-token"),
) -> PRReviewResponse:
    """Analyse a unified diff (pull request).

    Pass the output of `git diff base...head` as `diff`. The reviewer
    analyses only added lines to minimise false positives.
    Charged at $0.10 per call.
    """
    await _require_payment(PRICE_PR_REVIEW, "/review/pr", x_mainlayer_token)

    request_id = str(uuid.uuid4())
    result = review_pr(
        diff=body.diff,
        title=body.title,
        focus=body.focus,
        request_id=request_id,
    )

    logger.info(
        "review/pr: request_id=%s files=%d additions=%d issues=%d",
        request_id,
        result["files_changed"],
        result["additions"],
        result["summary"].total_issues,
    )

    return PRReviewResponse(
        request_id=result["request_id"],
        title=result["title"],
        focus=result["focus"],
        files_changed=result["files_changed"],
        additions=result["additions"],
        deletions=result["deletions"],
        issues=result["issues"],
        summary=result["summary"],
        recommendations=result["recommendations"],
        positive_aspects=result["positive_aspects"],
        merge_recommendation=result["merge_recommendation"],
    )


@app.post(
    "/review/file",
    response_model=FileReviewResponse,
    tags=["Review"],
    summary=f"Review a named file (${PRICE_FILE_REVIEW}/call)",
    responses={402: {"model": ErrorDetail, "description": "Payment required"}},
)
async def review_file_endpoint(
    body: FileReviewRequest,
    x_mainlayer_token: str = Header(default="", alias="x-mainlayer-token"),
) -> FileReviewResponse:
    """Review a file given its filename and content as a string.

    The filename extension is used for language detection. Charged at $0.05/call.
    """
    await _require_payment(PRICE_FILE_REVIEW, "/review/file", x_mainlayer_token)

    request_id = str(uuid.uuid4())
    result = review_file(
        filename=body.filename,
        content=body.content,
        focus=body.focus,
        request_id=request_id,
    )

    logger.info(
        "review/file: request_id=%s filename=%s language=%s issues=%d",
        request_id,
        body.filename,
        result["language"],
        result["summary"].total_issues,
    )

    return FileReviewResponse(
        request_id=result["request_id"],
        filename=result["filename"],
        language=result["language"],
        focus=result["focus"],
        issues=result["issues"],
        summary=result["summary"],
        recommendations=result["recommendations"],
        positive_aspects=result["positive_aspects"],
    )


@app.get(
    "/capabilities",
    response_model=CapabilitiesResponse,
    tags=["Info"],
    summary="List supported languages and focus areas",
)
async def capabilities() -> CapabilitiesResponse:
    """Return the current set of supported languages and analysis focuses."""
    langs = [
        LanguageCapability(
            name=lang["name"],
            extensions=lang["extensions"],
            supported_focuses=list(ReviewFocus),
            rule_count=len(lang.get("languages", [])) * 3 + 10,
        )
        for lang in SUPPORTED_LANGUAGES
    ]
    return CapabilitiesResponse(
        supported_languages=langs,
        focus_areas=[f.value for f in ReviewFocus],
        max_code_size_bytes=100_000,
        max_diff_size_bytes=500_000,
        version="1.0",
    )


@app.get("/health", tags=["Info"], include_in_schema=False)
async def health() -> dict:
    return {"status": "ok", "service": "code-review-agent-saas"}


# ---------------------------------------------------------------------------
# Exception handler
# ---------------------------------------------------------------------------


@app.exception_handler(Exception)
async def generic_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "message": str(exc)},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
    )
