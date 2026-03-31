"""Tests for the Code Review Agent SaaS API."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.main import app

HEADERS_WITH_TOKEN = {"x-mainlayer-token": "tok_test_demo"}

SAFE_PYTHON = """
def add(a: int, b: int) -> int:
    \"\"\"Return the sum of two integers.\"\"\"
    return a + b
"""

UNSAFE_PYTHON = """
import pickle

password = "secret123"

def run(data):
    return eval(data)
"""


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def mock_billing():
    """Bypass Mainlayer network calls in all tests."""
    with patch("src.main.charge_review", new_callable=AsyncMock) as mock:
        from src.mainlayer import PaymentResult
        mock.return_value = PaymentResult(
            transaction_id="txn_test",
            amount_usd=0.05,
            endpoint="/review",
            status="approved",
        )
        yield mock


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------


def test_capabilities(client):
    resp = client.get("/capabilities")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["supported_languages"]) > 0
    assert "security" in body["focus_areas"]


# ---------------------------------------------------------------------------
# Payment gating
# ---------------------------------------------------------------------------


def test_review_requires_token(client):
    resp = client.post(
        "/review",
        json={"code": "x = 1", "language": "python"},
    )
    assert resp.status_code == 402


def test_review_pr_requires_token(client):
    resp = client.post(
        "/review/pr",
        json={"diff": "+x = 1", "title": "test"},
    )
    assert resp.status_code == 402


def test_review_file_requires_token(client):
    resp = client.post(
        "/review/file",
        json={"filename": "test.py", "content": "x = 1"},
    )
    assert resp.status_code == 402


# ---------------------------------------------------------------------------
# Code review
# ---------------------------------------------------------------------------


def test_review_safe_code(client):
    resp = client.post(
        "/review",
        json={"code": SAFE_PYTHON, "language": "python", "focus": "security"},
        headers=HEADERS_WITH_TOKEN,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "request_id" in body
    assert body["language"] == "python"
    assert 0 <= body["summary"]["score"] <= 100
    # Safe code should score high
    assert body["summary"]["score"] >= 70


def test_review_unsafe_code_finds_issues(client):
    resp = client.post(
        "/review",
        json={"code": UNSAFE_PYTHON, "language": "python", "focus": "security"},
        headers=HEADERS_WITH_TOKEN,
    )
    assert resp.status_code == 200
    body = resp.json()
    severities = {i["severity"] for i in body["issues"]}
    # Should find critical or high issues (hardcoded secret, eval, pickle)
    assert severities & {"critical", "high"}


def test_review_returns_recommendations(client):
    resp = client.post(
        "/review",
        json={"code": UNSAFE_PYTHON, "language": "python"},
        headers=HEADERS_WITH_TOKEN,
    )
    assert resp.status_code == 200
    assert len(resp.json()["recommendations"]) > 0


# ---------------------------------------------------------------------------
# PR review
# ---------------------------------------------------------------------------


def test_review_pr(client):
    diff = (
        "--- a/app.py\n+++ b/app.py\n"
        "@@ -1,3 +1,6 @@\n"
        "+import hashlib\n"
        '+password = "secret"\n'
        "+result = eval(user_input)\n"
    )
    resp = client.post(
        "/review/pr",
        json={"diff": diff, "title": "Add feature", "focus": "security"},
        headers=HEADERS_WITH_TOKEN,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "merge_recommendation" in body
    assert body["merge_recommendation"] in ("approve", "comment", "request_changes")


# ---------------------------------------------------------------------------
# File review
# ---------------------------------------------------------------------------


def test_review_file(client):
    resp = client.post(
        "/review/file",
        json={"filename": "auth.py", "content": UNSAFE_PYTHON, "focus": "security"},
        headers=HEADERS_WITH_TOKEN,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["filename"] == "auth.py"
    assert body["language"] == "python"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_review_empty_code_rejected(client):
    resp = client.post(
        "/review",
        json={"code": "   ", "language": "python"},
        headers=HEADERS_WITH_TOKEN,
    )
    assert resp.status_code == 422


def test_review_all_focus_areas(client):
    for focus in ("security", "performance", "style", "all"):
        resp = client.post(
            "/review",
            json={"code": SAFE_PYTHON, "language": "python", "focus": focus},
            headers=HEADERS_WITH_TOKEN,
        )
        assert resp.status_code == 200, f"focus={focus} failed"
