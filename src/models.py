"""
Pydantic models for the Code Review Agent SaaS API.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ReviewFocus(str, Enum):
    security = "security"
    performance = "performance"
    style = "style"
    all = "all"


class IssueSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class IssueCategory(str, Enum):
    security = "security"
    performance = "performance"
    style = "style"
    maintainability = "maintainability"
    correctness = "correctness"
    documentation = "documentation"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CodeReviewRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=100_000, description="Source code to review")
    language: str = Field(..., min_length=1, max_length=50, description="Programming language")
    focus: ReviewFocus = Field(ReviewFocus.all, description="Review focus area")
    context: str | None = Field(None, max_length=1_000, description="Optional context about the code")

    @field_validator("language")
    @classmethod
    def normalise_language(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("code")
    @classmethod
    def code_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("code must not be blank")
        return v


class PRReviewRequest(BaseModel):
    diff: str = Field(..., min_length=1, max_length=500_000, description="Unified diff of the PR")
    title: str = Field(..., min_length=1, max_length=500, description="PR title")
    description: str | None = Field(None, max_length=5_000, description="PR description")
    base_branch: str = Field("main", max_length=200, description="Target branch")
    head_branch: str = Field("feature", max_length=200, description="Source branch")
    focus: ReviewFocus = Field(ReviewFocus.all, description="Review focus area")

    @field_validator("diff")
    @classmethod
    def diff_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("diff must not be blank")
        return v


class FileReviewRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=500, description="File name")
    content: str = Field(..., min_length=1, max_length=200_000, description="File content")
    focus: ReviewFocus = Field(ReviewFocus.all, description="Review focus area")
    context: str | None = Field(None, max_length=1_000, description="Optional context")

    @field_validator("filename")
    @classmethod
    def sanitise_filename(cls, v: str) -> str:
        # Prevent directory traversal
        import os
        name = os.path.basename(v.strip())
        if not name:
            raise ValueError("filename must not be empty after sanitisation")
        return name


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ReviewIssue(BaseModel):
    line: int | None = Field(None, description="Line number (1-based)")
    severity: IssueSeverity
    category: IssueCategory
    message: str
    suggestion: str | None = None
    rule_id: str | None = Field(None, description="Internal rule identifier")


class ReviewSummary(BaseModel):
    total_issues: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    score: float = Field(..., ge=0.0, le=100.0, description="Code quality score 0-100")
    grade: str = Field(..., description="Letter grade A-F")


class CodeReviewResponse(BaseModel):
    request_id: str
    language: str
    focus: ReviewFocus
    issues: list[ReviewIssue]
    summary: ReviewSummary
    recommendations: list[str]
    positive_aspects: list[str]
    review_version: str = "1.0"


class PRReviewResponse(BaseModel):
    request_id: str
    title: str
    focus: ReviewFocus
    files_changed: int
    additions: int
    deletions: int
    issues: list[ReviewIssue]
    summary: ReviewSummary
    recommendations: list[str]
    positive_aspects: list[str]
    merge_recommendation: str = Field(
        ..., description="One of: approve, request_changes, comment"
    )
    review_version: str = "1.0"


class FileReviewResponse(BaseModel):
    request_id: str
    filename: str
    language: str
    focus: ReviewFocus
    issues: list[ReviewIssue]
    summary: ReviewSummary
    recommendations: list[str]
    positive_aspects: list[str]
    review_version: str = "1.0"


# ---------------------------------------------------------------------------
# Capability & sample models
# ---------------------------------------------------------------------------


class LanguageCapability(BaseModel):
    name: str
    extensions: list[str]
    supported_focuses: list[ReviewFocus]
    rule_count: int


class CapabilitiesResponse(BaseModel):
    supported_languages: list[LanguageCapability]
    focus_areas: list[str]
    max_code_size_bytes: int
    max_diff_size_bytes: int
    version: str


class SampleReview(BaseModel):
    title: str
    language: str
    focus: ReviewFocus
    input_snippet: str
    output_preview: CodeReviewResponse


class SamplesResponse(BaseModel):
    samples: list[SampleReview]


# ---------------------------------------------------------------------------
# Error model
# ---------------------------------------------------------------------------


class ErrorDetail(BaseModel):
    error: str
    message: str
    details: dict[str, Any] | None = None
