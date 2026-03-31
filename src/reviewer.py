"""
Pattern-based static analysis engine for the Code Review Agent SaaS.

The reviewer uses a rule catalogue organised by language and focus area.
Each rule is a dataclass carrying a regex pattern (applied line-by-line and
optionally over the full source), a severity, a category, a human-readable
message, and an optional fix suggestion.

Design principles:
- No external LLM calls — purely deterministic pattern matching.
- Language detection from file extension and explicit language hint.
- Extensible: add new rules to RULE_CATALOGUE without touching routing logic.
- Thread-safe: all state is read-only after module import.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Callable

from .models import (
    IssueCategory,
    IssueSeverity,
    ReviewFocus,
    ReviewIssue,
    ReviewSummary,
)

# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    rule_id: str
    pattern: str                          # regex applied to each line
    severity: IssueSeverity
    category: IssueCategory
    message: str
    suggestion: str | None = None
    flags: int = re.IGNORECASE
    multiline: bool = False               # if True, applied to full source
    languages: set[str] = field(default_factory=set)  # empty = all languages
    focus: ReviewFocus = ReviewFocus.all  # which focus areas trigger this rule

    def matches(self, text: str) -> bool:
        return bool(re.search(self.pattern, text, self.flags))


# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------

SECURITY_RULES: list[Rule] = [
    Rule(
        rule_id="SEC001",
        pattern=r"(?:password|passwd|secret|api_key|apikey|auth_token)\s*=\s*['\"].+['\"]",
        severity=IssueSeverity.critical,
        category=IssueCategory.security,
        message="Hardcoded credential or secret detected.",
        suggestion="Move secrets to environment variables or a secrets manager.",
        focus=ReviewFocus.security,
    ),
    Rule(
        rule_id="SEC002",
        pattern=r"eval\s*\(",
        severity=IssueSeverity.high,
        category=IssueCategory.security,
        message="`eval()` executes arbitrary code and is a common injection vector.",
        suggestion="Replace `eval()` with a safer alternative such as `ast.literal_eval` (Python) or JSON.parse (JS).",
        focus=ReviewFocus.security,
    ),
    Rule(
        rule_id="SEC003",
        pattern=r"exec\s*\(",
        severity=IssueSeverity.high,
        category=IssueCategory.security,
        message="`exec()` can execute arbitrary code.",
        suggestion="Avoid `exec()`. Use subprocess with a fixed argument list instead.",
        focus=ReviewFocus.security,
    ),
    Rule(
        rule_id="SEC004",
        pattern=r"md5\s*\(|hashlib\.md5|new\s+MD5",
        severity=IssueSeverity.high,
        category=IssueCategory.security,
        message="MD5 is cryptographically broken and should not be used for security purposes.",
        suggestion="Use SHA-256 or SHA-3 for security-sensitive hashing.",
        focus=ReviewFocus.security,
    ),
    Rule(
        rule_id="SEC005",
        pattern=r"sha1\s*\(|hashlib\.sha1",
        severity=IssueSeverity.medium,
        category=IssueCategory.security,
        message="SHA-1 is deprecated for security-critical use cases.",
        suggestion="Use SHA-256 or stronger.",
        focus=ReviewFocus.security,
    ),
    Rule(
        rule_id="SEC006",
        pattern=r"random\.random\(\)|Math\.random\(\)",
        severity=IssueSeverity.medium,
        category=IssueCategory.security,
        message="Non-cryptographic RNG used — unsuitable for tokens or keys.",
        suggestion="Use `secrets` (Python) or `crypto.getRandomValues` (JS) for security tokens.",
        focus=ReviewFocus.security,
    ),
    Rule(
        rule_id="SEC007",
        pattern=r"innerHTML\s*=|outerHTML\s*=|document\.write\s*\(",
        severity=IssueSeverity.high,
        category=IssueCategory.security,
        message="Direct DOM manipulation with user data can cause XSS.",
        suggestion="Use `textContent` or a sanitisation library such as DOMPurify.",
        focus=ReviewFocus.security,
        languages={"javascript", "typescript", "js", "ts"},
    ),
    Rule(
        rule_id="SEC008",
        pattern=r"SELECT\s+.+\s+FROM\s+.+\s+WHERE.+\+|execute\s*\(\s*['\"].*%s",
        severity=IssueSeverity.critical,
        category=IssueCategory.security,
        message="Possible SQL injection via string concatenation.",
        suggestion="Use parameterised queries or an ORM.",
        focus=ReviewFocus.security,
    ),
    Rule(
        rule_id="SEC009",
        pattern=r"subprocess\.call\(.+shell\s*=\s*True|os\.system\s*\(",
        severity=IssueSeverity.high,
        category=IssueCategory.security,
        message="Shell injection risk: `shell=True` or `os.system` with dynamic input.",
        suggestion="Use `subprocess.run` with a list argument and `shell=False`.",
        focus=ReviewFocus.security,
        languages={"python", "py"},
    ),
    Rule(
        rule_id="SEC010",
        pattern=r"pickle\.loads?\s*\(",
        severity=IssueSeverity.high,
        category=IssueCategory.security,
        message="Deserialising untrusted `pickle` data can execute arbitrary code.",
        suggestion="Use JSON or a safe serialisation format for untrusted data.",
        focus=ReviewFocus.security,
        languages={"python", "py"},
    ),
]

PERFORMANCE_RULES: list[Rule] = [
    Rule(
        rule_id="PERF001",
        pattern=r"for\s+\w+\s+in\s+range\s*\(\s*len\s*\(",
        severity=IssueSeverity.low,
        category=IssueCategory.performance,
        message="`for i in range(len(x))` is slow and unidiomatic.",
        suggestion="Use `enumerate(x)` or iterate directly over the collection.",
        focus=ReviewFocus.performance,
        languages={"python", "py"},
    ),
    Rule(
        rule_id="PERF002",
        pattern=r"\+\s*=\s*(?:['\"]|str\()",
        severity=IssueSeverity.medium,
        category=IssueCategory.performance,
        message="String concatenation in a loop is O(n²).",
        suggestion="Collect parts in a list and use `''.join(parts)` at the end.",
        focus=ReviewFocus.performance,
        languages={"python", "py"},
    ),
    Rule(
        rule_id="PERF003",
        pattern=r"SELECT\s+\*\s+FROM",
        severity=IssueSeverity.medium,
        category=IssueCategory.performance,
        message="`SELECT *` fetches all columns, including unused ones.",
        suggestion="Specify only the columns you need.",
        focus=ReviewFocus.performance,
    ),
    Rule(
        rule_id="PERF004",
        pattern=r"time\.sleep\s*\(\s*(?:[5-9]\d*|\d{2,})",
        severity=IssueSeverity.low,
        category=IssueCategory.performance,
        message="Long `time.sleep()` call found — consider async/event-driven waiting.",
        suggestion="Use asyncio.sleep or a task queue for long waits.",
        focus=ReviewFocus.performance,
        languages={"python", "py"},
    ),
    Rule(
        rule_id="PERF005",
        pattern=r"\.filter\(.*\)\.filter\(",
        severity=IssueSeverity.low,
        category=IssueCategory.performance,
        message="Chained `.filter()` calls may scan the collection multiple times.",
        suggestion="Combine filter conditions into a single pass.",
        focus=ReviewFocus.performance,
    ),
    Rule(
        rule_id="PERF006",
        pattern=r"(?:var|let|const)\s+\w+\s*=\s*\[\s*\].*\nfor\b",
        severity=IssueSeverity.low,
        category=IssueCategory.performance,
        message="Consider using `.map()`, `.filter()`, or `.reduce()` instead of a manual loop.",
        suggestion="Declarative array methods are often faster and more readable in JS/TS.",
        focus=ReviewFocus.performance,
        languages={"javascript", "typescript", "js", "ts"},
        multiline=True,
    ),
    Rule(
        rule_id="PERF007",
        pattern=r"Object\.keys\(.+\)\.forEach",
        severity=IssueSeverity.info,
        category=IssueCategory.performance,
        message="`Object.keys(...).forEach` creates an intermediate array.",
        suggestion="Use `for...in` or `Object.entries` with destructuring for better performance.",
        focus=ReviewFocus.performance,
        languages={"javascript", "typescript", "js", "ts"},
    ),
]

STYLE_RULES: list[Rule] = [
    Rule(
        rule_id="STY001",
        pattern=r"^\s*#\s*TODO|^\s*#\s*FIXME|^\s*#\s*HACK|^\s*//\s*TODO|^\s*//\s*FIXME",
        severity=IssueSeverity.info,
        category=IssueCategory.maintainability,
        message="TODO/FIXME comment found.",
        suggestion="Create a tracked issue and reference its ID in the comment.",
        focus=ReviewFocus.style,
    ),
    Rule(
        rule_id="STY002",
        pattern=r"^.{120,}$",
        severity=IssueSeverity.low,
        category=IssueCategory.style,
        message="Line exceeds 120 characters.",
        suggestion="Break long lines to improve readability.",
        focus=ReviewFocus.style,
    ),
    Rule(
        rule_id="STY003",
        pattern=r"^\s*(def|class|function)\s+[a-z0-9_]{40,}\s*[\(:]",
        severity=IssueSeverity.low,
        category=IssueCategory.style,
        message="Identifier name is very long (>40 chars).",
        suggestion="Choose a shorter, equally descriptive name.",
        focus=ReviewFocus.style,
    ),
    Rule(
        rule_id="STY004",
        pattern=r"^\s*pass\s*$",
        severity=IssueSeverity.info,
        category=IssueCategory.maintainability,
        message="Empty `pass` block found.",
        suggestion="Add a comment explaining why the block is intentionally empty, or raise NotImplementedError.",
        focus=ReviewFocus.style,
        languages={"python", "py"},
    ),
    Rule(
        rule_id="STY005",
        pattern=r"print\s*\(",
        severity=IssueSeverity.info,
        category=IssueCategory.style,
        message="`print()` statement in production code.",
        suggestion="Replace `print()` with a structured logger.",
        focus=ReviewFocus.style,
        languages={"python", "py"},
    ),
    Rule(
        rule_id="STY006",
        pattern=r"console\.log\s*\(",
        severity=IssueSeverity.info,
        category=IssueCategory.style,
        message="`console.log()` in production code.",
        suggestion="Remove debug logging or replace with a structured logger.",
        focus=ReviewFocus.style,
        languages={"javascript", "typescript", "js", "ts"},
    ),
    Rule(
        rule_id="STY007",
        pattern=r"^\s*(var)\s+",
        severity=IssueSeverity.low,
        category=IssueCategory.style,
        message="`var` declaration — function-scoped and error-prone.",
        suggestion="Use `const` (preferred) or `let` instead.",
        focus=ReviewFocus.style,
        languages={"javascript", "js"},
    ),
    Rule(
        rule_id="STY008",
        pattern=r"==\s*(?:null|undefined)|!=\s*(?:null|undefined)",
        severity=IssueSeverity.low,
        category=IssueCategory.style,
        message="Loose equality check against `null` or `undefined`.",
        suggestion="Use strict equality (`===`/`!==`) or nullish coalescing.",
        focus=ReviewFocus.style,
        languages={"javascript", "typescript", "js", "ts"},
    ),
    Rule(
        rule_id="STY009",
        pattern=r"(?:def\s+\w+\s*\([^)]*\)\s*:(?!\s*(?:\"\"\"|\'\'\')))",
        severity=IssueSeverity.info,
        category=IssueCategory.documentation,
        message="Function is missing a docstring.",
        suggestion="Add a brief docstring describing the function's purpose, parameters, and return value.",
        focus=ReviewFocus.style,
        languages={"python", "py"},
    ),
    Rule(
        rule_id="STY010",
        pattern=r"^\s*except\s*:",
        severity=IssueSeverity.medium,
        category=IssueCategory.correctness,
        message="Bare `except:` catches all exceptions including `SystemExit` and `KeyboardInterrupt`.",
        suggestion="Catch specific exception types, e.g. `except ValueError:`.",
        focus=ReviewFocus.style,
        languages={"python", "py"},
    ),
]

# Master catalogue
ALL_RULES: list[Rule] = SECURITY_RULES + PERFORMANCE_RULES + STYLE_RULES

FOCUS_TO_RULES: dict[ReviewFocus, list[Rule]] = {
    ReviewFocus.security: [r for r in ALL_RULES if r.focus in (ReviewFocus.security, ReviewFocus.all)],
    ReviewFocus.performance: [r for r in ALL_RULES if r.focus in (ReviewFocus.performance, ReviewFocus.all)],
    ReviewFocus.style: [r for r in ALL_RULES if r.focus in (ReviewFocus.style, ReviewFocus.all)],
    ReviewFocus.all: ALL_RULES,
}

# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

SEVERITY_PENALTY: dict[IssueSeverity, float] = {
    IssueSeverity.critical: 25.0,
    IssueSeverity.high: 15.0,
    IssueSeverity.medium: 7.0,
    IssueSeverity.low: 3.0,
    IssueSeverity.info: 0.5,
}


def _compute_score(issues: list[ReviewIssue]) -> tuple[float, str]:
    penalty = sum(SEVERITY_PENALTY.get(i.severity, 0) for i in issues)
    score = max(0.0, 100.0 - penalty)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return round(score, 1), grade


def _make_summary(issues: list[ReviewIssue]) -> ReviewSummary:
    counts = {s: 0 for s in IssueSeverity}
    for issue in issues:
        counts[issue.severity] += 1
    score, grade = _compute_score(issues)
    return ReviewSummary(
        total_issues=len(issues),
        critical=counts[IssueSeverity.critical],
        high=counts[IssueSeverity.high],
        medium=counts[IssueSeverity.medium],
        low=counts[IssueSeverity.low],
        info=counts[IssueSeverity.info],
        score=score,
        grade=grade,
    )


# ---------------------------------------------------------------------------
# Core analyser
# ---------------------------------------------------------------------------


def _applicable_rules(language: str, focus: ReviewFocus) -> list[Rule]:
    rules = FOCUS_TO_RULES.get(focus, ALL_RULES)
    return [
        r for r in rules
        if not r.languages or language in r.languages
    ]


def _analyse_lines(
    lines: list[str],
    language: str,
    focus: ReviewFocus,
) -> list[ReviewIssue]:
    """Run line-by-line rules and return matched issues."""
    rules = _applicable_rules(language, focus)
    source = "\n".join(lines)

    issues: list[ReviewIssue] = []
    seen: set[str] = set()  # deduplicate identical rule+line combos

    for rule in rules:
        if rule.multiline:
            if rule.matches(source):
                key = f"{rule.rule_id}:multiline"
                if key not in seen:
                    seen.add(key)
                    issues.append(
                        ReviewIssue(
                            line=None,
                            severity=rule.severity,
                            category=rule.category,
                            message=rule.message,
                            suggestion=rule.suggestion,
                            rule_id=rule.rule_id,
                        )
                    )
        else:
            for lineno, line in enumerate(lines, start=1):
                key = f"{rule.rule_id}:{lineno}"
                if key not in seen and rule.matches(line):
                    seen.add(key)
                    issues.append(
                        ReviewIssue(
                            line=lineno,
                            severity=rule.severity,
                            category=rule.category,
                            message=rule.message,
                            suggestion=rule.suggestion,
                            rule_id=rule.rule_id,
                        )
                    )

    # Sort: critical first, then by line number
    severity_order = list(IssueSeverity)
    issues.sort(key=lambda i: (severity_order.index(i.severity), i.line or 0))
    return issues


# ---------------------------------------------------------------------------
# Recommendations / positive aspects
# ---------------------------------------------------------------------------

def _build_recommendations(issues: list[ReviewIssue], focus: ReviewFocus) -> list[str]:
    seen_rules: set[str] = set()
    recs: list[str] = []
    for issue in issues:
        if issue.rule_id and issue.rule_id not in seen_rules and issue.suggestion:
            seen_rules.add(issue.rule_id)
            recs.append(f"[{issue.rule_id}] {issue.suggestion}")
    if not recs:
        recs.append("No major issues detected. Continue following best practices.")
    return recs[:10]


def _build_positives(issues: list[ReviewIssue], lines: list[str], language: str) -> list[str]:
    positives: list[str] = []
    severities = {i.severity for i in issues}
    if IssueSeverity.critical not in severities:
        positives.append("No critical security vulnerabilities detected.")
    if not any(i.category == IssueCategory.security for i in issues):
        positives.append("Code appears free of common security anti-patterns.")
    if len(lines) < 200:
        positives.append("File is concise and focused.")
    if not any(r.rule_id == "STY001" for r in issues):  # type: ignore[attr-defined]
        positives.append("No TODO/FIXME comments found — clean codebase.")
    return positives or ["Code structure is acceptable."]


# ---------------------------------------------------------------------------
# Diff parser helpers
# ---------------------------------------------------------------------------

def _parse_diff(diff: str) -> tuple[int, int, int, list[str]]:
    """Return (files_changed, additions, deletions, added_lines)."""
    files: set[str] = set()
    additions = 0
    deletions = 0
    added_lines: list[str] = []

    for line in diff.splitlines():
        if line.startswith("+++ ") or line.startswith("--- "):
            fname = line[4:].strip()
            if fname not in ("/dev/null", ""):
                files.add(fname)
        elif line.startswith("+") and not line.startswith("+++"):
            additions += 1
            added_lines.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            deletions += 1

    return max(len(files), 1), additions, deletions, added_lines


def _merge_recommendation(summary: ReviewSummary) -> str:
    if summary.critical > 0 or summary.high > 2:
        return "request_changes"
    if summary.high > 0 or summary.medium > 3:
        return "comment"
    return "approve"


# ---------------------------------------------------------------------------
# Public reviewer functions
# ---------------------------------------------------------------------------


def review_code(
    code: str,
    language: str,
    focus: ReviewFocus,
    request_id: str | None = None,
) -> dict:
    """Analyse raw source code and return a result dict."""
    rid = request_id or str(uuid.uuid4())
    lines = code.splitlines()
    issues = _analyse_lines(lines, language, focus)
    summary = _make_summary(issues)
    return {
        "request_id": rid,
        "language": language,
        "focus": focus,
        "issues": issues,
        "summary": summary,
        "recommendations": _build_recommendations(issues, focus),
        "positive_aspects": _build_positives(issues, lines, language),
    }


def review_pr(
    diff: str,
    title: str,
    focus: ReviewFocus,
    request_id: str | None = None,
) -> dict:
    """Analyse a PR unified diff and return a result dict."""
    rid = request_id or str(uuid.uuid4())
    files_changed, additions, deletions, added_lines = _parse_diff(diff)

    # Infer language from diff header filenames if possible
    language = _infer_language_from_diff(diff)
    issues = _analyse_lines(added_lines, language, focus)
    summary = _make_summary(issues)
    return {
        "request_id": rid,
        "title": title,
        "focus": focus,
        "files_changed": files_changed,
        "additions": additions,
        "deletions": deletions,
        "issues": issues,
        "summary": summary,
        "recommendations": _build_recommendations(issues, focus),
        "positive_aspects": _build_positives(issues, added_lines, language),
        "merge_recommendation": _merge_recommendation(summary),
    }


def review_file(
    filename: str,
    content: str,
    focus: ReviewFocus,
    request_id: str | None = None,
) -> dict:
    """Analyse a file upload and return a result dict."""
    rid = request_id or str(uuid.uuid4())
    language = _infer_language_from_filename(filename)
    lines = content.splitlines()
    issues = _analyse_lines(lines, language, focus)
    summary = _make_summary(issues)
    return {
        "request_id": rid,
        "filename": filename,
        "language": language,
        "focus": focus,
        "issues": issues,
        "summary": summary,
        "recommendations": _build_recommendations(issues, focus),
        "positive_aspects": _build_positives(issues, lines, language),
    }


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".c": "c",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".sql": "sql",
    ".sh": "bash",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
}


def _infer_language_from_filename(filename: str) -> str:
    import os
    ext = os.path.splitext(filename)[1].lower()
    return EXT_TO_LANG.get(ext, "unknown")


def _infer_language_from_diff(diff: str) -> str:
    """Pick the dominant language from diff file headers."""
    from collections import Counter
    counts: Counter[str] = Counter()
    for line in diff.splitlines():
        if line.startswith("+++ b/") or line.startswith("--- a/"):
            fname = line.split("/", 1)[-1].strip()
            lang = _infer_language_from_filename(fname)
            if lang != "unknown":
                counts[lang] += 1
    return counts.most_common(1)[0][0] if counts else "unknown"


# ---------------------------------------------------------------------------
# Capabilities registry
# ---------------------------------------------------------------------------

SUPPORTED_LANGUAGES = [
    {"name": "Python", "extensions": [".py"], "languages": {"python", "py"}},
    {"name": "JavaScript", "extensions": [".js", ".jsx"], "languages": {"javascript", "js"}},
    {"name": "TypeScript", "extensions": [".ts", ".tsx"], "languages": {"typescript", "ts"}},
    {"name": "Java", "extensions": [".java"], "languages": {"java"}},
    {"name": "Go", "extensions": [".go"], "languages": {"go"}},
    {"name": "Ruby", "extensions": [".rb"], "languages": {"ruby"}},
    {"name": "PHP", "extensions": [".php"], "languages": {"php"}},
    {"name": "C#", "extensions": [".cs"], "languages": {"csharp", "cs"}},
    {"name": "C++", "extensions": [".cpp", ".cc", ".cxx"], "languages": {"cpp"}},
    {"name": "Rust", "extensions": [".rs"], "languages": {"rust"}},
    {"name": "SQL", "extensions": [".sql"], "languages": {"sql"}},
    {"name": "Shell", "extensions": [".sh", ".bash"], "languages": {"bash", "sh", "shell"}},
]
