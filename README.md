# Code Review Agent SaaS — Mainlayer

Automated code review API powered by pattern-based static analysis. Detects security vulnerabilities, performance issues, and style violations in 12+ languages. Monetized via [Mainlayer](https://mainlayer.fr).

**Pricing:**
- Code snippet: $0.05
- Pull request: $0.10
- File upload: $0.05

## Endpoints

| Method | Path | Price | Description |
|--------|------|-------|-------------|
| `POST` | `/review` | $0.05 | Review a raw code snippet |
| `POST` | `/review/pr` | $0.10 | Review a unified diff (PR) |
| `POST` | `/review/file` | $0.05 | Review an uploaded file |
| `GET` | `/capabilities` | Free | Supported languages and rules |
| `GET` | `/health` | Free | Health check |

## Quick Start

### Installation

```bash
git clone https://github.com/mainlayer/code-review-agent-saas
cd code-review-agent-saas
pip install -e ".[dev]"
```

### Run Locally

```bash
# Development (no Mainlayer API key — billing mocked)
uvicorn src.main:app --reload --port 8000

# Production (with Mainlayer API key)
export MAINLAYER_API_KEY=sk_test_...
uvicorn src.main:app --reload --port 8000
```

## API Examples

### 1. Review a Code Snippet

```bash
curl -X POST http://localhost:8000/review \
  -H "x-mainlayer-token: tok_test_..." \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"secret123\"\neval(user_input)",
    "language": "python",
    "focus": "security"
  }'
```

**Response (200 OK):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "language": "python",
  "focus": "security",
  "issues_found": 2,
  "issues": [
    {
      "id": "SEC001",
      "severity": "critical",
      "category": "security",
      "line": 1,
      "message": "Hardcoded credential or secret detected.",
      "code_context": "password = \"secret123\"",
      "suggestion": "Move secrets to environment variables or a secrets manager."
    },
    {
      "id": "SEC002",
      "severity": "high",
      "category": "security",
      "line": 2,
      "message": "`eval()` executes arbitrary code and is a common injection vector.",
      "code_context": "eval(user_input)",
      "suggestion": "Replace `eval()` with a safer alternative such as `ast.literal_eval` (Python) or JSON.parse (JS)."
    }
  ],
  "summary": {
    "total_issues": 2,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 0,
      "low": 0
    },
    "by_category": {
      "security": 2,
      "performance": 0,
      "style": 0
    }
  },
  "cost_usd": 0.05,
  "processing_time_ms": 24
}
```

### 2. Review a Pull Request (Unified Diff)

```bash
curl -X POST http://localhost:8000/review/pr \
  -H "x-mainlayer-token: tok_test_..." \
  -H "Content-Type: application/json" \
  -d '{
    "diff": "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n password = \"hardcoded\"\n+SELECT * FROM users WHERE id = \" + user_id",
    "focus": "security"
  }'
```

**Response (200 OK):**
- Same structure as `/review` but analyzes the changes in the diff
- Issues mapped to changed lines

### 3. Upload and Review a File

```bash
curl -X POST http://localhost:8000/review/file \
  -H "x-mainlayer-token: tok_test_..." \
  -F "file=@main.py" \
  -F "focus=all"
```

### 4. Get Capabilities

```bash
curl http://localhost:8000/capabilities
```

**Response:**
```json
{
  "supported_languages": [
    {
      "language": "python",
      "aliases": ["py"],
      "rules_count": 28
    },
    {
      "language": "javascript",
      "aliases": ["js"],
      "rules_count": 25
    }
  ],
  "focus_areas": ["security", "performance", "style", "all"],
  "total_rules": 150
}
```

## Supported Languages

| Language | Aliases | Rules | Notes |
|----------|---------|-------|-------|
| Python | `py` | 28 | Includes Django, Flask patterns |
| JavaScript | `js` | 25 | ES6+, async/await, DOM |
| TypeScript | `ts` | 25 | TypeScript-specific rules |
| Java | `java` | 22 | Spring, exception handling |
| Go | `go` | 20 | Goroutines, channels, error handling |
| Ruby | `rb` | 18 | Rails-specific rules |
| PHP | `php` | 20 | WordPress, Laravel patterns |
| C# | `cs` | 18 | .NET, LINQ |
| C++ | `cpp` | 15 | Memory safety, RAII |
| Rust | `rs` | 15 | Ownership, unsafe |
| SQL | `sql` | 12 | Injection, performance |
| Shell | `sh` | 12 | Command injection |

## Review Focus Areas

### Security (`focus: "security"`)
Detects:
- Hardcoded credentials (passwords, API keys, tokens)
- Code injection (eval, exec, SQL injection, command injection)
- Weak cryptography (MD5, SHA-1, non-cryptographic RNG)
- Unsafe deserialization (pickle)
- XSS vulnerabilities (DOM manipulation)

**Rules:** 40+

### Performance (`focus: "performance"`)
Detects:
- Inefficient loops (O(n²) operations)
- `SELECT *` in SQL queries
- String concatenation in loops
- Synchronous I/O in async code
- Missing indexes on frequently queried columns

**Rules:** 25+

### Style (`focus: "style"`)
Detects:
- TODO/FIXME comments
- Lines exceeding length limit (120 chars)
- Missing docstrings (Python)
- Bare `except` clauses
- Inconsistent naming conventions
- Unused imports

**Rules:** 30+

### All (`focus: "all"`)
Runs all rules from the above categories.

## Error Responses

### Payment Required

**Status 402 Payment Required:**
```json
{
  "error": "payment_required",
  "info": "mainlayer.fr",
  "amount_usd": 0.05,
  "message": "Supply x-mainlayer-token header for payment processing."
}
```

### Invalid Request

**Status 400 Bad Request:**
```json
{
  "error": "invalid_request",
  "message": "Code cannot be empty.",
  "details": {"field": "code"}
}
```

### Unsupported Language

**Status 400 Bad Request:**
```json
{
  "error": "unsupported_language",
  "message": "Language 'scala' is not supported.",
  "supported": ["python", "javascript", "java", ...]
}
```

### Internal Error

**Status 500 Internal Server Error:**
```json
{
  "error": "internal_error",
  "message": "Review processing failed.",
  "details": {"request_id": "..."}
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MAINLAYER_API_KEY` | (unset) | API key for Mainlayer (optional in dev) |
| `MAINLAYER_API_URL` | https://api.mainlayer.fr | Mainlayer API endpoint |
| `PRICE_CODE_REVIEW` | 0.05 | Cost for `/review` endpoint |
| `PRICE_PR_REVIEW` | 0.10 | Cost for `/review/pr` endpoint |
| `PRICE_FILE_REVIEW` | 0.05 | Cost for `/review/file` endpoint |
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `CORS_ORIGINS` | * | Comma-separated CORS origins |
| `HOST` | 0.0.0.0 | Server host |
| `PORT` | 8000 | Server port |
| `MAX_CODE_LENGTH` | 100000 | Maximum code size (chars) |
| `REQUEST_TIMEOUT` | 10 | Request timeout (seconds) |

## Architecture

```
POST /review
  ↓
[Payment verification] → Check Mainlayer token
  ↓
[Language detection] → From extension or explicit header
  ↓
[Rule matching] → Apply security/performance/style rules
  ↓
[Issue extraction] → Line numbers, context, suggestions
  ↓
[Summary generation] → Count by severity/category
  ↓
[Billing] → Charge via Mainlayer
  ↓
[Response] → Return issues + cost breakdown
```

## Development

### Add a Custom Rule

Edit `src/reviewer.py`:

```python
SECURITY_RULES.append(Rule(
    rule_id="SEC999",
    pattern=r"your_pattern_here",
    severity=IssueSeverity.high,
    category=IssueCategory.security,
    message="Descriptive message about the issue.",
    suggestion="How to fix it.",
    focus=ReviewFocus.security,
    languages={"python", "js"}  # empty = all languages
))
```

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_main.py::test_review_code_snippet -v

# With coverage
pytest tests/ --cov=src --cov-report=html
```

## Integration with Mainlayer

The code review agent integrates with Mainlayer for:
1. **Per-call billing**: Each review deducts from user's account
2. **Payment verification**: Checks token before processing
3. **Transaction tracking**: Mainlayer maintains audit logs

When `MAINLAYER_API_KEY` is not set, the service runs in **development mode**:
- All reviews succeed
- No charges are applied
- Full features available

## Production Deployment

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -e .
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Checklist

- [ ] Set `MAINLAYER_API_KEY` to production key
- [ ] Configure `CORS_ORIGINS` to trusted domains only
- [ ] Enable HTTPS (via reverse proxy)
- [ ] Set up structured logging (JSON format)
- [ ] Add request rate limiting
- [ ] Monitor billing for disputes
- [ ] Set up alerts for failed reviews
- [ ] Add authentication layer (OAuth2, JWT)

## Testing

```bash
pytest tests/ -v
```

## Support

- **Docs**: https://docs.mainlayer.fr
- **API**: https://api.mainlayer.fr
- **Dashboard**: https://dashboard.mainlayer.fr
- **Issues**: https://github.com/mainlayer/code-review-agent-saas/issues
