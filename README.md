# Code Review Agent SaaS — Mainlayer

Monetised code review API powered by pattern-based static analysis. Detects security vulnerabilities, performance issues, and style violations in 12+ languages.

Billing is handled by [Mainlayer](https://mainlayer.fr) — $0.05/review, $0.10/PR.

## Endpoints

| Method | Path | Price | Description |
|--------|------|-------|-------------|
| `POST` | `/review` | $0.05 | Review a code snippet |
| `POST` | `/review/pr` | $0.10 | Review a unified diff |
| `POST` | `/review/file` | $0.05 | Review a named file |
| `GET` | `/capabilities` | free | Supported languages |

## Quick start

```bash
pip install -e ".[dev]"
MAINLAYER_API_KEY=sk_... uvicorn src.main:app --reload
```

## Example request

```bash
curl -X POST http://localhost:8000/review \
  -H "x-mainlayer-token: tok_..." \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"secret\"", "language": "python", "focus": "security"}'
```

## Running tests

```bash
pytest tests/ -v
```

## Supported languages

Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, C++, Rust, SQL, Shell

## Focus areas

- **security** — hardcoded secrets, eval/exec, SQL injection, XSS, insecure hashing
- **performance** — inefficient loops, SELECT *, string concatenation
- **style** — TODO comments, long lines, missing docstrings, bare except
- **all** — all of the above
