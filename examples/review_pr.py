"""Example: review a pull-request diff via the Code Review Agent API.

Usage:
    MAINLAYER_TOKEN=tok_... python examples/review_pr.py
"""

import os

import httpx

BASE_URL = os.environ.get("REVIEW_API_URL", "http://localhost:8000")
TOKEN = os.environ.get("MAINLAYER_TOKEN", "demo-token")

HEADERS = {"x-mainlayer-token": TOKEN}

SAMPLE_DIFF = """\
--- a/app/auth.py
+++ b/app/auth.py
@@ -10,6 +10,14 @@ import hashlib

 SECRET_KEY = "hardcoded-secret-do-not-use"

+def login(username, password):
+    # TODO: add rate limiting
+    query = "SELECT * FROM users WHERE username = '" + username + "'"
+    user = db.execute(query).fetchone()
+    if user and hashlib.md5(password.encode()).hexdigest() == user.password_hash:
+        return generate_token(user.id)
+    return None
+
 def generate_token(user_id: int) -> str:
     return hashlib.sha1(f"{user_id}:{SECRET_KEY}".encode()).hexdigest()
"""


def main() -> None:
    resp = httpx.post(
        f"{BASE_URL}/review/pr",
        json={
            "diff": SAMPLE_DIFF,
            "title": "Add login function",
            "description": "Implements username/password login",
            "base_branch": "main",
            "head_branch": "feature/login",
            "focus": "security",
        },
        headers=HEADERS,
        timeout=30,
    )

    if resp.status_code == 402:
        print("Payment required. Set MAINLAYER_TOKEN to a valid token.")
        return

    resp.raise_for_status()
    data = resp.json()

    summary = data["summary"]
    print(f"PR Title   : {data['title']}")
    print(f"Request ID : {data['request_id']}")
    print(f"Files      : {data['files_changed']} changed (+{data['additions']} -{data['deletions']})")
    print(f"Score      : {summary['score']:.1f}/100 ({summary['grade']})")
    print(f"Verdict    : {data['merge_recommendation'].upper()}")

    print("\nIssues:")
    for issue in data["issues"]:
        line_info = f"line {issue['line']}" if issue.get("line") else "diff-level"
        print(f"  [{issue['severity'].upper()}] {line_info}: {issue['message']}")

    print("\nRecommendations:")
    for rec in data["recommendations"]:
        print(f"  - {rec}")


if __name__ == "__main__":
    main()
