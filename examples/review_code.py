"""Example: review a raw code snippet via the Code Review Agent API.

Usage:
    MAINLAYER_TOKEN=tok_... python examples/review_code.py
"""

import os

import httpx

BASE_URL = os.environ.get("REVIEW_API_URL", "http://localhost:8000")
TOKEN = os.environ.get("MAINLAYER_TOKEN", "demo-token")

HEADERS = {"x-mainlayer-token": TOKEN}

SAMPLE_CODE = """
import pickle
import os

password = "supersecret123"
API_KEY = "sk-abc123"

def process(data):
    obj = pickle.loads(data)
    result = eval(obj.get("expr", "0"))
    return result

def build_query(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return query
"""


def main() -> None:
    resp = httpx.post(
        f"{BASE_URL}/review",
        json={
            "code": SAMPLE_CODE,
            "language": "python",
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
    print(f"Request ID : {data['request_id']}")
    print(f"Language   : {data['language']}")
    print(f"Score      : {summary['score']:.1f}/100 ({summary['grade']})")
    print(f"Issues     : {summary['total_issues']} total")
    print(f"  Critical : {summary['critical']}")
    print(f"  High     : {summary['high']}")
    print(f"  Medium   : {summary['medium']}")
    print(f"  Low      : {summary['low']}")
    print(f"  Info     : {summary['info']}")

    print("\nIssues found:")
    for issue in data["issues"]:
        line_info = f"line {issue['line']}" if issue.get("line") else "global"
        print(f"  [{issue['severity'].upper()}] {line_info}: {issue['message']}")

    print("\nRecommendations:")
    for rec in data["recommendations"]:
        print(f"  - {rec}")


if __name__ == "__main__":
    main()
