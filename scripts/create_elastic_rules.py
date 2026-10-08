"""
Create / update the 8 AI-security detection rules in Kibana's Elastic Security
detection engine (Kibana 8.12). Idempotent: re-running updates existing rules.

Usage:
    python scripts/create_elastic_rules.py
"""
import base64
import json
import os
import urllib.error
import urllib.request

def load_dotenv(path):
    """Loads KEY=VALUE lines from the project's .env (without overriding real env vars)."""
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
    except FileNotFoundError:
        pass


load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

KIBANA_URL = os.getenv("KIBANA_URL", "http://127.0.0.1:5601")
DATA_VIEW_ID = "ai-audit-logs-pattern"
AUTH = base64.b64encode(f'{os.getenv("ELASTIC_USERNAME", "elastic")}:{os.getenv("ELASTIC_PASSWORD", "")}'.encode()).decode()
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json", "elastic-api-version": "2023-10-31",
           "Authorization": f"Basic {AUTH}"}

RISK = {"low": 21, "medium": 47, "high": 73, "critical": 99}

# Hour-of-day (UTC) runtime field on the data view, used by the off-hours rule.
RUNTIME_FIELD = {
    "name": "event.hour_of_day",
    "runtimeField": {"type": "long", "script": {"source": "emit(doc['@timestamp'].value.getHour())"}},
}

RULES = [
    {
        "rule_id": "ai-lab-01-pii-in-prompt",
        "name": "AI Lab - PII in LLM Prompt",
        "description": "Credit card numbers, SSNs or other personal data submitted in an LLM prompt. "
                       "MITRE ATLAS AML.T0024 (Exfiltration via ML Inference).",
        "severity": "high",
        "language": "lucene",  # regex is not supported in KQL
        "query": 'ai.prompt_text.keyword:/.*[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}[- ][0-9]{4}.*/ '
                 'OR ai.prompt_text.keyword:/.*[0-9]{3}-[0-9]{2}-[0-9]{4}.*/ '
                 'OR ai.prompt_text:("SSN" OR "card number" OR "CVV")',
        "tags": ["OWASP:LLM02", "ATLAS:AML.T0024"],
    },
    {
        "rule_id": "ai-lab-02-bulk-exfiltration",
        "name": "AI Lab - Bulk Data Upload / Exfiltration Burst",
        "description": "Single prompt larger than 4,000 tokens, indicating a document or database dump. "
                       "MITRE ATLAS AML.T0024 / AML.T0029.",
        "severity": "high",
        "language": "kuery",
        "query": "ai.tokens.prompt > 4000",
        "tags": ["OWASP:LLM02", "OWASP:LLM04", "ATLAS:AML.T0024", "ATLAS:AML.T0029"],
    },
    {
        "rule_id": "ai-lab-03-rbac-violation",
        "name": "AI Lab - Unauthorized Model Access (RBAC Violation)",
        "description": "Identity called a model outside its assigned department role, or the gateway returned 403. "
                       "MITRE ATLAS AML.T0012 / AML.T0016.",
        "severity": "medium",
        "language": "kuery",
        "query": 'ai.status_code : 403 '
                 'or (user.role.keyword : ("role_hr" or "role_finance") and ai.model.keyword : "dev-code-llm") '
                 'or (user.role.keyword : "role_hr" and ai.model.keyword : "financial-analyzer-llm")',
        "tags": ["OWASP:LLM06", "ATLAS:AML.T0012", "ATLAS:AML.T0016"],
    },
    {
        "rule_id": "ai-lab-04-shadow-ai",
        "name": "AI Lab - Shadow AI Access (Gateway Bypass)",
        "description": "Traffic to an unsanctioned public AI service instead of the corporate LiteLLM gateway. "
                       "MITRE ATLAS AML.T0010.",
        "severity": "medium",
        "language": "kuery",
        "query": 'network.destination_host.keyword : ("chatgpt.com" or "chat.openai.com" or "api.openai.com" '
                 'or "claude.ai" or "deepseek.com" or "poe.com" or "perplexity.ai" or "gemini.google.com")',
        "tags": ["OWASP:LLM02", "ATLAS:AML.T0010"],
    },
    {
        "rule_id": "ai-lab-05-prompt-injection",
        "name": "AI Lab - Prompt Injection / Jailbreak Attempt",
        "description": "DAN, instruction override, or system-prompt extraction phrasing in an LLM prompt. "
                       "MITRE ATLAS AML.T0051 / AML.T0054.",
        "severity": "critical",
        "language": "kuery",
        "query": 'ai.prompt_text : ("ignore previous instructions" or "ignore all previous instructions" '
                 'or "ignore all instructions" or "system prompt" or "DAN mode" or "do anything now" '
                 'or "jailbreak" or "bypass rules" or "developer mode enabled" or "verbatim" '
                 'or "disregard guidelines" or "disregard all")',
        "tags": ["OWASP:LLM01", "ATLAS:AML.T0051", "ATLAS:AML.T0054"],
    },
    {
        "rule_id": "ai-lab-06-secret-leakage",
        "name": "AI Lab - Credential / Secret Leakage in Prompt",
        "description": "AWS access key, GitHub token or private key material submitted in an LLM prompt. "
                       "MITRE ATLAS AML.T0048.",
        "severity": "critical",
        "language": "lucene",  # regex on analyzed (lower-cased) tokens
        "query": 'ai.prompt_text:/akia[0-9a-z]{16}/ OR ai.prompt_text:/ghp_[0-9a-z]{36}/ '
                 'OR ai.prompt_text:"PRIVATE KEY"',
        "tags": ["OWASP:LLM02", "ATLAS:AML.T0048"],
    },
    {
        "rule_id": "ai-lab-07-off-hours",
        "name": "AI Lab - Off-Hours AI Usage (01:00-05:00 UTC)",
        "description": "Inference requests during 01:00-05:00 UTC, a possible account takeover or automated scraping. "
                       "MITRE ATLAS AML.T0012.",
        "severity": "medium",
        "language": "kuery",
        "query": "event.hour_of_day >= 1 and event.hour_of_day < 5",
        "tags": ["OWASP:LLM06", "ATLAS:AML.T0012"],
    },
    {
        "rule_id": "ai-lab-08-recon-errors",
        "name": "AI Lab - Reconnaissance / Excessive Client Errors",
        "description": "400/401/403/429 responses from the AI gateway, indicating schema or guardrail probing. "
                       "MITRE ATLAS AML.T0002.",
        "severity": "medium",
        "language": "kuery",
        "query": "ai.status_code : (400 or 401 or 403 or 429)",
        "tags": ["OWASP:LLM01", "OWASP:LLM04", "ATLAS:AML.T0002"],
    },
]


def call(method, path, body=None):
    req = urllib.request.Request(KIBANA_URL + path, method=method, headers=HEADERS,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def rule_body(r):
    return {
        **r,
        "type": "query",
        "data_view_id": DATA_VIEW_ID,
        "risk_score": RISK[r["severity"]],
        "tags": ["AI Security Lab"] + r["tags"],
        "interval": "5m",
        "from": "now-6m",
        "enabled": True,
        "author": ["AI Monitoring Lab"],
        "license": "Lab",
    }


def ensure_runtime_field():
    status, _ = call("POST", f"/api/data_views/data_view/{DATA_VIEW_ID}/runtime_field", RUNTIME_FIELD)
    if status == 400:  # already exists -> update
        status, _ = call("POST", f"/api/data_views/data_view/{DATA_VIEW_ID}/runtime_field/{RUNTIME_FIELD['name']}",
                         {"runtimeField": RUNTIME_FIELD["runtimeField"]})
    print(f"runtime field {RUNTIME_FIELD['name']}: HTTP {status}")


def upsert():
    for r in RULES:
        body = rule_body(r)
        status, res = call("POST", "/api/detection_engine/rules", body)
        if status == 409:  # exists -> replace
            status, res = call("PUT", "/api/detection_engine/rules", body)
        ok = "ok" if status == 200 else f"FAILED {res}"
        print(f"{r['rule_id']:32} HTTP {status} {ok}")


if __name__ == "__main__":
    ensure_runtime_field()
    upsert()
