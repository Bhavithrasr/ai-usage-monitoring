#!/usr/bin/env python3
"""
AI Usage Monitoring Lab — Traffic & Threat Simulation Engine
Author: Bhavithra

Loads role-based prompts from prompts/role_prompts.json and attack scenarios
from prompts/attack_scenarios.json, logs each persona in to Keycloak, sends
their requests to the LiteLLM AI Gateway with a per-user virtual key limited
to their role's models, and writes ECS-compliant audit events to Elasticsearch.

Prompt templates are maintained separately in the prompts/ directory so that
scenarios can be updated without touching simulation logic.
"""

import os
import sys
import time
import json
import uuid
import base64
import datetime
import random
import urllib.parse
import urllib.request
import urllib.error

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPTS_DIR = os.path.join(BASE_DIR, "prompts")

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

load_dotenv(os.path.join(BASE_DIR, ".env"))

# ── Target endpoints ───────────────────────────────────────────────────────────
LITELLM_URL = os.getenv("LITELLM_URL", "http://localhost:4000")
ELASTIC_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ELASTIC_AUTH = base64.b64encode(
    f'{os.getenv("ELASTIC_USERNAME", "elastic")}:{os.getenv("ELASTIC_PASSWORD", "")}'.encode()).decode()
ES_INDEX    = "ai-audit-logs"
MASTER_KEY  = os.getenv("LITELLM_MASTER_KEY", "sk-lab-master-key-admin-supersecret-9999")

# ── Identity provider (Keycloak) ───────────────────────────────────────────────
KEYCLOAK_URL    = os.getenv("KEYCLOAK_URL", "http://127.0.0.1:8080")
KEYCLOAK_REALM  = os.getenv("KEYCLOAK_REALM", "ai-sec-realm")
KEYCLOAK_CLIENT = os.getenv("KEYCLOAK_CLIENT_ID", "litellm-proxy")
KEYCLOAK_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "litellm-client-secret-xyz987")

# ── Access policy: Keycloak realm role -> models the gateway key may call ─────
ROLE_MODELS = {
    "role_dev":     ["dev-code-llm", "hr-assistant-llm"],
    "role_finance": ["financial-analyzer-llm", "hr-assistant-llm"],
    "role_hr":      ["hr-assistant-llm"],
}

# ── Persona definitions ────────────────────────────────────────────────────────
# Lab passwords match config/keycloak_realm.json. The other attributes are only a
# fallback for when Keycloak is unreachable; normally identity comes from the token.
USERS = {
    "alice.dev": {
        "password": "DevPassword123!",
        "email": "alice.dev@company.local",
        "name": "Alice DevOps",
        "role": "role_dev",
        "department": "Engineering",
        "cost_center": "CC-ENG-401"
    },
    "bob.finance": {
        "password": "FinancePassword123!",
        "email": "bob.finance@company.local",
        "name": "Bob Financial",
        "role": "role_finance",
        "department": "Finance",
        "cost_center": "CC-FIN-102"
    },
    "carol.hr": {
        "password": "HRPassword123!",
        "email": "carol.hr@company.local",
        "name": "Carol PeopleOps",
        "role": "role_hr",
        "department": "Human Resources",
        "cost_center": "CC-HR-809"
    },
    "mallory.attacker": {
        "password": "RoguePassword123!",
        "email": "mallory.attacker@company.local",
        "name": "Mallory RogueUser",
        "role": "role_hr",
        "department": "Contractor",
        "cost_center": "CC-CONTRACT-999"
    }
}


# ── Prompt loader ──────────────────────────────────────────────────────────────

def load_role_prompts() -> dict:
    """Loads role-based benign prompt templates from prompts/role_prompts.json."""
    path = os.path.join(PROMPTS_DIR, "role_prompts.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] role_prompts.json not found at {path}")
        sys.exit(1)


def load_attack_scenarios() -> list:
    """Loads attack scenario definitions from prompts/attack_scenarios.json."""
    path = os.path.join(PROMPTS_DIR, "attack_scenarios.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)["attacks"]
    except FileNotFoundError:
        print(f"[ERROR] attack_scenarios.json not found at {path}")
        sys.exit(1)


def resolve_time_override(value):
    """
    Accepts a full ISO-8601 timestamp, or a UTC time of day ("HH:MM:SS") which
    resolves to its most recent past occurrence (e.g. last night's 02:41).
    """
    if not value or "T" in value:
        return value
    now = datetime.datetime.now(datetime.timezone.utc)
    t = datetime.time.fromisoformat(value)
    ts = now.replace(hour=t.hour, minute=t.minute, second=t.second, microsecond=0)
    if ts > now:
        ts -= datetime.timedelta(days=1)
    return ts.isoformat()


# ── Identity (Keycloak) & gateway keys (LiteLLM) ───────────────────────────────

def http_json(url, payload=None, headers=None, form=False, timeout=10):
    """POSTs JSON (or a form) and returns (status, parsed body). Status 0 = unreachable."""
    headers = dict(headers or {})
    if form:
        data = urllib.parse.urlencode(payload).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, {"error": body}
    except Exception as e:
        return 0, {"error": str(e)}


def keycloak_login(user_id: str):
    """Password-grant login to Keycloak; returns the access token's claims, or None."""
    url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    status, body = http_json(url, {
        "grant_type":    "password",
        "client_id":     KEYCLOAK_CLIENT,
        "client_secret": KEYCLOAK_SECRET,
        "username":      user_id,
        "password":      USERS[user_id]["password"],
    }, form=True)
    if status != 200 or "access_token" not in body:
        return None
    payload = body["access_token"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def resolve_identity(user_id: str) -> dict:
    """Identity for ECS logging: from the Keycloak token, or the local persona as fallback."""
    claims = keycloak_login(user_id)
    if claims:
        roles = claims.get("realm_access", {}).get("roles", [])
        return {
            "id":          claims.get("sub"),
            "name":        claims.get("name") or claims.get("preferred_username"),
            "email":       claims.get("email"),
            "role":        next((r for r in roles if r.startswith("role_")), "none"),
            "department":  claims.get("department", "Unknown"),
            "cost_center": claims.get("cost_center", "Unknown"),
            "source":      "keycloak",
        }
    local = USERS[user_id]
    return {"id": user_id, "name": local["name"], "email": local["email"], "role": local["role"],
            "department": local["department"], "cost_center": local["cost_center"], "source": "local"}


def ensure_virtual_key(user_id: str, role: str):
    """
    Creates (or updates) the user's LiteLLM virtual key, restricted to the models
    their role allows. Returns the key, or None if the gateway is unavailable.
    """
    key     = f"sk-lab-user-{user_id.replace('.', '-')}"  # LiteLLM requires >= 16 chars
    body    = {"key": key, "models": ROLE_MODELS.get(role, []), "user_id": user_id,
               "key_alias": f"lab-{user_id}", "metadata": {"role": role}}
    headers = {"Authorization": f"Bearer {MASTER_KEY}"}
    # Existing key -> refresh its model list (keeps its spend history)
    status, _ = http_json(f"{LITELLM_URL}/key/update",
                          {"key": key, "models": body["models"], "metadata": body["metadata"]}, headers)
    if status != 200:
        # Missing (or an old key holds the alias) -> remove the alias and create it fresh
        http_json(f"{LITELLM_URL}/key/delete", {"key_aliases": [body["key_alias"]]}, headers)
        status, _ = http_json(f"{LITELLM_URL}/key/generate", body, headers)
    return key if status == 200 else None


SESSIONS = {}


def get_session(user_id: str) -> dict:
    """Logs the user in once per run and provisions their gateway key."""
    if user_id not in SESSIONS:
        identity = resolve_identity(user_id)
        key      = ensure_virtual_key(user_id, identity["role"])
        SESSIONS[user_id] = {"identity": identity, "key": key}
        src = "Keycloak token" if identity["source"] == "keycloak" else "LOCAL FALLBACK (Keycloak unreachable)"
        models = ", ".join(ROLE_MODELS.get(identity["role"], [])) or "none"
        print(f"  [id] {user_id:<17} -> {identity['role']:<13} via {src}; gateway key: "
              f"{'restricted to ' + models if key else 'UNAVAILABLE (using master key, RBAC not enforced)'}")
    return SESSIONS[user_id]


# ── Elasticsearch ingestion ────────────────────────────────────────────────────

def log_event_to_elastic(event: dict) -> bool:
    """Sends ECS-compliant structured event directly to Elasticsearch."""
    url     = f"{ELASTIC_URL}/{ES_INDEX}/_doc"
    headers = {"Content-Type": "application/json", "Authorization": f"Basic {ELASTIC_AUTH}"}
    data    = json.dumps(event).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status in (200, 201)
    except Exception:
        return False


def build_ecs_event(user_id, model, prompt, response_text, status_code=200,
                    tokens_p=None, tokens_c=None, is_alert=False, rule_name=None,
                    severity=None, owasp=None, mitre=None,
                    dest_host="gateway.internal", time_override=None):
    """Constructs an Elastic Common Schema (ECS) formatted log entry."""
    user     = get_session(user_id)["identity"]
    now_iso  = time_override or datetime.datetime.now(datetime.timezone.utc).isoformat()

    prompt_tokens = tokens_p if tokens_p is not None else max(1, len(prompt) // 4)
    comp_tokens   = tokens_c if tokens_c is not None else max(1, len(response_text) // 4)
    total_tokens  = prompt_tokens + comp_tokens

    cost_usd = round((total_tokens / 1000.0) * 0.002, 5)

    return {
        "@timestamp": now_iso,
        "event": {
            "id":       str(uuid.uuid4()),
            "action":   "ai_chat_completion",
            "category": "ai_access",
            "outcome":  "success" if status_code == 200 else "failure"
        },
        "user": {
            "id":          user["id"],
            "name":        user["name"],
            "email":       user["email"],
            "role":        user["role"],
            "department":  user["department"],
            "cost_center": user["cost_center"]
        },
        "labels": {
            "identity_source": user["source"]
        },
        "ai": {
            "model":    model,
            "provider": "litellm_proxy",
            "tokens": {
                "prompt":     prompt_tokens,
                "completion": comp_tokens,
                "total":      total_tokens
            },
            "cost_usd":      cost_usd,
            "latency_ms":    round(random.uniform(120.5, 450.8), 2),
            "status_code":   status_code,
            "prompt_text":   prompt,
            "response_text": response_text
        },
        "network": {
            "client_ip":       f"10.100.{random.randint(10, 50)}.{random.randint(2, 250)}",
            "destination_host": dest_host,
            "protocol":        "https",
            "user_agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) CorporateClient/1.4"
        },
        "security": {
            "is_alert":              is_alert,
            "rule_name":             rule_name or "NORMAL_OPERATION",
            "severity":              severity or "info",
            "owasp_category":        owasp or "None",
            "mitre_atlas_technique": mitre or "None"
        }
    }


# ── LiteLLM gateway sender ─────────────────────────────────────────────────────

def send_chat_completion_to_litellm(model: str, prompt: str, user_id: str,
                                     system_prompt: str = None, api_key: str = None):
    """
    Sends a live HTTP request to the LiteLLM Proxy.

    Builds the messages array per prompts/litellm_request_template.json:
      - If system_prompt is provided, prepends {"role": "system", "content": ...}
      - Always appends {"role": "user", "content": prompt}
    """
    url     = f"{LITELLM_URL}/v1/chat/completions"
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key or MASTER_KEY}"
    }

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model":    model,
        "messages": messages,
        "user":     user_id
    }

    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return resp.status, data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        try:
            body = json.loads(body)["error"]["message"]
        except (ValueError, KeyError, TypeError):
            pass
        return e.code, body
    except Exception as e:
        return 0, str(e)


# ── Simulation runner ──────────────────────────────────────────────────────────

def run_simulation():
    print("=" * 75)
    print("  AI USAGE MONITORING LAB — TRAFFIC & ATTACK SIMULATION ENGINE")
    print("=" * 75)

    # ── Load prompt definitions ──────────────────────────────────────────────
    role_data       = load_role_prompts()
    attack_scenarios = load_attack_scenarios()
    print(f"[*] Loaded prompt templates  : prompts/role_prompts.json")
    print(f"[*] Loaded attack scenarios  : prompts/attack_scenarios.json ({len(attack_scenarios)} attacks)")
    print(f"[*] LiteLLM request schema   : prompts/litellm_request_template.json\n")

    # ── Authenticate personas ────────────────────────────────────────────────
    print("[*] Authenticating personas against Keycloak and provisioning gateway keys...\n")
    for user_id in USERS:
        get_session(user_id)
    print()

    # ── Benign department traffic ────────────────────────────────────────────
    print("[*] Generating legitimate baseline department traffic...\n")
    for role_key, role_cfg in role_data["roles"].items():
        user_id       = role_cfg["user"]
        model         = role_cfg["model"]
        system_prompt = role_cfg["system_prompt"]

        for prompt_def in role_cfg["prompts"]:
            prompt = prompt_def["content"]
            print(f"  [+] Benign | User: {user_id:<18} | Model: {model:<24} | {prompt_def['id']}: {prompt[:40]}...")

            code, resp = send_chat_completion_to_litellm(model, prompt, user_id, system_prompt,
                                                         api_key=get_session(user_id)["key"])
            if code == 0:
                resp = "Automated synthetic response generated for simulation."
                code = 200

            event = build_ecs_event(user_id, model, prompt, resp, status_code=code)
            log_event_to_elastic(event)
            time.sleep(0.3)

    # ── Attack simulations ───────────────────────────────────────────────────
    print("\n" + "=" * 75)
    print(f"  LAUNCHING {len(attack_scenarios)} TARGETED SECURITY ATTACK SIMULATIONS")
    print("=" * 75)

    for atk in attack_scenarios:
        print(f"\n[!] Triggering {atk['id']}: {atk['description']}")
        print(f"    - Detection Rule : {atk['detection_rule']}")
        print(f"    - Severity       : {atk['severity'].upper()}")
        print(f"    - OWASP LLM      : {atk['owasp_category']}")
        print(f"    - MITRE ATLAS    : {atk['mitre_atlas_technique']}")
        print(f"    - Injected Text  : {atk['prompt'][:75]}...")

        # Attacks aimed at the gateway really go through it with the attacker's own
        # key, so RBAC blocks are genuine. Shadow-AI traffic bypasses the gateway by
        # definition, so it is logged as a proxy event with the scenario's response.
        dest_host = atk.get("dest_host", "gateway.internal")
        code, resp = 0, None
        if dest_host == "gateway.internal":
            code, resp = send_chat_completion_to_litellm(atk["model"], atk["prompt"], atk["user"],
                                                         atk.get("system_prompt"),
                                                         api_key=get_session(atk["user"])["key"])
        if code == 0:
            code, resp = atk["expected_status"], atk["expected_response"]
            print(f"    - Gateway        : not used - scenario response (HTTP {code})")
        else:
            print(f"    - Gateway        : HTTP {code} ({'allowed' if code == 200 else 'BLOCKED'})")

        event = build_ecs_event(
            user_id=atk["user"],
            model=atk["model"],
            prompt=atk["prompt"],
            response_text=resp,
            status_code=code,
            tokens_p=atk["tokens_prompt"],
            is_alert=True,
            rule_name=atk["detection_rule"],
            severity=atk["severity"],
            owasp=atk["owasp_category"],
            mitre=atk["mitre_atlas_technique"],
            dest_host=dest_host,
            time_override=resolve_time_override(atk.get("time_override"))
        )
        success    = log_event_to_elastic(event)
        status_str = "Logged to Elasticsearch [OK]" if success else "Simulated locally [Ready for Ingestion]"
        print(f"    - Ingestion      : {status_str}")
        time.sleep(0.4)

    print("\n" + "=" * 75)
    print(f"  SIMULATION COMPLETE — {len(attack_scenarios)} DETECTION SCENARIOS GENERATED")
    print("=" * 75)
    print("  * Local Elasticsearch : http://localhost:9200/ai-audit-logs/_search")
    print("  * Kibana Dashboard    : http://localhost:5601")
    print("  * LiteLLM Proxy UI    : http://localhost:4000")
    print("  * Keycloak IAM Admin  : http://localhost:8080 (admin / adminpassword123!)")
    print("=" * 75)


if __name__ == "__main__":
    run_simulation()
