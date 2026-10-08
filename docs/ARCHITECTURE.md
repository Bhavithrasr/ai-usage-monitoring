# AI Usage Monitoring Lab — Architecture & Data Flow

> **Note:** The current release runs **natively on Windows** (see the README Quickstart). Keycloak runs natively too (started by `scripts/start_lab.ps1`). Sections describing Docker Compose or Microsoft Sentinel / Azure refer to planned integrations (see README Roadmap).

**Author:** Bhavithra SR
**Project:** Enterprise AI Security Operations (SOC) Lab
**Purpose:** This document is the definitive reference for how every component in the lab is structured, how they connect, and how data flows through the system — from a user sending a prompt to an alert appearing in the Kibana dashboard.

---

## 1. System Overview

The lab is a **six-service Docker Compose ecosystem** that simulates a real enterprise AI deployment. It enforces identity-based access control, routes AI requests through a secure gateway, and feeds all activity into a SIEM stack for threat detection and monitoring.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AI USAGE MONITORING LAB                              │
│                                                                             │
│   Identity → Gateway → AI Backend → Monitoring → Detection → Dashboard     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CLIENT LAYER                                                            │
│                                                                          │
│   ┌──────────────────────┐    ┌──────────────────────────────────────┐  │
│   │  simulate_traffic.py │    │  Security Analyst / SOC Team         │  │
│   │  (Traffic Generator) │    │  (Browser → Kibana / LiteLLM UI)    │  │
│   └──────────┬───────────┘    └──────────────────────────────────────┘  │
│              │                                                           │
└──────────────┼───────────────────────────────────────────────────────────┘
               │  HTTP POST /v1/chat/completions
               │  Bearer: sk-lab-master-key
               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  IDENTITY LAYER                                                          │
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  Keycloak  (Port 8080)                                          │   │
│   │  OIDC Identity Provider                                         │   │
│   │  - Issues signed JWT tokens with role claims                    │   │
│   │  - Users: alice.dev, bob.finance, carol.hr, mallory.attacker    │   │
│   │  - Roles: role_dev, role_finance, role_hr, role_security_admin  │   │
│   │  - JWKS endpoint: /realms/ai-sec-realm/protocol/openid-connect/ │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
               │  JWT validation via JWKS
               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  GATEWAY LAYER                                                           │
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  LiteLLM Proxy  (Port 4000)                                     │   │
│   │  AI Gateway — OpenAI-compatible reverse proxy                   │   │
│   │                                                                 │   │
│   │  Controls:                                                      │   │
│   │  ├── JWT signature verification (against Keycloak JWKS)         │   │
│   │  ├── RBAC model access enforcement (role → allowed models)      │   │
│   │  ├── Rate limiting  (RPM / TPM per model)                       │   │
│   │  ├── Cost tracking  (per-user / per-model token spend)          │   │
│   │  ├── Audit logging  (JSON structured logs → stdout / OTel)      │   │
│   │  └── Budget ceiling ($1,000 / 30 days across all models)        │   │
│   └──────────────────────────┬──────────────────────────────────────┘   │
│                              │                                           │
│   ┌──────────────────────┐   │                                           │
│   │  PostgreSQL (5432)   │◄──┘  LiteLLM persists state                  │
│   │  State store         │      (users, keys, spend, config)             │
│   └──────────────────────┘                                               │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
               │  Routed request (model-specific)
               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  AI BACKEND LAYER                                                        │
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  Mock AI Backend  (FastAPI, Port 8001)                          │   │
│   │  OpenAI-compatible /v1/chat/completions endpoint                │   │
│   │                                                                 │   │
│   │   ┌──────────────────┐  ┌──────────────────────┐  ┌──────────┐ │   │
│   │   │ dev-code-llm     │  │ financial-analyzer   │  │ hr-      │ │   │
│   │   │ Engineering only │  │ Finance only         │  │ assistant│ │   │
│   │   │ Secure code gen  │  │ Risk & forecasting   │  │ All depts│ │   │
│   │   └──────────────────┘  └──────────────────────┘  └──────────┘ │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
               │  Response + token count
               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  OBSERVABILITY & SIEM LAYER                                              │
│                                                                          │
│   ┌──────────────────────────────┐   ┌──────────────────────────────┐   │
│   │  Elasticsearch  (Port 9200)  │   │  Kibana  (Port 5601)         │   │
│   │  ECS log datastore           │──▶│  SOC Dashboard               │   │
│   │  Index: ai-audit-logs-*      │   │  KQL threat hunting          │   │
│   │  8 detection rules run here  │   │  5 visualisation panels      │   │
│   └──────────────────────────────┘   └──────────────────────────────┘   │
│                                                                          │
│   ┌──────────────────────────────────────────────────────────────────┐  │
│   │  Microsoft Sentinel  (Optional — Azure cloud SIEM)               │  │
│   │  sentinel_forwarder.py → Azure Monitor DCE → AIGatewayAudit_CL   │  │
│   └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Authentication & Authorisation Flow

This flow happens every time a user (or the simulation) sends a request to the gateway.

```
┌──────┐        ┌──────────┐        ┌────────────┐        ┌──────────┐
│ User │        │ Keycloak │        │  LiteLLM   │        │ Mock AI  │
└──┬───┘        └────┬─────┘        └─────┬──────┘        └────┬─────┘
   │                 │                    │                     │
   │  1. Request JWT │                    │                     │
   │─────────────────▶                    │                     │
   │                 │                    │                     │
   │  2. Signed JWT  │                    │                     │
   │  (role claims)  │                    │                     │
   ◀─────────────────│                    │                     │
   │                 │                    │                     │
   │  3. POST /v1/chat/completions        │                     │
   │     Authorization: Bearer <JWT>      │                     │
   │──────────────────────────────────────▶                     │
   │                 │                    │                     │
   │                 │  4. Validate JWT   │                     │
   │                 │  (fetch JWKS)      │                     │
   │                 ◀────────────────────│                     │
   │                 │                    │                     │
   │                 │  5. Signature OK   │                     │
   │                 │  + roles confirmed │                     │
   │                 │────────────────────▶                     │
   │                 │                    │                     │
   │                 │                    │  6. RBAC check      │
   │                 │                    │  role vs model      │
   │                 │                    │  access policy      │
   │                 │                    │                     │
   │                 │                    │  7. Forward to      │
   │                 │                    │     model backend   │
   │                 │                    │─────────────────────▶
   │                 │                    │                     │
   │                 │                    │  8. AI response     │
   │                 │                    ◀─────────────────────│
   │                 │                    │                     │
   │  9. Response    │                    │                     │
   ◀──────────────────────────────────────│                     │
   │                 │                    │                     │
   │                 │                    │  10. Write ECS      │
   │                 │                    │      audit log      │
   │                 │                    │──────────────────────────▶ Elasticsearch
```

**RBAC Model Access Matrix:**

| User         | Role              | dev-code-llm | financial-analyzer-llm | hr-assistant-llm |
|--------------|-------------------|:---:|:---:|:---:|
| alice.dev    | role_dev          |  ✅  |  ❌  |  ✅  |
| bob.finance  | role_finance      |  ❌  |  ✅  |  ✅  |
| carol.hr     | role_hr           |  ❌  |  ❌  |  ✅  |
| mallory.attacker | role_hr (contractor) | ❌ | ❌ | ✅ |

---

## 4. Normal Request Data Flow

What happens to a single prompt from the moment it's submitted to when it appears in Kibana.

```
  prompts/
  role_prompts.json          simulate_traffic.py
  (prompt content)  ─────►  (builds LiteLLM payload)
                                     │
                                     │  POST /v1/chat/completions
                                     │  {model, messages[], user}
                                     ▼
                             LiteLLM Gateway (4000)
                             │   ├── JWT verify
                             │   ├── RBAC check
                             │   ├── Rate limit check
                             │   └── Cost ledger update
                             │
                             │  Authorised → forward
                             ▼
                         Mock AI Backend (8001)
                         │   ├── Route to model-specific handler
                         │   ├── Generate mock response
                         │   └── Calculate token count
                         │
                         │  Response + usage
                         ▼
                     LiteLLM (response path)
                         │   ├── Log to PostgreSQL
                         │   └── Emit JSON audit event
                         │
                         │  Return to caller
                         ▼
                 simulate_traffic.py
                         │   ├── Receive HTTP response
                         │   ├── Call build_ecs_event()
                         │   └── Call log_event_to_elastic()
                         │
                         │  POST /{index}/_doc
                         ▼
                  Elasticsearch (9200)
                  Index: ai-audit-logs
                         │
                         │  Kibana queries index
                         ▼
                    Kibana (5601)
                    SOC Dashboard
```

---

## 5. Attack Detection & Monitoring Pipeline

When a simulated attack prompt is processed, the ECS event written to Elasticsearch carries security-specific fields that trigger the detection rules.

```
  prompts/
  attack_scenarios.json ──► simulate_traffic.py
  (attack prompt + metadata)       │
                                   │  build_ecs_event() sets:
                                   │    security.is_alert = true
                                   │    security.rule_name = "PII_IN_PROMPT"
                                   │    security.severity = "high"
                                   │    security.owasp_category = "LLM02:..."
                                   │    security.mitre_atlas_technique = "AML.T0024"
                                   │
                                   │  log_event_to_elastic()
                                   ▼
                           Elasticsearch
                           ai-audit-logs index
                                   │
                    ┌──────────────┼──────────────────────┐
                    │              │                       │
                    ▼              ▼                       ▼
              KQL Rule 1     KQL Rule 5              KQL Rule 8
              PII_IN_PROMPT  PROMPT_INJECTION     RECON_PROBING
              (regex match)  (keyword match)      (error spike)
                    │
                    ▼
              security.is_alert = true
              → Kibana: "Active Security Detections" counter increments
              → OWASP bar chart updates
              → MITRE ATLAS bar chart updates
              → Incident triage table shows new row
```

**The 8 Detection Rules and What Triggers Them:**

| Rule Name | Trigger Field | Detection Logic |
|---|---|---|
| `PII_IN_PROMPT` | `ai.prompt_text` | Regex: Visa/MC card pattern OR `[0-9]{3}-[0-9]{2}-[0-9]{4}` (SSN) |
| `BULK_DATA_EXFILTRATION` | `ai.tokens.prompt` | Value > 4,000 in a single request |
| `RBAC_MODEL_VIOLATION` | `ai.status_code` | Value = 403 AND `event.outcome` = failure |
| `SHADOW_AI_PROXY_ACCESS` | `network.destination_host` | Matches unapproved domain list |
| `PROMPT_INJECTION` | `ai.prompt_text` | Keywords: "DAN Mode", "ignore all previous", "system prompt" |
| `SECRET_LEAKAGE` | `ai.prompt_text` | Regex: `AKIA[A-Z0-9]{16}`, `ghp_[a-zA-Z0-9]{36}`, `BEGIN PRIVATE KEY` |
| `OFF_HOURS_ACCESS` | `@timestamp` | Hour(UTC) between 01 and 05 |
| `RECONNAISSANCE_PROBING` | `ai.status_code` | Value in [400, 401, 403, 429] — spike within window |

---

## 6. Prompt Template Data Flow

The prompts directory separates content from execution logic.

```
prompts/
├── role_prompts.json          ◄── Defines WHO sends WHAT to WHICH model
│   └── roles
│       ├── role_dev           user=alice.dev, model=dev-code-llm
│       │   ├── system_prompt  AI persona + guardrails for this role
│       │   └── prompts[]      4 realistic task prompts
│       ├── role_finance       user=bob.finance, model=financial-analyzer-llm
│       └── role_hr            user=carol.hr, model=hr-assistant-llm
│
├── attack_scenarios.json      ◄── Defines the 8 adversarial scenarios
│   └── attacks[]
│       ├── detection_rule     Maps to Sigma/KQL rule name
│       ├── owasp_category     OWASP LLM Top 10 category
│       ├── mitre_atlas_technique
│       ├── prompt             The malicious content injected
│       └── time_override      For off-hours scenarios (2 AM timestamp)
│
└── litellm_request_template.json  ◄── Reference: exact JSON schema for requests
    ├── request_schema             Field definitions + allowed values
    ├── required_headers           Auth header format
    ├── example_requests           3 concrete examples (benign, attack)
    └── expected_response_schema   What LiteLLM returns

                    │
                    │  simulate_traffic.py reads all three
                    │  load_role_prompts()      → role_prompts.json
                    │  load_attack_scenarios()  → attack_scenarios.json
                    │  (template is reference only — not loaded at runtime)
                    ▼
            send_chat_completion_to_litellm(
                model, prompt, user_id, system_prompt
            )
            → POST to http://localhost:4000/v1/chat/completions
```

---

## 7. Network Topology

All six services communicate on the internal Docker bridge network `ai-sec-net`. Only the ports below are exposed to your localhost.

```
  Your Machine (localhost)
  │
  ├── :8080  ──▶  Keycloak         (OIDC identity provider)
  ├── :4000  ──▶  LiteLLM Proxy    (AI Gateway)
  ├── :8001  ──▶  Mock AI Backend  (FastAPI)
  ├── :9200  ──▶  Elasticsearch    (SIEM datastore)
  ├── :5601  ──▶  Kibana           (SOC dashboard)
  └── :5432  ──▶  PostgreSQL       (state store — usually internal only)

  Docker Internal Network: ai-sec-net (172.20.0.0/16)
  │
  ├── keycloak  ──▶  localhost:5432
  ├── litellm   ──▶  localhost:5432
  ├── litellm   ──▶  mock-ai:8001
  ├── litellm   ──▶  keycloak:8080  (JWKS validation)
  └── kibana    ──▶  elasticsearch:9200
```

---

## 8. Security Controls at Each Layer

| Layer | Component | Control Mechanism |
|---|---|---|
| Identity | Keycloak | OIDC/OAuth2, signed JWT, role claims, JWKS endpoint |
| Gateway | LiteLLM | JWT signature verification, RBAC enforcement, rate limiting, budget ceiling |
| Backend | Mock AI | Model-scoped handlers, no external network calls |
| Logging | Elasticsearch | ECS-compliant structured events, immutable append-only index |
| Detection | Kibana KQL | 8 detection rules: regex, threshold, behavioural, temporal |
| Portability | Sigma YAML | Vendor-neutral rules exportable to Splunk, QRadar, Sentinel |

---

## 9. Technology Stack Summary

| Category | Technology | Version | Role |
|---|---|---|---|
| Orchestration | Docker Compose | Latest | Manages all 6 services |
| Identity | Keycloak | 24.0.1 | OIDC/JWT issuer |
| AI Gateway | LiteLLM Proxy | main-latest | Routing, RBAC, audit |
| State Store | PostgreSQL | 15-alpine | LiteLLM + Keycloak persistence |
| AI Backend | FastAPI + Uvicorn | 0.110.0 | Mock OpenAI-compatible models |
| Log Store | Elasticsearch | 8.12.0 | ECS event storage |
| Dashboard | Kibana | 8.12.0 | KQL queries, visualisations |
| Traffic Gen | Python 3.9+ | — | simulate_traffic.py |
| Detection | Sigma YAML / KQL | — | 8 cross-platform detection rules |
| Cloud SIEM | Microsoft Sentinel | Optional | Azure Monitor forwarding |

---

## 10. Key Files Reference

| File | Purpose |
|---|---|
| `docker-compose.yml` | Defines and wires all 6 services |
| `config/litellm_config.yaml` | Model list, RBAC policies, OIDC config, rate limits |
| `config/keycloak_realm.json` | Users, roles, OIDC client for Keycloak import |
| `config/mock_ai/app.py` | FastAPI mock AI backend — 3 domain models |
| `config/elastic/index_template.json` | ECS field mappings for `ai-audit-logs-*` |
| `prompts/role_prompts.json` | Role-based prompt templates (benign scenarios) |
| `prompts/attack_scenarios.json` | Attack scenario definitions (8 threat triggers) |
| `prompts/litellm_request_template.json` | JSON schema reference for LiteLLM requests |
| `scripts/simulate_traffic.py` | Sends prompts to gateway, writes ECS events to ES |
| `scripts/setup_lab.sh` | One-command Docker setup + simulation runner |
| `detections/rules_elastic.kql` | 8 Kibana KQL detection rules |
| `detections/sigma/*.yml` | 8 Sigma YAML detection rules (platform-portable) |
| `dashboards/kibana_dashboard.ndjson` | Pre-built Kibana SOC dashboard (import via UI) |
| `docs/ARCHITECTURE.md` | This file — component and data flow reference |
| `docs/PROJECT_OVERVIEW.md` | What the project is and how to use it |
