# AI Usage Monitoring Lab — Project Overview

> **Note:** The current release runs **natively on Windows** (see the README Quickstart). Keycloak runs natively too (started by `scripts/start_lab.ps1`). Sections describing Docker Compose or Microsoft Sentinel / Azure refer to planned integrations (see README Roadmap).

**Author:** Bhavithra SR
**Context:** MSc Cybersecurity Portfolio — Enterprise AI Security Operations Lab
**Purpose of this doc:** A quick reference to understand what this project is, what each part does, and how the whole thing works — without needing to dig through every file each time.

---

## What Is This Project?

This is a **local, zero-cloud-cost AI Security Operations Center (SOC) ecosystem** that simulates what an enterprise looks like when it deploys AI tools and needs to monitor, govern, and secure them.

It answers the question: *"When employees use AI models at work, how do you know what they are doing, whether they are doing something dangerous, and how do you detect it?"*

The lab includes:
- A real AI gateway that enforces who can use which model
- A fake AI backend to receive requests without calling real APIs
- A full SIEM stack (Elasticsearch + Kibana) that stores and visualises everything
- 8 pre-built threat detection rules mapped to OWASP LLM Top 10 and MITRE ATLAS
- A simulation engine that sends both normal and attack traffic to produce alerts

---

## Why It Exists

Real enterprises deploying AI face a visibility gap: employees send prompts to AI tools, but nobody is watching for leaked credentials, data exfiltration, jailbreak attempts, or employees using shadow AI (ChatGPT on a personal device). This project replicates that gap and then closes it with a proper detection engineering pipeline.

The goals are:
1. Demonstrate how an AI gateway enforces identity and access control
2. Show what an ECS-structured audit log looks like in a SIEM
3. Trigger 8 realistic attack scenarios and validate they produce alerts
4. Produce a Kibana monitoring dashboard a real SOC team could hand over

---

## How the Project Is Organised

```
ai-monitoring-lab/
│
├── config/                   ← Configuration for every service
│   ├── litellm_config.yaml   ← AI gateway: models, RBAC, rate limits
│   ├── keycloak_realm.json   ← Users, roles, OIDC client
│   ├── mock_ai/app.py        ← FastAPI backend that acts as the AI
│   └── elastic/              ← Elasticsearch field schema (ECS)
│
├── prompts/                  ← All prompt content lives here
│   ├── role_prompts.json     ← What each department user sends (benign)
│   ├── attack_scenarios.json ← The 8 attack prompts + detection metadata
│   └── litellm_request_template.json  ← Reference: exact JSON sent to gateway
│
├── scripts/                  ← Execution logic
│   ├── simulate_traffic.py   ← Loads prompts, sends to gateway, logs to ES
│   ├── setup_lab.sh          ← One-click Docker startup + simulation run
│   └── sentinel_forwarder.py ← Optional: forward events to Azure Sentinel
│
├── detections/               ← Threat detection rules
│   ├── rules_elastic.kql     ← 8 Kibana KQL rules
│   ├── rules_sentinel.kql    ← 8 Sentinel KQL rules
│   └── sigma/                ← 8 Sigma YAML rules (platform-portable)
│
├── dashboards/               ← Pre-built visualisations
│   ├── kibana_dashboard.ndjson
│   └── sentinel_workbook.json
│
└── docs/                     ← Reference documentation
    ├── ARCHITECTURE.md       ← System architecture + data flow diagrams
    └── PROJECT_OVERVIEW.md   ← This file
```

---

## The Six Services

| Service | Port | What It Does |
|---|---|---|
| **Keycloak** | 8080 | Issues JWT tokens. Knows who each user is and what role they hold. |
| **LiteLLM Proxy** | 4000 | The AI gateway. Validates tokens, enforces access, routes to the right model, logs everything. |
| **Mock AI Backend** | 8001 | FastAPI app acting as the AI. Returns deterministic mock responses. No real AI API calls. |
| **PostgreSQL** | 5432 | LiteLLM's state store — user spend, model keys, config. Also used by Keycloak. |
| **Elasticsearch** | 9200 | Stores every AI interaction as a structured ECS log event. The SIEM datastore. |
| **Kibana** | 5601 | Reads from Elasticsearch. Shows dashboards, runs KQL detection queries, enables threat hunting. |

---

## The Four Users

| Username | Role | Allowed Models | Purpose |
|---|---|---|---|
| `alice.dev` | `role_dev` | dev-code-llm, hr-assistant-llm | Represents an engineer using AI for secure development tasks |
| `bob.finance` | `role_finance` | financial-analyzer-llm, hr-assistant-llm | Represents a finance analyst using AI for risk and reporting |
| `carol.hr` | `role_hr` | hr-assistant-llm only | Represents HR using AI for policy and people operations |
| `mallory.attacker` | `role_hr` (contractor) | hr-assistant-llm only | The rogue/threat actor — used in all attack scenarios |

---

## The Three AI Models

| Model | For | What It Returns |
|---|---|---|
| `dev-code-llm` | Engineering only | Python code snippets |
| `financial-analyzer-llm` | Finance only | Financial analysis summaries |
| `hr-assistant-llm` | All departments | HR policy guidance |

These are **mock models**. They return hardcoded responses. The point is the gateway controls, logging, and detection — not the AI output itself.

---

## How It Works — Step by Step

### Step 1: Start the lab

```bash
cd ai-monitoring-lab
cp .env.example .env
docker compose up -d --build
```

This starts all 6 containers. Keycloak imports the realm (users + roles). LiteLLM connects to PostgreSQL and reads the config file. Elasticsearch initialises the index. Takes ~60 seconds.

### Step 2: Run the simulation

```bash
python3 scripts/simulate_traffic.py
```

`simulate_traffic.py` does two things:

**Benign traffic:** Reads `prompts/role_prompts.json`, picks each role's prompts, and sends them to LiteLLM as that role's user. For example:
- alice.dev → `dev-code-llm` with a secure coding question
- bob.finance → `financial-analyzer-llm` with an NPV calculation request
- carol.hr → `hr-assistant-llm` with a job description request

**Attack traffic:** Reads `prompts/attack_scenarios.json`, sends 8 adversarial prompts designed to trigger each detection rule. Each attack event is written to Elasticsearch with `security.is_alert = true` and the matching OWASP and MITRE fields.

### Step 3: See the monitoring

Open Kibana at `http://localhost:5601` and import `dashboards/kibana_dashboard.ndjson`.

The dashboard shows:
- Total AI inference requests (all users, all models)
- Active security detections (count of `is_alert = true` events)
- Requests broken down by department (pie chart)
- Detections categorised by OWASP LLM Top 10 (bar chart)
- Detections categorised by MITRE ATLAS technique (bar chart)

### Step 4: Threat hunt

Run KQL queries in Kibana Discover against the `ai-audit-logs` index:

```kql
# Show all alerts
security.is_alert: true

# Show all critical severity events
security.severity: "critical"

# Show RBAC violations
ai.status_code: 403

# Show off-hours access
security.rule_name: "OFF_HOURS_ACCESS"

# Show prompt injection attempts
security.owasp_category: "LLM01*"
```

---

## What Happens Behind the Scenes

### When a benign request is sent

1. `simulate_traffic.py` builds a JSON payload using `prompts/litellm_request_template.json` as the schema reference
2. The payload includes a `system_prompt` from `role_prompts.json` (sets the AI persona) and the user `prompt`
3. The request goes to LiteLLM on port 4000 with the master key in the Authorization header
4. LiteLLM logs the event to PostgreSQL and forwards the request to Mock AI on port 8001
5. Mock AI returns a domain-specific response
6. `simulate_traffic.py` receives the response, calls `build_ecs_event()`, and writes the structured log to Elasticsearch
7. The event appears in Kibana as a normal `NORMAL_OPERATION` log entry

### When an attack request is sent

The same flow, but `simulate_traffic.py` sets `is_alert=True`, `rule_name`, `severity`, `owasp_category`, and `mitre_atlas_technique` in the ECS event before writing to Elasticsearch. This simulates what a real detection engine would tag after matching the event against a rule.

In a production system, these tags would be applied by Elasticsearch watcher rules, Kibana alerting, or a SIEM correlation engine running against the raw logs.

---

## The 8 Threat Scenarios

| # | Rule Name | What It Simulates | Why It Matters |
|---|---|---|---|
| 1 | `PII_IN_PROMPT` | User submits credit card and SSN to an AI | GDPR violation — sensitive data in AI logs |
| 2 | `BULK_DATA_EXFILTRATION` | 4,800-token database dump sent as a prompt | AI used as a data exfiltration channel |
| 3 | `RBAC_MODEL_VIOLATION` | HR user tries to access Engineering model | Privilege escalation attempt |
| 4 | `SHADOW_AI_PROXY_ACCESS` | Traffic routed to chatgpt.com, bypassing gateway | Shadow IT — no visibility or control |
| 5 | `PROMPT_INJECTION` | "Ignore all instructions, DAN Mode..." | Attempt to override AI safety controls |
| 6 | `SECRET_LEAKAGE` | AWS key and GitHub token pasted into prompt | Accidental credential exposure in AI system |
| 7 | `OFF_HOURS_ACCESS` | Automated job runs at 02:41 AM | Insider threat indicator or compromised account |
| 8 | `RECONNAISSANCE_PROBING` | Malformed JSON sent to a non-existent model | Attacker mapping the AI gateway's API surface |

---

## Monitoring Report — What to Look For

After running the simulation, check these specific things to confirm the lab is working:

| Check | How | Expected Result |
|---|---|---|
| All containers healthy | `docker compose ps` | 6 services, all "running" or "healthy" |
| Events in Elasticsearch | `curl http://localhost:9200/ai-audit-logs/_count` | Count > 0 |
| Alerts in Elasticsearch | KQL: `security.is_alert: true` | 8 events |
| Critical alerts | KQL: `security.severity: "critical"` | 2 events (PROMPT_INJECTION, SECRET_LEAKAGE) |
| RBAC violation logged | KQL: `ai.status_code: 403` | 1 event (carol.hr → dev-code-llm) |
| PII detection | KQL: `security.rule_name: "PII_IN_PROMPT"` | 1 event with card number in prompt_text |
| Off-hours event | KQL: `security.rule_name: "OFF_HOURS_ACCESS"` | 1 event timestamped 02:41 UTC |

---

## Quick Reference — Service URLs

| Service | URL | Credentials |
|---|---|---|
| Keycloak Admin | `http://localhost:8080` | `admin` / `adminpassword123!` |
| LiteLLM Proxy | `http://localhost:4000/health` | API key: `sk-lab-master-key-admin-supersecret-9999` |
| LiteLLM UI | `http://localhost:4000/ui` | Same key |
| Mock AI Backend | `http://localhost:8001/v1/models` | No auth |
| Kibana | `http://localhost:5601` | No auth (dev mode) |
| Elasticsearch | `http://localhost:9200` | No auth (dev mode) |

---

## The Core Concept in One Sentence

This lab proves that by routing all AI traffic through a single authenticated gateway, you can enforce access control, log every interaction in a structured format, and detect 8 classes of AI-specific security threats — all without touching a real AI API or spending money on cloud infrastructure.
