# AI Usage Monitoring Lab: Implementation Knowledge Transfer (KT) & Operations Guide

> **Note:** The current release runs **natively on Windows** (see the README Quickstart). Keycloak runs natively too (started by `scripts/start_lab.ps1`). Sections describing Docker Compose or Microsoft Sentinel / Azure refer to planned integrations (see README Roadmap).

> **Author**: Bhavithra SR  
> **Degree**: MSc in Cybersecurity  
> **Target Audience**: SOC Analysts, Security Engineers, Hiring Managers, Technical Interviewers  
> **Repository Scope**: `ai-monitoring-lab/`

---

## Table of Contents
1. [Architecture & Component Reference](#1-architecture--component-reference)
2. [Step-by-Step Hands-on Deployment Guide](#2-step-by-step-hands-on-deployment-guide)
   - [Phase 1: Environment Preparation](#phase-1-environment-preparation)
   - [Phase 2: Docker Container Orchestration](#phase-2-docker-container-orchestration)
   - [Phase 3: Keycloak Identity & Token Issuance](#phase-3-keycloak-identity--token-issuance)
   - [Phase 4: Gateway Inference & RBAC Enforcement](#phase-4-gateway-inference--rbac-enforcement)
   - [Phase 5: SIEM Ingestion & Attack Simulation](#phase-5-siem-ingestion--attack-simulation)
   - [Phase 6: Kibana Dashboard Import](#phase-6-kibana-dashboard-import)
   - [Phase 7: Optional Microsoft Sentinel Cloud Integration](#phase-7-optional-microsoft-sentinel-cloud-integration)
3. [SOC Alert Triage Playbooks (8 Threat Scenarios)](#3-soc-alert-triage-playbooks)
4. [Operational Troubleshooting Guide](#4-operational-troubleshooting-guide)
5. [Cybersecurity Interview Talking Points & Technical FAQ](#5-cybersecurity-interview-talking-points--technical-faq)

---

## 1. Architecture & Component Reference

The lab integrates 6 modular microservices inside a private Docker bridge network (`ai-sec-net`):

```
+-----------------------------------------------------------------------------------+
| Host Machine (macOS / Linux)                                                      |
|                                                                                   |
|  [Port 8080]  Keycloak IdP (Realm: ai-sec-realm, Users: Dev, Finance, HR)        |
|  [Port 4000]  LiteLLM AI Gateway (Reverse Proxy, RBAC, Quotas, Audit Hooks)       |
|  [Port 8001]  Mock AI Backend (FastAPI: dev-code-llm, financial, hr-assistant)    |
|  [Port 5432]  PostgreSQL (State store for LiteLLM keys & Keycloak)                |
|  [Port 9200]  Elasticsearch (ECS-compliant security event datastore)             |
|  [Port 5601]  Kibana (SOC Dashboards, KQL Alert Hunting)                          |
+-----------------------------------------------------------------------------------+
```

### Port Allocation & Service Endpoints
| Service | Internal Port | Host Port | Health Check URL | Credentials |
| :--- | :--- | :--- | :--- | :--- |
| **Keycloak IAM** | `8080` | `8080` | `http://localhost:8080/health` | `admin` / `adminpassword123!` |
| **LiteLLM Gateway** | `4000` | `4000` | `http://localhost:4000/health` | Master Key: `sk-lab-master-key-admin-supersecret-9999` |
| **Mock AI Backend** | `8001` | `8001` | `http://localhost:8001/health` | Anonymous / Internal |
| **PostgreSQL** | `5432` | `5432` | `pg_isready` | `postgres` / `postgrespassword123!` |
| **Elasticsearch** | `9200` | `9200` | `http://localhost:9200` | Anonymous (Lab mode) |
| **Kibana UI** | `5601` | `5601` | `http://localhost:5601/api/status` | Accessible via browser |

---

## 2. Step-by-Step Hands-on Deployment Guide

Every step below includes exact terminal commands with explanations.

### Phase 1: Environment Preparation

Navigate to the lab directory:
```bash
cd ai-monitoring-lab
```
*Explanation*: The lab is fully isolated in `ai-monitoring-lab` so it will never conflict with other projects.

Create your local environment file:
```bash
cp .env.example .env
```
*Explanation*: Copies default passwords, master keys, and port allocations into an active `.env` file read by Docker Compose.

---

### Phase 2: Docker Container Orchestration

Build and start all 6 services in detached mode:
```bash
docker compose up -d --build
```
*Explanation*: Builds the lightweight Python `mock-ai` image and starts PostgreSQL, Keycloak, LiteLLM, Elasticsearch, and Kibana in parallel.

Verify container status:
```bash
docker compose ps
```
*Expected Output*: All 6 containers should report `Up` or `Up (healthy)`.

Inspect gateway logs to ensure proper initialization:
```bash
docker logs ai-sec-litellm-gateway --tail 30
```
*Explanation*: Confirms LiteLLM connected to PostgreSQL and registered the 3 AI models.

---

### Phase 3: Keycloak Identity & Token Issuance

Keycloak automatically imports `config/keycloak_realm.json` on startup.

#### 1. Retrieve an Access Token for Alice (Dev Role)
```bash
curl -s -X POST "http://localhost:8080/realms/ai-sec-realm/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=litellm-proxy" \
  -d "client_secret=litellm-client-secret-xyz987" \
  -d "username=alice.dev" \
  -d "password=DevPassword123!" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4
```
*Explanation*: Uses OAuth2 Resource Owner Password Credentials (ROPC) grant to authenticate Alice with Keycloak and retrieve a signed JWT containing her role `role_dev` and department `Engineering`.

#### 2. Retrieve an Access Token for Carol (HR Role)
```bash
curl -s -X POST "http://localhost:8080/realms/ai-sec-realm/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=litellm-proxy" \
  -d "client_secret=litellm-client-secret-xyz987" \
  -d "username=carol.hr" \
  -d "password=HRPassword123!" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4
```

---

### Phase 4: Gateway Inference & RBAC Enforcement

#### 1. Test Authorized Access: Alice (Dev) calls `dev-code-llm`
```bash
curl -s -X POST "http://localhost:4000/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-lab-master-key-admin-supersecret-9999" \
  -d '{
    "model": "dev-code-llm",
    "messages": [{"role": "user", "content": "Write a secure hash function in Python"}],
    "user": "alice.dev"
  }'
```
*Expected Output*: HTTP 200 with generated Python code response and token counts.

#### 2. Test RBAC Violation: Carol (HR) attempts to call `dev-code-llm`
```bash
curl -i -X POST "http://localhost:4000/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-lab-master-key-admin-supersecret-9999" \
  -d '{
    "model": "dev-code-llm",
    "messages": [{"role": "user", "content": "Generate shell exploit script"}],
    "user": "carol.hr"
  }'
```
*Expected Result*: Gateway policy or simulation engine flags Carol's unauthorized attempt, logging a `403 Forbidden` / RBAC violation security alert.

---

### Phase 5: SIEM Ingestion & Attack Simulation

#### 1. Install Elasticsearch Index Template
```bash
curl -s -X PUT "http://localhost:9200/_index_template/ai_audit_logs_template" \
  -H "Content-Type: application/json" \
  -d @"config/elastic/index_template.json"
```
*Explanation*: Defines field mappings (`user.email`, `ai.prompt_text`, `security.is_alert`) adhering to Elastic Common Schema.

#### 2. Run the Full Traffic & Attack Simulation
```bash
python3 scripts/simulate_traffic.py
```
*Explanation*: Generates benign departmental queries and executes all 8 adversarial attack vectors:
1. PII Injection (Credit Card & SSN)
2. Bulk Data Exfiltration (4,800 token prompt)
3. RBAC Model Violation (HR accessing Dev Code model)
4. Shadow AI Web Proxy Activity (`chatgpt.com` bypass)
5. Direct Prompt Injection & Jailbreak (DAN mode)
6. Secret Leakage (AWS Access Key & RSA private key)
7. Off-Hours Access (02:41 AM activity)
8. Reconnaissance Probing (Malformed JSON & rapid 400 errors)

#### 3. Verify Events in Elasticsearch
Check the total document count:
```bash
curl -s "http://localhost:9200/ai-audit-logs/_count"
```
*Explanation*: Should return `{"count": 14, ...}` (6 benign + 8 attacks).

Query security alerts only:
```bash
curl -s -X POST "http://localhost:9200/ai-audit-logs/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": { "term": { "security.is_alert": true } },
    "_source": ["@timestamp", "user.name", "security.rule_name", "security.severity", "security.owasp_category"]
  }'
```

---

### Phase 6: Kibana Dashboard Import

1. Open your browser and navigate to **`http://localhost:5601`**.
2. Go to **Management** > **Stack Management** > **Saved Objects**.
3. Click **Import** in the top right corner.
4. Select `ai-monitoring-lab/dashboards/kibana_dashboard.ndjson`.
5. Check **Automatically overwrite all saved objects** and click **Import**.
6. Navigate to **Analytics** > **Dashboard** and select **`[SOC] AI Security & Governance Monitoring Dashboard`**.

You will see:
- Real-time token consumption KPIs.
- Interactive pie chart of requests per department.
- Threat breakdown categorized by **OWASP Top 10 for LLMs**.
- Adversarial tactics mapped to **MITRE ATLAS**.

---

### Phase 7: Optional Microsoft Sentinel Cloud Integration

If you have an **Azure Free Trial** subscription:
1. Create a **Log Analytics Workspace** in the Azure Portal.
2. Enable **Microsoft Sentinel** on the workspace.
3. Create a **Data Collection Endpoint (DCE)** and a **Data Collection Rule (DCR)** with custom table `AIGatewayAudit_CL`.
4. Register an App in Microsoft Entra ID (Azure AD), generate a client secret, and grant the app `Monitoring Metrics Publisher` role on the DCR.
5. In `ai-monitoring-lab/.env`, set:
   ```env
   AZURE_TENANT_ID=your-azure-tenant-id
   AZURE_CLIENT_ID=your-app-client-id
   AZURE_CLIENT_SECRET=your-app-client-secret
   AZURE_LOG_INGESTION_ENDPOINT=https://your-dce.ingest.monitor.azure.com
   AZURE_DCR_RULE_ID=dcr-your-rule-id
   ```
6. Run the forwarder:
   ```bash
   python3 scripts/sentinel_forwarder.py
   ```
7. Open Microsoft Sentinel > **Workbooks** > **Add workbook** > **Advanced Editor** and paste the JSON from `dashboards/sentinel_workbook.json` to deploy your cloud dashboard!

---

## 3. SOC Alert Triage Playbooks

When an alert triggers, follow these step-by-step Standard Operating Procedures (SOPs):

### Playbook 1: Personal Data (PII) in Prompts
* **Alert Trigger**: `PII_IN_PROMPT` (Severity: High)
* **Triage**:
  1. Identify `user.email` and `network.client_ip`.
  2. Inspect `ai.prompt_text` snippet in SIEM to identify data type (Credit Card, SSN, NHS number).
  3. Determine if the user is an authorized processor (e.g. HR processing applicant) or an accidental paste.
* **Containment**:
  1. Purge the prompt text from gateway cache/logs if required under GDPR Article 17 (Right to Erasure).
  2. Notify user's line manager of data handling violation.
* **Remediation**:
  1. Direct employee to mandatory Information Governance & Acceptable Use Training.

### Playbook 2: Bulk Data Exfiltration Burst
* **Alert Trigger**: `BULK_DATA_EXFILTRATION` (Severity: High)
* **Triage**:
  1. Check `ai.tokens.prompt` (>4,000 tokens).
  2. Review user's historical 30-day baseline token usage.
  3. Inspect if raw database tables, financial ledgers, or source repositories were pasted.
* **Containment**:
  1. Temporarily suspend the user's Keycloak virtual API token via admin console (`ai-sec-realm`).
  2. Isolate host endpoint via EDR if exfiltration was performed via automated bot/script.
* **Remediation**:
  1. Require user justification before re-enabling AI Gateway access.

### Playbook 3: Unauthorized Model Access (RBAC Violation)
* **Alert Trigger**: `RBAC_MODEL_VIOLATION` (Severity: Medium)
* **Triage**:
  1. Check HTTP status code (`403 Forbidden`).
  2. Confirm user department (`carol.hr` attempting to call `dev-code-llm`).
* **Containment**:
  1. Verify the Gateway properly blocked model inference (status 403 ensures zero data was returned).
* **Remediation**:
  1. If user legitimate business need changed, request an IT Access Request ticket to update Keycloak role group.

### Playbook 4: Shadow AI Access via Proxy Logs
* **Alert Trigger**: `SHADOW_AI_PROXY_ACCESS` (Severity: Medium)
* **Triage**:
  1. Identify source workstation IP and corporate username browsing to `chatgpt.com` or `claude.ai`.
* **Containment**:
  1. Update Secure Web Gateway (SWG) / DNS filter (e.g., Cisco Umbrella / Cloudflare Gateway) to redirect requests to internal LiteLLM gateway portal.
* **Remediation**:
  1. Provide employee with approved internal gateway credentials so they do not feel the need to use consumer AI.

### Playbook 5: Prompt Injection & Jailbreak Attempts
* **Alert Trigger**: `PROMPT_INJECTION` (Severity: Critical)
* **Triage**:
  1. Analyze payload: Is it a DAN ("Do Anything Now") prompt, system prompt extractor, or indirect delimiter injection?
  2. Determine if the caller is an internal developer running security benchmarks or an external adversary probing an integrated AI app.
* **Containment**:
  1. If external or unauthenticated, block the source IP on the edge WAF.
  2. If internal user, escalate to SOC Tier 2 for insider threat investigation.
* **Remediation**:
  1. Enhance pre-prompt input guardrails in LiteLLM config.

### Playbook 6: Credential & API Secret Leakage
* **Alert Trigger**: `SECRET_LEAKAGE` (Severity: Critical)
* **Triage**:
  1. Identify secret type: AWS Access Key (`AKIA...`), GitHub Personal Access Token (`ghp_...`), or RSA Private Key.
* **Containment**:
  1. **IMMEDIATE ACTION**: Treat the credential as compromised. Revoke the key immediately in AWS IAM or GitHub Developer Settings!
  2. Audit cloud provider CloudTrail / audit logs for unauthorized actions using the leaked key ID.
* **Remediation**:
  1. Rotate credential and issue new secret to the developer via HashiCorp Vault.

### Playbook 7: Off-Hours AI Inference Spike
* **Alert Trigger**: `OFF_HOURS_ACCESS` (Severity: Medium)
* **Triage**:
  1. Verify if user is in a different timezone, on approved night call, or if the account shows impossible travel.
* **Containment**:
  1. Trigger Entra ID / Keycloak password reset and revoke active refresh tokens if account takeover is suspected.

### Playbook 8: Reconnaissance Probing & Error Spike
* **Alert Trigger**: `RECONNAISSANCE_PROBING` (Severity: Medium)
* **Triage**:
  1. Inspect error code cluster (rapid 400 Bad Request, 401 Unauthorized, 429 Rate Limit).
  2. Review client IP and user agent strings for known fuzzing tools (ffuf, Burp Suite, Postman collections).
* **Containment**:
  1. Apply IP-level rate limiting at the reverse proxy.

---

## 4. Operational Troubleshooting Guide

### Issue 1: Port Conflict (Port 5432 or 8080 already in use)
* **Cause**: Local PostgreSQL or another service running on your host machine.
* **Fix**: Edit `.env` and change host port:
  ```env
  POSTGRES_PORT=5433
  KEYCLOAK_PORT=8085
  ```
  Then restart with `docker compose up -d`.

### Issue 2: Elasticsearch JVM Out of Memory
* **Cause**: Default Docker Desktop memory setting is too low.
* **Fix**: Ensure Docker Desktop has at least 4 GB RAM assigned in settings. Adjust `.env`:
  ```env
  ES_JAVA_OPTS=-Xms256m -Xmx512m
  ```

### Issue 3: LiteLLM says "Database Connection Failed"
* **Cause**: PostgreSQL container not finished initializing before LiteLLM started.
* **Fix**: Run:
  ```bash
  docker restart ai-sec-litellm-gateway
  ```

---

## 5. Cybersecurity Interview Talking Points & Technical FAQ

Use these battle-tested questions and answers when interviewing for SOC Analyst, Detection Engineer, or AI Security roles:

#### Q1: "Why did you build an AI Usage Monitoring Lab?"
> **Answer**: *"With enterprise adoption of LLMs exploding, AI represents an unmonitored shadow IT risk and data exfiltration channel. Organizations are exposing source code, customer PII, and financial forecasts without governance. Coming from a Support Analyst background and pursuing my MSc in Cybersecurity, I wanted to engineer a production-grade solution. I deployed LiteLLM as a reverse proxy gateway integrated with Keycloak for RBAC, centralized logging into Elasticsearch and Microsoft Sentinel, authored 8 detection rules mapped to OWASP LLM and MITRE ATLAS, and created real-time SOC triage playbooks."*

#### Q2: "Why put an AI Gateway in front of models rather than monitoring endpoints via EDR?"
> **Answer**: *"Endpoint Detection and Response (EDR) agents monitor processes and kernel syscalls on local laptops, but they lack deep semantic visibility into encrypted HTTPS payloads sent to cloud APIs. An AI Gateway acts as a sanctioned reverse proxy. It terminates TLS, evaluates prompt tokens, enforces team-level budgets, validates OIDC identity claims, redacts secrets before they reach the model, and generates structured, schema-compliant audit logs for the SIEM."*

#### Q3: "How does detecting Prompt Injection differ from traditional SQL Injection?"
> **Answer**: *"SQL Injection has a deterministic grammar; you can parameterize queries to strictly separate code from data. Large Language Models operate on natural language where code and data share the same semantic context window. A prompt injection attack like DAN or indirect system instruction overrides looks like valid English prose. Detection therefore requires a defense-in-depth approach: heuristic regex matching on known jailbreak markers, semantic guardrails, output sanitization, and SIEM correlation looking for sudden anomalous behavior."*

#### Q4: "How do you handle data privacy when storing user prompts in a SIEM?"
> **Answer**: *"Storing raw prompts containing confidential employee text inside a SIEM could violate GDPR Article 5(1)(c) data minimization. In enterprise production, the gateway should implement client-side DLP to hash or tokenize sensitive entities before indexing, or truncate prompts to a fixed character snippet (e.g. 150 chars). In our lab, prompts are tagged with classification metadata and encrypted at rest with role-restricted access within Kibana/Sentinel."*

#### Q5: "How does your Support Analyst background make you a better SOC Analyst?"
> **Answer**: *"Support Analysts and SOC Analysts share the same core DNA: rapid triage, root-cause investigation under pressure, systematic log analysis, and communicating complex technical risks to stakeholders. In support, I learned how to isolate complex system failures and follow runbooks. In cybersecurity, I apply that exact same methodology to identify adversarial indicators of compromise (IoCs), contain threats quickly, and tune detections to prevent alert fatigue."*
