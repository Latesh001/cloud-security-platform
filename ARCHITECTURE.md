# Cloud Security Platform — Architecture

**Project title:** Cloud Security Monitoring and Automated Incident Response using AI

This file describes how the application is designed: layers, modules, the three-phase pipeline, data flow, and security controls. For the list of libraries and versions, see [TECH_STACK.md](./TECH_STACK.md).

---
## 1. Purpose of the Design

The platform takes a developer project from **source-code assessment** to **runtime monitoring** to **automated incident response**. The three phases are not independent demos. They are gated:

1. A project must pass **Phase 1** (security score and no unresolved critical findings) before it can be monitored.
2. **Phase 2** only escalates detections at or above the configured confidence threshold.
3. **Phase 3** opens an incident, runs a playbook, collects evidence, and builds a timeline.

Everything is designed to run **locally** (Windows, macOS, or Linux). No Docker, cloud account, or paid service is required for the core product. An optional OpenAI key improves chatbot fluency; without it the assistant answers from a curated knowledge base.

---

## 2. High-Level Architecture

The system is a **three-tier web application** with a background monitoring loop and offline-trained ML models.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Presentation tier                                │
│  React SPA                                                               │
│  http://localhost:5173                                                   │
│  Pages: Auth, Dashboard, Projects, Monitoring, Incidents, Profile,       │
│         Advanced (dashboard, integration, assistant, compliance,         │
│         forensics)                                                       │
│  HTTP client → /api  (dev proxy to Flask)                                │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │ HTTP + JWT
┌─────────────────────────────────▼────────────────────────────────────────┐
│                         Application tier                                 │
│  Flask API  ·  http://localhost:5000                                     │
│                                                                          │
│  Blueprints                                                              │
│  ┌────────────┐ ┌──────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │ Auth       │ │ Projects │ │ Phase 1 │ │ Phase 2 │ │ Phase 3 │       │
│  │ Dashboard  │ │ Notify   │ │ Scan    │ │ Monitor │ │ IR      │       │
│  │ Chatbot    │ │          │ │ Score   │ │ Detect  │ │ Forensics│      │
│  └────────────┘ └──────────┘ └─────────┘ └─────────┘ └─────────┘       │
│                                                                          │
│  Background scheduler → Phase 2 event generation + AI inference          │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
┌───────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ MongoDB       │       │ File store      │       │ Trained models  │
│ localhost:    │       │ uploads/        │       │ trained_models/ │
│ 27017         │       │ Incident reports│       │ anomaly +       │
│ cloud_        │       │ (PDF archive)   │       │ classifier +    │
│ security_db   │       │ logs/ datasets/ │       │ scaler          │
└───────────────┘       └─────────────────┘       └─────────────────┘
```

### Design principles

| Principle | How it is applied |
|---|---|
| Layered separation | UI never talks to MongoDB. All data goes through Flask REST APIs. |
| Phase gating | Phase 2 cannot start until Phase 1 approval. Phase 3 cannot start until Phase 2 confidence clears the threshold. |
| Explainable AI | Phase 1 is rule-based and auditable. Phase 2 uses ML with a transparent rule fallback. |
| Local-first | MongoDB on localhost; simulated CloudTrail events; Gmail SMTP welcome mail; optional LLM. |
| Defence in depth | ZIP validation, email-only identity + JWT, CORS allow-list, ownership checks, audit logs. |
| Graceful degradation | Missing ML models → rule detector. SMTP failure is logged; the account still signs in. Mongo down → health reports degraded. |

---

## 3. Application Architecture (Backend)

Flask is organised as an **application factory** plus **blueprints**. Each blueprint owns one domain.

```
backend/
├── app.py                      Factory, CORS, JWT, error handlers, /api/health
├── config/settings.py          All env-driven configuration
├── database/
│   ├── extensions.py           Mongo client, indexes, helpers
│   └── models.py               Document models + query layer
├── authentication/             Email register, email login, welcome mail, profile
├── projects/                   CRUD + ZIP upload
├── dashboard/                  Cross-phase analytics
├── notifications/              In-app + email notifications
├── phase1/                     Static assessment pipeline
├── phase2/                     Monitoring + threat detection
├── phase3/                     Incident response + forensics
├── ai/
│   ├── train_model.py          Offline model training
│   ├── chatbot/                Context-aware assistant
│   └── knowledge_base/         Curated Q&A content
├── utils/                      Logging, helpers, security utilities
└── tests/                      Detector, upload, auth, Mongo tests
```

### 3.1 Blueprints and URL prefixes

| Blueprint | Prefix | Responsibility |
|---|---|---|
| `auth_bp` | `/api/auth` | Email register, email login, JWT, profile |
| `advanced_bp` | `/api/advanced` | Overlay dashboard, integration, assistant, compliance, forensics |
| `projects_bp` | `/api/projects` | Project lifecycle and upload |
| `phase1_bp` | `/api/phase1` | Scan, rescan, report, PDF |
| `monitor_bp` | `/api/monitoring` | Start/stop, logs, threats, SOC dashboard |
| `incidents_bp` | `/api/incidents` | Open/respond/close, timeline, PDF |
| `dashboard_bp` | `/api/dashboard` | Aggregated Phase 1–3 analytics |
| `notifications_bp` | `/api/notifications` | List, read, delete |
| `chatbot_bp` | `/api/chatbot` | Ask, suggestions, history |

### 3.2 Request path

```
Browser
  → Dev server (:5173)  proxy /api → Flask (:5000)
  → JWT interceptor attaches Authorization: Bearer <token>
  → Blueprint route + @jwt_required
  → Model / detector / scheduler
  → MongoDB or filesystem
  → JSON (or PDF blob)
```

---

## 4. Frontend Architecture

### 4.1 Structure

```
frontend/src/
├── main.jsx                 React root
├── App.jsx                  Routes, lazy loading, guards
├── index.css                Shared styles
├── context/AuthContext.jsx  Session: token, user, login/logout
├── layouts/Layout.jsx       Sidebar, header, unread badge, chatbot
├── services/api.js          HTTP client + download helper
├── components/              UI primitives, Markdown, Chatbot
└── pages/                   One page per route
```

### 4.2 Routing model

- **Public routes:** login (registered email only) and register (user name, email, location, role). Forgot/reset/verify paths remain in the router for older links but are not part of the live sign-in flow.
- **Private routes:** wrapped in `Layout` + `PrivateRoute`. Unauthenticated users are sent to `/login`.
- **Lazy loading:** login is eager; chart-heavy pages load on demand so the first paint stays small.

### 4.3 Client state

| Concern | Mechanism |
|---|---|
| Auth session | `AuthContext` + `localStorage` (`token`, `user`) |
| Server data | Per-page fetch through the API client |
| Monitoring live view | 5-second poll of logs, threats, and dashboard |
| Chat | Floating assistant on every authenticated page |

The dev-server proxy avoids CORS during development: the browser calls `/api/...` on port 5173, and the request is forwarded to `http://127.0.0.1:5000`.

---

## 5. Data Architecture

MongoDB is the **single source of truth** for users, projects, scans, events, incidents, and chat.

### 5.1 Collections

| Collection | Model | Purpose |
|---|---|---|
| `users` | `User` | Accounts (email identity, name, location, role) |
| `projects` | `Project` | Name, category, score, status, monitoring flag |
| `security_reports` | `SecurityReport` | Phase 1 counts, score, recommendation, PDF path |
| `project_monitoring` | `ProjectMonitoring` | Enabled flag, log/threat counters |
| `threat_summary` | `ThreatSummary` | Phase 2 classified threats |
| `cloud_logs` | documents | Normalised simulated cloud events |
| `incidents` | `Incident` | Phase 3 cases |
| `responses` | `Response` | Playbook actions executed |
| `incident_evidence` / `forensic_logs` | documents | Preserved evidence |
| `timeline_history` | documents | Reconstructed incident timeline |
| `notifications` | `Notification` | In-app alerts |
| `chat_history` | `ChatHistory` | Assistant Q&A |
| `email_verifications` / `otp_records` | tokens | Verification and reset |
| `counters` | sequences | Auto-increment IDs |
| `scan_logs` / `ai_inference` | documents | Audit of scans and model calls |

### 5.2 Access layer

`BaseMongoModel` provides `.query.filter_by()`, `.save()`, `.delete()`, and integer/string-tolerant `user_id` matching. Indexes are created on connect for `email`, `user_id`, `project_id`, `incident_id`, `report_id`, `notification_id`, and verification tokens. Phone is no longer used for registration or login.

### 5.3 Filesystem (not in MongoDB)

| Folder | Contents |
|---|---|
| `uploads/<project_id>/` | Original ZIP + extracted tree |
| `INCIDENT_REPORTS_FOLDER` (default `D:\mainproject papers\Documents\Incident reports`) | All downloadable PDFs (Phase 1, Phase 3, forensics, compliance, executive) |
| `trained_models/` | Saved ML artifacts + metadata |
| `datasets/` | Synthetic training data |
| `logs/` | Application and audit logs |

---

## 6. Phase Design (the core product architecture)

```
                    ┌─────────────┐
   ZIP / GitHub ───►│   Phase 1   │  Static assessment
                    │  Detectors  │
                    │  Score 0–100│
                    └──────┬──────┘
                           │ score ≥ threshold
                           │ AND 0 criticals
                    ┌──────▼──────┐
                    │   Phase 2   │  Runtime monitoring
                    │  Events + ML│
                    └──────┬──────┘
                           │ confidence ≥ threshold
                    ┌──────▼──────┐
                    │   Phase 3   │  Incident response
                    │  Playbooks  │
                    │  Forensics  │
                    └─────────────┘
```

### 6.1 Phase 1 — AI-based security assessment

**Goal:** Decide whether a project is safe enough to monitor.

**Pipeline**

1. **Upload hardening** — `ZipValidator` rejects encrypted archives, zip bombs, Zip Slip, oversize files, and forbidden executables/scripts.
2. **Safe extract** — `ZipExtractor` resolves every path inside the extract root (no `extractall`).
3. **Technology detection** — language, framework, dependency manifests.
4. **Five detectors** (independent, then de-duplicated):

   | Detector | Input | Finds |
   |---|---|---|
   | Secret scanner | source, `.env`, IaC | keys, tokens, hardcoded credentials |
   | Static code analysis | `.py .js .ts .java .php .cs .rb .go` | SQLi, XSS, command injection, weak crypto |
   | Configuration | env, settings, YAML/JSON | debug mode, default passwords, open CORS |
   | Infrastructure | Terraform, CloudFormation, Docker, K8s | `0.0.0.0/0`, public buckets, privileged containers |
   | Dependencies | `requirements.txt`, `package.json`, `pom.xml`, … | known-vulnerable versions |

5. **Scoring engine** — weighted Critical / High / Medium / Low → score 0–100. Category (e.g. Banking vs hobby) escalates severity.
6. **Decision engine** — Approved if score ≥ `APPROVAL_SCORE_THRESHOLD` (default 65) and critical count is 0; otherwise Pending Remediation.
7. **Recommendation engine** — prioritised remediation text.
8. **PDF report** — written only to `INCIDENT_REPORTS_FOLDER` (never under a developer home folder). Detectors run in a small thread pool; MongoDB stores the first 800 findings so large trees stay responsive. ZIP cap is `MAX_UPLOAD_SIZE_MB` (default **1000**). The Vite proxy allows a 30-minute scan.

On approval the project status becomes **Monitoring Enabled** and Phase 2 may start.

### 6.2 Phase 2 — Cloud monitoring and threat detection

**Goal:** Continuously watch approved projects.

**Pipeline**

1. **Event generator** — AWS CloudTrail-style simulated events (login, IAM change, data transfer, …).
2. **Normalisation + features** — ten numeric features: login hour, encoded event type, failed login, IAM change, data transfer, MFA, suspicious flag, GB transferred, high-risk country, request failed.
3. **Hybrid detector**
   - Unsupervised anomaly model — trained only on benign traffic; flags outliers.
   - Supervised classifier — probability that the event is malicious (confidence).
   - Same scaler used at train and infer time.
   - If models are missing → weighted rule fallback.
4. **Classification** — brute force, credential theft, privilege escalation, exfiltration, impossible travel, and others.
5. **Correlation engine** — groups related events into one narrative.
6. **Escalation gate** — only confidence ≥ `THREAT_CONFIDENCE_THRESHOLD` (default 85) becomes a Phase 3 incident.

The scheduler interval is `MONITORING_INTERVAL_SECONDS` (default 5). The SOC page polls the API every 5 seconds.

### 6.3 Phase 3 — Automated incident response and forensics

**Goal:** Contain, record, and close a validated threat.

**Pipeline**

1. **Incident manager** — opens an incident; project status → `Incident Detected`.
2. **Rule engine** — maps threat category → playbook.
3. **Playbook executor** (simulated containment): disable user, revoke keys, block IP, isolate resource, enforce MFA.
4. **Evidence collector** — forensic documents in MongoDB.
5. **Timeline builder** — ordered reconstruction of the incident.
6. **PDF incident report** (same PDF archive folder) + in-app notification (email if SMTP is up).
7. Incident stays **In Progress** until an analyst **closes** it. Response Success on the Incidents page is the share of playbook actions with a successful simulated result, not the closed-case ratio.

---

## 7. Cross-Cutting Modules

### 7.1 Authentication

```
Register (user name, email, location, role)
  → account auto-verified
  → Gmail SMTP welcome message to that email
  → Login with the same email only (no password, no phone)
  → JWT (identity = user_id, lifetime = SESSION_TIMEOUT_MINUTES)
  → Dashboard
  → Authorization: Bearer <token> on every protected route
```

Profile can update name, location, and role. Email is the sign-in identity and is not changed from the profile form.

### 7.2 AI Security Assistant

Mounted on every authenticated page. Four tabs: **Project**, **Security**, **SOC**, **Viva**.

Each answer is grounded in the signed-in user’s real projects, findings, threats, and incidents plus a curated knowledge base. With an API key an LLM is used for wording; on failure or if no key is set, the knowledge base answers. The assistant is instructed not to invent project facts.

### 7.3 Notifications and audit

- In-app notifications on create, scan, monitor, and incident state changes.
- SMTP (Gmail) sends the registration welcome mail; other alerts email when SMTP is up.
- Audit logger records authentication, scans, and response actions under `logs/`.

### 7.4 Dashboard lifetime filter

Project IDs are reused (`P001`, `P002`, …). Dashboard, Monitoring, and Incidents count only records whose timestamp is at or after the **current** project’s `created_date`. Average score uses the latest scan of projects that have actually been assessed. Threats are validated Phase 2 rows (or `ProjectMonitoring.total_threats`). Ops widgets: Phase Gate, Analyst Queue, Detection Confidence.

---

## 8. End-to-End Data Flow

```
Developer
   │  register (email) → welcome mail
   │  login (email only) → dashboard
   ▼
Create project  →  MongoDB projects (status: Created)
   │  upload ZIP
   ▼
Phase 1 scan
   │  detectors → score → decision → PDF
   ▼
Approved? ──no──► Pending Remediation (fix, re-upload, rescan)
   │ yes
   ▼
Phase 2 monitoring
   │  generate events → features → anomaly model + classifier
   ▼
Confidence ≥ threshold?
   │ yes
   ▼
Phase 3 incident
   │  playbook → evidence → timeline → notify → close
   ▼
Dashboard / Monitoring / Incidents UI  +  Chatbot
```

Typical project statuses: `Created` → `Uploaded` → `Scanning` → `Approved` / `Pending Remediation` → `Monitoring Enabled` → `Incident Detected` (or `Upload Failed`).

---

## 9. Security Architecture

The platform accepts untrusted ZIP archives, so it is built to protect itself as well as assess others.

| Control | Implementation |
|---|---|
| Archive safety | Size, entry count, compression ratio, encrypted ZIP rejection |
| Zip Slip | Every entry path resolved inside the extract root |
| Forbidden payloads | `.exe .bat .cmd .sh .vbs .ps1 .msi .dll` rejected at upload |
| Identity | Registered email issues a JWT; phone registration is removed |
| Sessions | JWT, configurable expiry, invalid/expired handlers |
| Transport (dev) | CORS limited to `FRONTEND_URL` and localhost:5173 |
| Authorization | Ownership check on project, report, and incident routes |
| Input | Sanitisation and schema validation |
| Uploads | Request size limit before the view runs |
| Audit | Auth, scan, and response events logged |
| ML safety | Models trained offline; inference-only at runtime |

---

## 10. Configuration (design knobs)

All live in `backend/.env` (`config/settings.py`).

| Variable | Default | Effect on architecture |
|---|---|---|
| `MONGO_URI` | `mongodb://127.0.0.1:27017/cloud_security_db` | Database |
| `FRONTEND_URL` | `http://localhost:5173` | CORS and email links |
| `SESSION_TIMEOUT_MINUTES` | 60 | JWT lifetime |
| `MAX_UPLOAD_SIZE_MB` | 1000 | Phase 1 upload cap |
| `APPROVAL_SCORE_THRESHOLD` | 65 | Phase 1 → Phase 2 gate |
| `THREAT_CONFIDENCE_THRESHOLD` | 85 | Phase 2 → Phase 3 gate |
| `MONITORING_INTERVAL_SECONDS` | 5 | Event generation cadence |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | empty / `gemini-3.5-flash-lite` | Preferred assistant LLM (Google Gemini) |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | empty / `gpt-4o-mini` | Fallback assistant LLM |
| `LLM_PROVIDER` | `auto` | `auto` = Gemini, then OpenAI, then knowledge base |
| `MAIL_*` | Gmail SMTP | Welcome email on register; other notifications when send_email is set |
| `INCIDENT_REPORTS_FOLDER` | `D:\mainproject papers\Documents\Incident reports` | Sole PDF archive |

---

## 11. Runtime Topology (local)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Frontend    │     │ Flask API   │     │ MongoDB     │
│ :5173       │────►│ :5000       │────►│ :27017      │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                    Scheduler thread
                    (Phase 2 loop)
```

**Start (Windows):**

```powershell
cd CloudSecurityPlatform
.\scripts\start-platform.ps1
```

Or two terminals: `python app.py` in `backend/` and `npm run dev` in `frontend/`. Flask starts with `use_reloader=False` and `threaded=True`, so backend file changes need a process restart. The Vite `/api` proxy timeout is 30 minutes so large ZIP scans can finish.

---

## 12. Architecture summary

The application is a **local three-tier SOC platform**:

- **UI** — SPA for developers and analysts.
- **API** — Flask factory with domain blueprints.
- **Data** — MongoDB plus on-disk uploads, PDFs, and trained models.
- **Intelligence** — five Phase 1 detectors, a Phase 2 ensemble, Phase 3 playbooks, and a context-aware assistant.

The design is **pipeline-shaped, not modular-demo-shaped**: Phase 1 approval unlocks Phase 2, and Phase 2 confidence unlocks Phase 3. That gating is the architectural spine of the system.

Related document: [TECH_STACK.md](./TECH_STACK.md)
