# Cloud Security Monitoring and Automated Incident Response using AI

An end-to-end security platform that takes a developer's project from source code
to production monitoring to automated incident response, with AI at every stage.
Everything runs locally on Windows, macOS, or Linux — no Docker, no cloud account,
no paid services required.

```
  Phase 1                     Phase 2                        Phase 3
  ─────────────────────       ─────────────────────────      ──────────────────────────
  Upload project ZIP          Collect cloud events           Validated threat arrives
  Validate + extract          Normalize and enrich           Verify and open incident
  5 static detectors          Feature engineering            Select response playbook
  Risk scoring engine         Isolation Forest (anomaly)     Execute containment
  AI recommendations          Random Forest (confidence)     Collect forensic evidence
  Approve or remediate  ───►  Correlate and classify   ───►  Build timeline + report
                              Escalate high confidence       Notify and close
```

A project must **pass Phase 1** before Phase 2 will monitor it, and Phase 2 only
escalates detections above the configured confidence threshold into Phase 3
incidents. That gating is what makes the three phases one system rather than three
demos.

---

## Table of Contents

1. [Feature Overview](#feature-overview)
2. [Technology Stack](#technology-stack)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Running the Platform](#running-the-platform)
6. [Using the Platform](#using-the-platform)
7. [Configuration Reference](#configuration-reference)
8. [Project Structure](#project-structure)
9. [API Reference](#api-reference)
10. [How the AI Works](#how-the-ai-works)
11. [Security Controls](#security-controls)
12. [Verification and Tests](#verification-and-tests)
13. [Troubleshooting](#troubleshooting)

---

## Feature Overview

### Authentication and Accounts
- Registration with email verification and phone registration (password login, no OTP)
- JWT-based login with optional multi-factor authentication
- Forgot password with a signed, expiring reset link
- Profile management and password change
- bcrypt password hashing and full audit logging

### Phase 1 — AI-Based Security Assessment
Determines whether a project is safe enough to monitor at runtime.

- Safe ZIP upload: rejects encrypted archives, zip bombs, path traversal
  (Zip Slip) entries, and forbidden script/executable files (such as `.bat`, `.cmd`, `.exe`, `.sh`, `.vbs`, `.ps1`, `.msi`, `.dll`).
  If any forbidden file extension is detected (e.g. `start.bat`), the upload is rejected with an explicit error message
  asking the user to remove those files before uploading.
- Automatic technology detection (language, framework, dependencies)
- **Five independent detectors**, each with its own file filters and rule set:

  | Detector | Looks at | Finds |
  |---|---|---|
  | Secret Detection | source, config, `.env`, IaC | AWS keys, private keys, API tokens, hardcoded database credentials |
  | Code Analysis | `.py .js .ts .java .php .cs .rb .go` | SQL injection, XSS, command injection, insecure deserialization, weak crypto |
  | Configuration | `.env`, `settings.py`, `appsettings.json`, `application.yml` | debug mode, weak secrets, default passwords, permissive CORS, disabled TLS verification |
  | Infrastructure | Terraform, CloudFormation, Dockerfile, Kubernetes | `0.0.0.0/0` ingress, public S3 buckets, public databases, privileged containers, IAM wildcards |
  | Dependency Analysis | `requirements.txt`, `package.json`, `pom.xml`, `composer.json`, `build.gradle` | known-vulnerable versions matched against a curated CVE advisory table |

- Category-aware severity escalation: a hardcoded password in a *Banking System*
  is scored more harshly than the same finding in a hobby project
- Weighted risk scoring, 0–100, with an explicit approval decision
- AI recommendation engine producing prioritised remediation guidance
- Downloadable PDF report and a printable in-app report view
- Rescan and re-upload with full scan history and score trend

### Phase 2 — Cloud Security Monitoring and Threat Detection
Runs continuously for every approved, monitoring-enabled project.

- Cloud event generator simulating AWS CloudTrail-style activity
- Log normalization and feature engineering
- Hybrid AI detection: Isolation Forest for anomalies + Random Forest for
  calibrated confidence, with a transparent rule-based fallback
- Threat classification (brute force, credential stuffing, privilege escalation,
  data exfiltration, impossible travel, and more) with severity assignment
- Correlation engine that groups related events into a single narrative
- Live dashboard: severity distribution, threat categories, source countries,
  active users, event stream
- Only detections at or above `THREAT_CONFIDENCE_THRESHOLD` become incidents

### Phase 3 — Automated Incident Response and Digital Forensics
- Incident manager that opens, tracks, and closes incidents
- Rule engine mapping each threat category to a response playbook
- Simulated containment actions (disable user, revoke keys, block IP, isolate
  resource, enforce MFA) with per-action status
- Forensic evidence collection preserved in MongoDB
- Automatic incident timeline reconstruction
- PDF incident report generation
- In-app and email notification at every state change

### AI Security Assistant
A context-aware chatbot available on every page, with four modes:

| Tab | Answers questions about |
|---|---|
| **Project** | architecture, modules, data flow, why a design choice was made |
| **Security** | your actual findings, what a vulnerability means, how to fix it |
| **SOC** | threats detected, incidents, playbooks, analyst workflow |
| **Viva** | model answers for project review and defence questions |

It reads your real data — your projects, your scores, your findings, your
incidents — and grounds every answer in it. With `OPENAI_API_KEY` set it uses an
LLM for fluency; without one it answers from the curated knowledge base. Either
way it never invents facts about your project.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite 5, Tailwind CSS 3, React Router 6, Chart.js, Framer Motion, Formik + Yup, Axios |
| Backend | Python 3.12+, Flask 3, Flask-JWT-Extended, Flask-Mail, Flask-CORS |
| Database | MongoDB — users, projects, reports, incidents, notifications, cloud logs, forensics, timelines |
| AI / ML | scikit-learn (Isolation Forest, Random Forest), NumPy, Pandas, Joblib |
| Reporting | ReportLab |

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.12 or newer | `python --version` |
| Node.js | 18 LTS or newer | `node --version` |
| MongoDB Community | 6 or newer | **Required database.** (`mongodb://localhost:27017`) |
| Git | any | optional |

---

## Quick start (recommended on Windows)

This path checks and launches the **MongoDB service**, writes `backend/.env` configured for `mongodb://localhost:27017/cloud_security_db`, and opens the backend + frontend in two windows.

```powershell
cd CloudSecurityPlatform

# Start the full platform
.\scripts\start-platform.ps1
```

Then open **http://localhost:5173**.

| Script | Purpose |
|---|---|
| `scripts\start-platform.ps1` | Verifies MongoDB + launches Flask backend and Vite frontend |

Default local database connection:

```
URI:      mongodb://localhost:27017/cloud_security_db
Database: cloud_security_db
```

`backend/.env` is automatically configured to point to this MongoDB database.

---

## Installation

### 1. Start MongoDB

MongoDB is the primary database storing users, projects, reports, incidents, notifications, cloud logs, and forensic evidence.

```powershell
net start MongoDB
```

MongoDB stores logs, findings, and forensic evidence. If the service is not
running, the backend logs a warning and continues — relational features keep
working, but the event stream and findings list will be empty.

```powershell
net start MongoDB
```

### 3. Backend setup

```powershell
cd CloudSecurityPlatform\backend

python -m venv venv
.\venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt

Copy-Item .env.example .env
```

Open `.env` and set at minimum:

```ini
SECRET_KEY=<any long random string>
JWT_SECRET_KEY=<a different long random string>
DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/cloud_security_db
MONGO_URI=mongodb://localhost:27017/cloud_security_mongo
```

> **Email is optional.** Leave `MAIL_USERNAME` blank and accounts are
> auto-verified so you can sign in immediately. Phone registration is also
> activated immediately (no OTP / Twilio).

### 4. Train the AI models

```powershell
python ai\train_model.py
```

This generates a synthetic dataset, trains both models, prints accuracy /
precision / recall / F1 / ROC-AUC plus a feature importance ranking, and writes
the artifacts to `trained_models/`. Without this step Phase 2 falls back to the
rule-based detector, which still works but is less accurate.

### 5. Frontend setup

```powershell
cd ..\frontend
npm install
```

---

## Running the Platform

**Easiest:** `.\scripts\start-platform.ps1` (starts Postgres, checks MongoDB, opens both apps).

**Manual — two terminals, both left running.**

**Terminal 1 — backend**

```powershell
cd CloudSecurityPlatform
.\scripts\start-postgres.ps1
cd backend
python app.py
```

Serving on `http://localhost:5000`. Confirm with `http://localhost:5000/api/health`,
which reports the live status of both databases.

**Terminal 2 — frontend**

```powershell
cd CloudSecurityPlatform\frontend
npm run dev
```

Open **http://localhost:5173**.

---

## Using the Platform

1. **Register** — provide name, email, phone, and a strong password. Verify via
   the emailed link, or copy the link from the backend console.
2. **Log in** with your email/phone and password.
3. **Create a project** — name it, pick a category (this drives severity
   escalation), and upload a ZIP of your source code.
4. **Review the assessment** — the scan runs immediately. Inspect the security
   score, findings grouped by detector, and AI recommendations. Download the PDF.
5. **Remediate and rescan** — fix findings, re-upload, and watch the score trend
   climb. A project is approved at or above the threshold with no criticals.
6. **Start monitoring** — available once approved. The backend begins generating
   and analysing cloud events for that project.
7. **Watch the SOC dashboard** — threats appear live with severity, category, and
   AI confidence.
8. **Handle incidents** — high-confidence threats become incidents automatically.
   Open one to see the timeline, the executed playbook actions, and the collected
   forensic evidence. Download the incident report, then close it.
9. **Ask the assistant** — the chat button on the bottom right answers questions
   about any of the above using your actual data.

---

## Configuration Reference

All values live in `backend/.env`. Every one has a working default.

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | dev value | Flask session signing. **Change this.** |
| `JWT_SECRET_KEY` | dev value | JWT signing. **Change this.** |
| `DATABASE_URL` | localhost postgres | PostgreSQL connection string |
| `MONGO_URI` | localhost mongo | MongoDB connection string |
| `SESSION_TIMEOUT_MINUTES` | `60` | JWT lifetime |
| `SESSION_TIMEOUT_MINUTES` | `60` | JWT / session lifetime |
| `MAX_UPLOAD_SIZE_MB` | `700` | Largest accepted project archive (MB) |
| `APPROVAL_SCORE_THRESHOLD` | `65` | Minimum Phase 1 score to reach Phase 2 |
| `THREAT_CONFIDENCE_THRESHOLD` | `85` | Minimum AI confidence to open an incident |
| `MONITORING_INTERVAL_SECONDS` | `5` | Seconds between simulated cloud events |
| `OPENAI_API_KEY` | empty | Enables LLM-backed chatbot answers |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model used when the key is set |
| `MAIL_USERNAME` | empty | Blank auto-verifies accounts locally |
| `FRONTEND_URL` | `http://localhost:5173` | Used for CORS and email links |

Tuning tips for a demo: lower `MONITORING_INTERVAL_SECONDS` to `2` for a busier
event stream, and lower `THREAT_CONFIDENCE_THRESHOLD` to `70` to see incidents
open sooner.

---

## Project Structure

```
CloudSecurityPlatform/
├── backend/
│   ├── app.py                       Application factory, blueprints, error handlers
│   ├── requirements.txt
│   ├── .env.example
│   ├── config/settings.py           All configuration in one place
│   ├── database/
│   │   ├── extensions.py            SQLAlchemy, Mail, JWT, fault-tolerant Mongo helpers
│   │   └── models.py                User, Project, SecurityReport, Incident, Notification
│   ├── authentication/              Registration, login, password reset, profile
│   ├── projects/                    Project CRUD and upload handling
│   ├── notifications/               Notification service and routes
│   ├── dashboard/                   Aggregated cross-phase statistics
│   ├── phase1/
│   │   ├── upload/validator.py      ZIP validation and safe extraction
│   │   ├── extractor/               Technology and framework detection
│   │   ├── detectors/
│   │   │   ├── base.py              Shared file walking, severity escalation, dedupe
│   │   │   ├── secrets/             Credential and key detection
│   │   │   ├── code/                Language-specific insecure pattern rules
│   │   │   ├── configs/             Insecure application configuration
│   │   │   ├── infrastructure/      Terraform, CloudFormation, Docker, Kubernetes
│   │   │   └── dependencies/        CVE advisory matching
│   │   ├── scoring/engine.py        Weighted score and approval decision
│   │   ├── recommendations/         AI remediation guidance
│   │   ├── reports/                 PDF generation
│   │   └── api/routes.py
│   ├── phase2/
│   │   ├── collectors/              Cloud event generator
│   │   ├── preprocess/              Log normalization and feature engineering
│   │   ├── ai/threat_detector.py    Isolation Forest + Random Forest inference
│   │   ├── correlation/             Multi-event attack correlation
│   │   ├── scheduler/               Background monitoring loop
│   │   └── api/routes.py
│   ├── phase3/
│   │   ├── incident_manager/        Incident lifecycle
│   │   ├── rule_engine/             Threat to playbook mapping
│   │   ├── playbooks/               Simulated containment actions
│   │   ├── evidence/                Forensic evidence collection
│   │   ├── timeline/                Incident timeline reconstruction
│   │   ├── reports/                 Incident PDF reports
│   │   └── api/routes.py
│   ├── ai/
│   │   ├── train_model.py           Offline model training with full metrics
│   │   ├── chatbot/                 AI Security Assistant service and routes
│   │   └── knowledge_base/          Curated security and project knowledge
│   └── utils/                       Logging, helpers, security utilities
│
├── frontend/
│   ├── package.json
│   └── src/
│       ├── App.jsx                  Routes and route guards
│       ├── main.jsx
│       ├── index.css                Tailwind layer and shared component classes
│       ├── context/AuthContext.jsx  Session state
│       ├── layouts/Layout.jsx       Sidebar, header, unread badge, chatbot mount
│       ├── services/api.js          Axios instance, JWT interceptor, file download
│       ├── components/
│       │   ├── ui.jsx               Badges, loaders, stat cards, score ring, alerts
│       │   ├── Markdown.jsx         Safe minimal Markdown renderer
│       │   └── Chatbot.jsx          AI Security Assistant
│       └── pages/                   Auth, Dashboard, Projects, Monitoring,
│                                    Incidents, Notifications, Profile
│
├── uploads/          Uploaded and extracted projects  (generated)
├── reports/          Generated PDF reports            (generated)
├── trained_models/   Trained ML artifacts             (generated)
├── datasets/         Training data                    (generated)
└── logs/             Application and audit logs       (generated)
```

---

## API Reference

All endpoints are prefixed with `http://localhost:5000/api`.
Protected routes require `Authorization: Bearer <token>`.

### Authentication
| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/auth/register` | Create an account |
| POST | `/auth/login` | Authenticate and return a JWT |
| POST | `/auth/verify-email` | Confirm an email address using the token |
| POST | `/auth/resend-verification` | Re-issue a verification email |
| POST | `/auth/forgot-password` | Request a reset link |
| POST | `/auth/reset-password` | Set a new password using the token |
| GET | `/auth/me` | Current user profile |
| PUT | `/auth/profile` | Update profile fields |
| POST | `/auth/change-password` | Change password while signed in |

### Projects
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/projects/categories` | Available project categories |
| POST | `/projects/create` | Create a project |
| GET | `/projects` | List the current user's projects |
| GET | `/projects/<id>` | Project details |
| POST | `/projects/upload/<id>` | Upload the project ZIP (triggers the Phase 1 scan) |

### Phase 1
| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/phase1/scan/<id>` | Run the security assessment |
| POST | `/phase1/rescan/<id>` | Re-run the assessment on the current upload |
| GET | `/phase1/result/<id>` | Report, findings, detector summary, scan history |
| GET | `/phase1/report/<id>` | Download the PDF report |

### Phase 2
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/monitoring/projects` | Projects eligible for or currently under monitoring |
| POST | `/monitoring/start/<id>` | Enable monitoring for an approved project |
| POST | `/monitoring/stop/<id>` | Disable monitoring |
| GET | `/monitoring/status/<id>` | Monitoring state for a project |
| GET | `/monitoring/logs` `/monitoring/logs/<id>` | Recent normalized cloud events |
| GET | `/monitoring/threats` `/monitoring/threats/<id>` | Detected threats with AI confidence |
| GET | `/monitoring/dashboard` | Aggregated monitoring statistics |

### Phase 3
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/incidents` | List incidents |
| GET | `/incidents/<id>` | Incident with timeline, actions, and evidence |
| POST | `/incidents/respond/<id>` | Re-run the response playbook |
| POST | `/incidents/close/<id>` | Close an incident |
| GET | `/incidents/timeline/<id>` | Incident timeline only |
| GET | `/incidents/report/<id>` | Download the incident PDF |

### Assistant, Notifications, Dashboard
| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/chatbot/ask` | Ask a question in a given tab and project context |
| GET | `/chatbot/suggestions` | Starter questions for a tab |
| GET | `/chatbot/history` | Conversation history |
| DELETE | `/chatbot/history` | Clear conversation history |
| GET | `/notifications` | List notifications (`?unread=true` to filter) |
| POST | `/notifications/<id>/read` | Mark one as read |
| POST | `/notifications/read-all` | Mark all as read |
| DELETE | `/notifications/<id>` | Delete a notification |
| GET | `/dashboard` | Cross-phase dashboard data |
| GET | `/health` | Service and database health |

---

## How the AI Works

### Phase 1 — hybrid rule-based and AI scoring

Pure machine learning on source code needs a large labelled corpus that a local
project cannot supply, so Phase 1 uses a deterministic detection layer with an
AI reasoning layer on top:

1. **Rule-based detection** — regex rules per language and file type produce
   findings with a base severity. Deterministic, explainable, and reproducible.
2. **Category-aware escalation** — the project category raises the severity of
   the findings that matter most for that domain.
3. **Weighted scoring** — Critical, High, Medium, and Low findings carry
   different weights; the result is normalized to 0–100.
4. **Decision engine** — a project is *Approved* at or above the threshold with
   no unresolved critical findings, otherwise *Pending Remediation*.
5. **AI recommendation engine** — ranks the findings by exploitability and
   business impact and writes prioritised, actionable remediation guidance.

### Phase 2 — supervised and unsupervised ensemble

Ten features are extracted per event: login hour, encoded event type, failed
login flag, IAM change flag, data transfer flag, MFA state, suspicious flag,
bytes transferred, high-risk country flag, and failure status.

- **Isolation Forest** is fit only on benign traffic, so it learns the shape of
  normal behaviour and flags outliers. It catches attack patterns that were never
  labelled, which is exactly what a signature-based system misses.
- **Random Forest** is trained on labelled events and outputs the probability
  that an event is malicious. That probability becomes the reported confidence.
- Both consume the **same StandardScaler** that was fit during training. Applying
  a different transformation at inference time is the single most common way an
  ML pipeline silently breaks.
- An event is malicious if the classifier says so *or* the anomaly detector flags
  it. It becomes a Phase 3 incident only if confidence clears the threshold.
- If no trained model is present, a transparent weighted rule set takes over, so
  the platform works on a fresh checkout.

`python ai/train_model.py` prints accuracy, precision, recall, F1, ROC-AUC,
a 5-fold cross-validated F1, the confusion matrix, and feature importances, and
saves them to `trained_models/model_metadata.json`.

### The Assistant

Every question is answered against a context built from the signed-in user's own
data: their projects, the selected project's report and findings, recent threats,
and open incidents. That context is combined with a curated knowledge base of
vulnerability definitions, cloud security concepts, SOC practices, and project
architecture notes. When an OpenAI key is configured the same context is sent to
the LLM with instructions never to contradict it; if that call fails the
knowledge base answers instead. There is no path where the assistant guesses at
your project's state.

---

## Security Controls

The platform accepts untrusted archives from users, so it is built to defend
itself as seriously as it assesses others.

**Upload and extraction**
- Archive size, entry count, and total uncompressed size are capped
- Compression ratio checked to reject zip bombs
- Password-protected archives rejected
- Every file extension is accepted and extracted; Phase 1 detectors scan the
  full tree and always return a security score
- Dependency trees (`.venv`, `node_modules`, `site-packages`, …) are skipped
  to keep scans focused on project source
- Every entry path resolved and confirmed to land inside the extraction root,
  which blocks Zip Slip; `extractall` is deliberately not used
- Previous extractions are cleared before a rescan so results are never stale

**Authentication and session**
- bcrypt password hashing with per-user salt
- Enforced password complexity
- JWT with configurable expiry

**Application**
- Input validation on every endpoint
- SQLAlchemy ORM parameterisation throughout, so no string-built SQL
- CORS restricted to the configured frontend origin
- Ownership checks on every project, report, and incident route
- Request size limit enforced by Werkzeug before the view runs
- Audit logging of authentication, scanning, and response events
- Graceful degradation: MongoDB going down disables document features rather
  than crashing the platform

---

## Verification and Tests

Two self-contained scripts prove the security-critical paths actually work.
Neither needs a database or a running server.

### Detector accuracy

```powershell
cd backend
python tests\test_detectors.py
```

Builds a deliberately vulnerable project in a temporary directory — hardcoded
AWS keys, SQL injection, `pickle.loads`, `innerHTML`, a `0.0.0.0/0` security
group, a public S3 bucket, a wildcard IAM policy, a root Dockerfile, and
outdated dependencies — then asserts that each detector reports what it owns.

It also includes a **clean control file** using `os.environ` lookups and
placeholder values. If any detector flags that file, the run fails. A scanner
that cries wolf is worse than no scanner, so false positives are treated as
hard failures. Finally it confirms the scoring engine refuses to approve the
sample and that every finding carries a remediation step and a reference.

Current result: 28 findings across 5 detectors, 0 false positives.

### Upload hardening

```powershell
python tests\test_upload_security.py
```

Builds genuinely malicious archives and asserts each is refused: a Zip Slip
entry (`../../../pwned.txt`), an absolute path (`/etc/passwd`), a decompression
bomb, an empty archive, and a file that is not a ZIP at all. Zip Slip is checked
twice — once at validation and once at extraction — so the extractor is proven
to confine entries even if validation were bypassed.

It also proves the non-blocking paths: an archive containing `payload.exe` and
`phishing/start.bat` is accepted and every file is extracted for scanning.
Legitimate deeply nested archives and archives carrying a `.venv` must still
extract their source intact.

Current result: 14 of 14 checks pass.

### Model quality

```powershell
python ai\train_model.py
```

Reports accuracy, precision, recall, F1, ROC-AUC, 5-fold cross-validated F1, the
confusion matrix, and feature importances.

Representative run: **97.4% accuracy, 89.1% precision, 93.6% recall, 0.994
ROC-AUC**, with a 5-fold cross-validated F1 of 89.4%.

Those numbers are deliberately not perfect. The data generator gives every
simulated attack a *stealth* factor, so patient low-and-slow intrusions suppress
their tell-tale signals while some legitimate activity — night deployments, a
mistyped password, a large authorised backup — looks alarming. A model that
scores 100% on synthetic security data has learned a label leak, not a threat.

### Backend smoke check

```powershell
python -c "from app import app; print(len(list(app.url_map.iter_rules())), 'routes')"
```

Confirms every blueprint imports and registers. PostgreSQL and MongoDB warnings
here are expected and non-fatal if those services are not running.

---

## Troubleshooting

**`connection to server at "localhost", port 5432 failed`**
PostgreSQL is not running or `DATABASE_URL` is wrong. Start the service
(`net start postgresql-x64-16`) and confirm the password in `.env`.

**`MongoDB unavailable ... Document features are disabled`**
Informational, not fatal. Start MongoDB with `net start MongoDB` to enable the
event stream, findings list, and forensic evidence.

**`ModuleNotFoundError: No module named 'flask_mail'`**
The virtual environment is not active or dependencies are missing.
Run `.\venv\Scripts\Activate.ps1` then `pip install -r requirements.txt`.

**No verification email arrives**
Expected when `MAIL_USERNAME` is blank — accounts are auto-verified for local demo.
For real email, use a Gmail **App Password**, not your account password.

**`npm install` hangs or fails with `UNABLE_TO_VERIFY_LEAF_SIGNATURE`**
Your network inspects TLS traffic (campus firewall, corporate proxy, or antivirus
HTTPS scanning). Windows trusts the interception certificate, but Node ships its
own CA list and does not. Export the Windows root store and point Node at it —
this keeps certificate verification fully enabled:

```powershell
$out = "$env:USERPROFILE\windows-ca-bundle.pem"
$sb = New-Object System.Text.StringBuilder
foreach ($store in @("Cert:\LocalMachine\Root","Cert:\CurrentUser\Root")) {
  Get-ChildItem $store | ForEach-Object {
    [void]$sb.AppendLine("-----BEGIN CERTIFICATE-----")
    [void]$sb.AppendLine([Convert]::ToBase64String($_.RawData,'InsertLineBreaks'))
    [void]$sb.AppendLine("-----END CERTIFICATE-----")
  }
}
Set-Content -Path $out -Value $sb.ToString() -Encoding ascii

setx NODE_EXTRA_CA_CERTS $out
$env:NODE_EXTRA_CA_CERTS = $out
npm install
```

`setx` makes it permanent for new terminals; the `$env:` line applies it to the
current one. Verify with `npm ping`, which should answer `PONG`.

Do **not** reach for `npm config set strict-ssl false`. It disables certificate
verification for every future install on the machine, which is exactly the class
of misconfiguration this platform is built to detect.

**Frontend shows "Backend Unreachable"**
The backend is not running on port 5000, or `FRONTEND_URL` in `.env` does not
match the address the browser is using.

**Phase 2 reports `modelUsed: RuleBased`**
The trained models are missing. Run `python ai/train_model.py`.

**Monitoring produces no events**
Monitoring only runs for projects that passed Phase 1 and have monitoring
enabled. Check the project status, then wait `MONITORING_INTERVAL_SECONDS`.

**Upload rejected as a zip bomb**
The archive expands far beyond its compressed size. Remove `node_modules`,
`venv`, and build output before zipping; they are skipped by the scanner anyway.

**Port 5000 or 5173 already in use**
Stop the other process, or change the port in `app.py` / `vite.config.js` and
update `FRONTEND_URL` to match.
