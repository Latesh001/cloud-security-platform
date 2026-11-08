# Cloud Security Platform — Complete Working Process

**Project title:** Cloud Security Monitoring and Automated Incident Response using AI

This document describes **how the application works from end to end**: what the user does, what the system does next, which modules fire, and **which machine-learning models are actually used**. It matches the running code in this repository (Phase 1, Phase 2, Phase 3, and Advanced Features).

Related files: [ARCHITECTURE.md](./ARCHITECTURE.md) (design), [TECH_STACK.md](./TECH_STACK.md) (libraries).

---

## 1. How to start the system

Three processes must be running:

| Process | Address | Role |
|---|---|---|
| MongoDB | `127.0.0.1:27017` database `cloud_security_db` | All application data |
| Flask API | `http://127.0.0.1:5000` | REST APIs, scans, monitoring, incidents |
| React UI (Vite) | `http://127.0.0.1:5173` | Screens the user clicks |

Typical local start:

```powershell
# MongoDB Windows service
net start MongoDB

# Optional: train Phase 2 models once (creates files under trained_models/)
cd CloudSecurityPlatform\backend
python ai\train_model.py

# Backend
python app.py

# Frontend (second terminal)
cd CloudSecurityPlatform\frontend
npm run dev
```

Or use `CloudSecurityPlatform\scripts\start-platform.ps1`.

The browser talks to `/api/...` on port 5173. Vite **proxies** those calls to Flask on port 5000. Every protected API requires a JWT (`Authorization: Bearer <token>`).

---

## 2. End-to-end story (one sentence)

A developer **registers with email**, **signs in with that email**, **uploads a project ZIP (up to 1000 MB)**, **Phase 1 scans and scores it**, **Phase 2 monitors approved projects with ML**, **high-confidence threats become Phase 3 incidents**, and **Advanced Features** (unified dashboard, phase engine, forensics, compliance, Gemini assistant) sit on top of the same Project ID without replacing Phase 1–3 pages. SIEM, SOAR, Assets, Vulnerabilities, and Threat Intel screens are not shown.

```
Register (name, email, location, role) → welcome email
      ↓
Login (registered email only) → Dashboard
      ↓
Create project + upload ZIP (≤ 1000 MB)
      ↓
Phase 1: five detectors (parallel) → score 0–100 → Approve or Pending Remediation
      ↓  (score ≥ 65 AND residual criticals within Gate A)
Phase 2: simulated cloud events every few seconds → Isolation Forest + Random Forest
      ↓  (confidence ≥ 85%)
Phase 3: incident + simulated playbook + evidence + timeline + PDF
         (stays In Progress until the analyst closes it)
      ↓
Advanced: unified dashboard, phase engine, forensics, compliance, Gemini chat
```

---

## 3. Authentication (start of every session)

**Screens:** Register, Login. (Forgot/verify/reset routes still exist for old links; they are not used in the live flow.)

**Working process**

1. User registers with **user name, email address, location, and role**. There is no phone registration and no password field.
2. The account is **verified immediately**. A **welcome email** is sent to that address over Gmail SMTP (`MAIL_USERNAME` / app password in `backend/.env`).
3. Login is **email only**: enter the registered address and click Login. The API looks up the user, issues a **JWT**, and the UI opens the **dashboard**. Identity inside the token is `user_id`. Lifetime comes from `SESSION_TIMEOUT_MINUTES` (default 60).
4. The React app stores `token` and `user` in `localStorage` and attaches the token on every API call.
5. Unauthenticated visitors hitting private routes are sent to `/login`.
6. Role (Developer, Security Analyst, Incident Responder, Student, Researcher, Project Manager) is shown in the sidebar; Advanced Features uses the same login.

Phase 1, 2, 3, and Advanced Features **all require this login**. Nothing in those modules runs as an anonymous user.

---

## 4. Phase 1 — Secure project upload and AI security analysis

**Menu:** Home → Phase 1 (Projects).  
**Pages:** Projects list, Create project, Project detail, Security report.

This phase is **static assessment of source code**. It does **not** use Isolation Forest or Random Forest. Findings come from **rule-based detectors**. Scoring is a weighted formula, not a neural network.

### 4.1 What the user does

1. Click **Create project**, enter name and category (for example Banking, Hospital, E-Commerce).
2. Upload a `.zip` of the application (maximum **1000 MB**).
3. Wait for the scan (the proxy waits up to 30 minutes). Open the project to see score, findings, recommendation, and PDF.

### 4.2 What the system does (pipeline)

```
ZIP file
  → ZipValidator (reject encrypted ZIP, zip bombs, Zip Slip, huge files, dangerous executables)
  → Safe extract under uploads/<project_id>/
  → Technology detection (language, framework, manifests)
  → Five independent detectors
  → Deduplicate findings
  → Scoring engine (0–100)
  → Decision engine (Approved vs Pending Remediation)
  → Recommendation text + PDF under INCIDENT_REPORTS_FOLDER
  → If Approved: status becomes Monitoring Enabled (Phase 2 may start)
  → Advanced Features hook stores the same Project ID, score, vulns, and risk
```

### 4.3 The five detectors (rule-based, not ML)

| Detector | Looks at | Typical findings |
|---|---|---|
| Secret scanner | Source, `.env`, IaC | API keys, tokens, hardcoded passwords |
| Static code analysis | `.py .js .ts .java .php .cs .rb .go` | SQL injection, XSS, command injection, weak hashing |
| Configuration | Env, YAML/JSON, settings | Debug mode, default passwords, open CORS |
| Infrastructure | Terraform, CloudFormation, Docker, Kubernetes | `0.0.0.0/0`, public buckets, privileged containers |
| Dependencies | `requirements.txt`, `package.json`, `pom.xml`, … | Known-vulnerable library versions |

### 4.4 Scoring and the 65 gate

- Each finding has a severity: Critical, High, Medium, Low.
- Project **category** can raise severity (a bank is treated more strictly than a hobby app).
- Weighted counts become a **security score from 0 to 100**.
- **Approved** only if:
  - score ≥ `APPROVAL_SCORE_THRESHOLD` (default **65**), **and**
  - **zero** unresolved Critical findings.
- Otherwise status is **Pending Remediation**. Phase 2 monitoring is **blocked**.

This gate is the same idea used in Advanced Features Phase Engine (`deployment_blocked` when score &lt; 65).

### 4.5 What is stored

- Project document (name, category, score, status).
- Security report (counts, recommendation, PDF path).
- Scan log in MongoDB (`scan_logs`).
- Advanced copy: `phase1_analysis` + workflow status for the same **Project ID**.

---

## 5. Phase 2 — Cloud security monitoring

**Menu:** Phase 2 (Monitoring).  
**Page:** Monitoring / SOC live view.

Only **Approved** projects with monitoring enabled are watched. Events are **simulated CloudTrail-style logs** (no real AWS account is required). Containment later in Phase 3 is also simulated.

### 5.1 What the user does

1. After Phase 1 approval, start monitoring from the project or Monitoring page.
2. Watch live logs, threat list, and confidence scores. The UI polls about every 5 seconds.

### 5.2 What the system does (pipeline)

```
Scheduler (every MONITORING_INTERVAL_SECONDS, default 5 seconds)
  → Event generator creates one simulated cloud event
      (login, failed login, IAM change, data transfer, API call, …)
  → Preprocessor normalises the event and builds 10 numeric features
  → ThreatDetector.predict()
      Isolation Forest  → anomaly yes/no
      Random Forest     → probability / confidence %
      (or rule fallback if model files are missing)
  → Threat class + severity (Brute Force, Credential Theft, Exfiltration, …)
  → If confidence ≥ THREAT_CONFIDENCE_THRESHOLD (default 85)
        → open Phase 3 incident
  → Else keep as observation / threat summary only
  → Advanced hook writes raw_logs, normalized_logs, optional threat_alerts
```

### 5.3 Feature vector (same order at train time and run time)

| # | Feature | Meaning |
|---|---|---|
| 1 | `loginHour` | Hour of the event (0–23) |
| 2 | `eventTypeEncoded` | Encoded CloudTrail-style event name |
| 3 | `failedLogin` | 1 if login failed |
| 4 | `iamChange` | 1 if IAM/policy changed |
| 5 | `dataTransfer` | 1 if data movement |
| 6 | `mfaEnabled` | 1 if MFA present |
| 7 | `isSuspicious` | Generator/rule suspicious flag |
| 8 | `gigabytesTransferred` | Bytes / 1e9 |
| 9 | `highRiskCountry` | 1 if country in a high-risk set |
| 10 | `requestFailed` | 1 if status is Failure |

### 5.4 How a detection becomes an incident

- **isAnomaly** = model (or rules) think the event is malicious.
- **confidence** = Random Forest probability × 100 (or Isolation Forest margin / rule score).
- **isThreat / forward to Phase 3** = malicious **and** confidence ≥ **85**.

Low-confidence anomalies stay on the Monitoring page so the SOC is not flooded.

---

## 6. Phase 3 — Automated incident response

**Menu:** Phase 3 (Incidents).  
**Pages:** Incidents list, Incident detail.

### 6.1 What the user does

1. Open Incidents when Phase 2 has escalated a detection.
2. Read threat, severity, confidence, affected user, source IP, playbook result, evidence, timeline.
3. Optionally re-run the playbook (Open cases) or **close** the incident. Cases stay **In Progress** after the automatic playbook until Close is used.
4. Download the **incident PDF** (saved only under the Incident reports folder).
5. The Incidents list **Response Success** card is the share of playbook actions that returned a successful simulated result (for the current project lifetime).

### 6.2 What the system does (pipeline)

```
High-confidence Phase 2 prediction
  → Incident manager creates incident (project status → Incident Detected)
  → Rule engine maps threat type → playbook
        Brute Force        → lock / notify
        Malware            → isolate
        Suspicious IP      → block IP (simulated)
        Credential theft   → disable user (simulated)
        Any incident       → email-style notification record
  → Playbook executor runs simulated containment (does NOT change a real cloud account)
  → Evidence collector writes forensic documents
  → Timeline builder orders events
  → Notification + PDF report (Incident reports folder)
  → Incident remains In Progress until Close
  → Advanced hook: workflow status Incident
```

Closing the incident sets **Closed**, `resolved_time`, and workflow status toward **Resolved** in Advanced Features.

---

## 7. Main dashboard (Home)

**Menu:** Home / Dashboard.

This is the signed-in landing page (not the Advanced unified dashboard). It aggregates **current-project lifetime** data only (records at or after each project’s `created_date`, so leftover rows on reused IDs such as P001 do not inflate the cards):

- Project counts and average security score (latest scan of assessed projects; unscanned 0 defaults are ignored)
- Approved / pending / failed / incident statuses  
- Phase 1 finding severities  
- Phase 2 **validated** threat types (aligned with Monitoring `total_threats`)  
- Phase 3 incident severities  
- Pipeline chart (Phase 1 → 2 → 3)  
- Ops widgets: **Phase Gate**, **Analyst Queue**, **Detection Confidence**  
- Recent activity and notifications  

Charts are Chart.js. Data comes from `/api/dashboard` plus `/api/projects` where needed.

---

## 8. AI Security Assistant (floating chat + Advanced assistant)

Two UIs, **one backend**:

- Floating chatbot on every logged-in page (`/api/chatbot/ask`).
- Advanced Features → AI Assistant (`/api/advanced/chat`).

### Working process

1. User types **any** question (this product, a scan, a CVE, programming, general knowledge).
2. Optional **Project ID** grounds answers in that user’s latest scan, threats, and incidents.
3. **Google Gemini** is called first (`GEMINI_API_KEY`, current Flash-Lite models such as `gemini-3.5-flash-lite`).
4. If Gemini fails, optional **OpenAI** is tried.
5. If no LLM answers, a **local knowledge base** is used (predefined security/product topics only).
6. Q&A is stored in `chat_history` / `advanced_chat`.

Gemini is a **remote LLM**, not a model trained inside this repo. It is not Isolation Forest or Random Forest.

---

## 9. Advanced Features (remaining modules)

These sit under **Advanced Features** after login. They **do not replace** Phase 1–3 pages. They reuse the same **Project ID**.

**Live Advanced screens:** Unified Dashboard, Phase Integration Engine, AI Assistant, Compliance, Digital Forensics.

SIEM, SOAR, Assets, Vulnerabilities, and Threat Intel **pages are not shown**. Those routes redirect to the Advanced hub. Phase 3 playbooks remain the response path on the Incidents pages.

### 9.1 Unified Security Dashboard

**Path:** `/advanced/dashboard`

Shows live widgets from MongoDB + Phase 1–3: uploaded projects, average score, findings, alerts, critical incidents, automated responses, compliance %. Charts: severity pie, **horizontal risk bars**, score history. Executive PDF download (Incident reports folder).

### 9.2 Phase Integration Engine

**Path:** `/advanced/integration`

Table of every project with score, workflow status, whether Phase 2 is enabled, whether deploy is blocked (score &lt; 65), and latest incident. Click a row for the eight-step workflow, SHAP/LIME-style explanation of a related event, and AI incident summary.

Statuses used: Pending, Scanning, Passed, Failed, Monitoring, Incident, Resolved.

### 9.3 Compliance Manager

**Path:** `/advanced/compliance`

Scores live Phase 1–3 evidence against **ISO 27001, NIST CSF, CIS Controls, GDPR, HIPAA**. Shows passed/failed controls, percentage, recommendations, and a downloadable PDF. This is **rule mapping**, not an ML classifier.

### 9.4 Digital Forensics

**Path:** `/advanced/forensics`

1. Upload a file or paste text.
2. Click **Generate SHA256 + MD5**.
3. Card **below the form**: SHA256, MD5, size, project, and **chain of custody** (first event: evidence received and hashed / Sealed).
4. Add custody steps, download the **custody `.txt` file**, or download **Forensic PDF**.

Hashes are **SHA-256 and MD5 cryptographic hashes**, not machine-learning models.

---

## 10. Machine learning models used in this application

### 10.1 Models that are trained and used for security detections

These are the **only ML models that score live cloud events**.

| Model | Type | Library | When it runs | Output |
|---|---|---|---|---|
| **Isolation Forest** | Unsupervised anomaly detection | scikit-learn `IsolationForest` | Phase 2 every simulated event | Outlier (−1) vs inlier (+1). Catches unusual behaviour even if that attack was never labelled. |
| **Random Forest Classifier** | Supervised binary classifier | scikit-learn `RandomForestClassifier` | Phase 2 every simulated event | Probability the event is malicious → **confidence %**. |
| **StandardScaler** | Feature scaling (not a predictor) | scikit-learn `StandardScaler` | Before both models | Same scale as training. Required so inference matches training. |

**Training (offline only)** — `backend/ai/train_model.py`:

- Builds ~8000 synthetic cloud events (~15% attacks).
- Fits **StandardScaler** on the training split.
- Fits **Isolation Forest** on **benign traffic only** (`n_estimators=200`, `contamination=0.15`).
- Fits **Random Forest** on labelled events (`n_estimators=200`, `max_depth=12`, balanced class weight).
- Saves artifacts with Joblib. **Nothing is retrained while the web app is running.**

**Saved files** (`trained_models/`):

| File | Contents |
|---|---|
| `threat_detector.joblib` | Isolation Forest |
| `threat_classifier.joblib` | Random Forest |
| `feature_scaler.joblib` | StandardScaler |
| `model_metadata.json` | Training metrics and settings |

**Combined inference name** (shown as `modelUsed`): `RandomForest + IsolationForest`.

If those files are missing, Phase 2 uses a **transparent weighted rule set** so monitoring still works.

**Escalation:** Random Forest probability (and/or Isolation Forest anomaly) must reach **≥ 85% confidence** before Phase 3 opens an incident.

### 10.2 Explainability (not separate trained models)

On Phase Engine, **SHAP-style** and **LIME-style** viewers explain a cloud event:

- SHAP-style: uses Random Forest **feature_importances_** × scaled feature values (no `shap` package).
- LIME-style: perturbs one feature at a time and re-runs `ThreatDetector.predict` (no `lime` package).

They **explain** the Phase 2 Random Forest / Isolation Forest; they are not extra trained models.

### 10.3 Other “AI” that is not Isolation Forest / Random Forest

| Capability | What it actually is |
|---|---|
| Phase 1 “AI security analysis” | Rule-based detectors + scoring formula |
| Phase 3 playbooks | Rule map from threat type → simulated action |
| Compliance scoring | Control-to-evidence rules |
| Risk / severity helpers in Advanced | Heuristics plus the same Phase 2 `ThreatDetector` for severity |
| Incident summarization | Template text from incident + Phase 1 counts |
| Google Gemini | External LLM for the chatbot (any question) |
| OpenAI (optional) | External LLM fallback |
| Knowledge base | Curated Q&A if no LLM is available |
| SHA256 / MD5 | Cryptographic hashes in Forensics |
| XGBoost (listed in requirements) | Present in the Python toolchain; **live training and inference in this app use Isolation Forest + Random Forest, not XGBoost** |

---

## 11. How the same Project ID ties everything together

| Step | Uses Project ID for |
|---|---|
| Phase 1 scan | Store score, findings, report |
| Phase 2 monitoring | Generate events and predictions for that project |
| Phase 3 incident | Link incident to project, user, IP, threat |
| Advanced dashboard | Average score, charts, timeline |
| Phase Engine | Deploy gate and workflow steps |
| Forensics | Optional tag on evidence |
| Compliance | Control pass/fail from that project’s scan and incidents |
| Chatbot | Ground answers in that project’s data |

---

## 12. What is simulated vs real

| Real | Simulated (by design) |
|---|---|
| ZIP upload and Phase 1 code scan | AWS CloudTrail / live cloud APIs |
| MongoDB storage, JWT login, PDFs | Blocking a real IP or disabling a real IAM user |
| Isolation Forest + Random Forest on generated events | Production cloud containment |
| Gemini answers (if API key is set) | |

Playbook **Execute** always records a **simulated** success. It does not change a real cloud account.

---

## 13. Quick map: screen → working action

| User clicks | What runs |
|---|---|
| Register | Email account + welcome SMTP mail |
| Login | Email lookup + JWT → dashboard |
| Create project + upload ZIP | Phase 1 detectors + score + PDF |
| Start monitoring | Phase 2 scheduler + Isolation Forest + Random Forest |
| Open Incidents | Phase 3 incident, playbook, evidence, timeline |
| Advanced Unified Dashboard | Aggregated metrics and charts |
| Phase Engine row | Workflow + SHAP/LIME-style explanation |
| Assistant Send | Gemini (then OpenAI / knowledge base) |
| Compliance download | PDF of framework scores |
| Forensics Generate SHA256 + MD5 | Hash card + chain of custody below the form |

That is the complete working process of the application as implemented.
