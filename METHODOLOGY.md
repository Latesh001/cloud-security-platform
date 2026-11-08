# Cloud Security Platform — Methodology

**Project title:** Cloud Security Monitoring and Automated Incident Response using AI

This document describes **the methodology of the project**: the problem it addresses, the method chosen, how each phase is designed and executed, which algorithms and models are used, how data moves through the system, and how the running application actually works. It matches the implementation in this repository.

Related documents:

- [ARCHITECTURE.md](./ARCHITECTURE.md) — layers, modules, and design
- [WORKING_PROCESS.md](./WORKING_PROCESS.md) — screen-by-screen user and system flow
- [TECH_STACK.md](./TECH_STACK.md) — libraries and versions
- [CONCLUSION.md](./CONCLUSION.md) — results, limitations, and final conclusion

---

## 1. Purpose of this methodology

The project is an **end-to-end local Security Operations (SOC) platform**. A developer’s source code is assessed, approved projects are watched at runtime with machine learning, and high-confidence threats become incidents with simulated containment, evidence, and reports.

The methodology answers four questions:

1. **What problem is being solved?** Fragmented tools (a scanner, a SIEM, a ticketing system) do not share one project identity or one approval gate.
2. **What method is used?** A **gated three-phase pipeline**, not three independent demos.
3. **How is intelligence applied?** Rules where source-code labels are scarce; trained ML where cloud events can be synthesised; an optional LLM only for assistant wording.
4. **How does the live system work?** Email register + welcome mail → email login → dashboard → ZIP scan → score gate → monitoring loop → confidence gate → incident playbook → Advanced Features on the same Project ID.

---

## 2. Problem statement and objectives

### 2.1 Problem

Cloud-native applications fail in three distinct ways that are usually handled by separate products:

| Failure mode | Typical tool | Gap if used alone |
|---|---|---|
| Insecure source, secrets, IaC, and dependencies | SAST / secret scanner | Does not watch the app after deploy |
| Abnormal runtime behaviour (brute force, exfiltration, IAM abuse) | SIEM / UEBA | Has no proof the codebase was ever assessed |
| Confirmed attack needing containment and evidence | SOAR / IR playbook | Has no shared Project ID or forensic hash trail |

Without a **gate**, a critical codebase can be “monitored” as if it were production-ready. Without a **confidence threshold**, every noisy anomaly becomes an incident. Without a **shared Project ID**, dashboards, forensics, and compliance cannot tell a single story.

### 2.2 Objectives

1. Accept an untrusted project ZIP, scan it safely, and produce an auditable **security score (0–100)**.
2. Allow **continuous monitoring only after** the Phase 1 decision is Approved.
3. Detect threats on **simulated CloudTrail-style events** using Isolation Forest + Random Forest (or a transparent rule fallback).
4. Open a Phase 3 incident only when **confidence ≥ threshold** (default 85%).
5. Execute **simulated** playbooks, collect evidence, build a timeline, and emit PDFs.
6. Layer Advanced Features (unified dashboard, phase engine, forensics, compliance, Gemini assistant) on the **same Project ID** without replacing Phase 1–3 screens. SIEM/SOAR/Assets screens are not part of the live UI.
7. Run **entirely locally** (Windows / macOS / Linux): MongoDB, Flask, React. No Docker or live AWS account is required for the core product.

---

## 3. Methodological approach

### 3.1 Overall method: gated pipeline

The system is designed as a **sequential pipeline with hard gates**, analogous to industrial change-control: assess → operate → respond.

```
Untrusted ZIP
      │
      ▼
Phase 1  Static assessment (rule-based detectors + scoring formula)
      │
      │  GATE A — Approved only if score ≥ 65 and residual criticals are limited
      ▼
Phase 2  Runtime monitoring (simulated events + Isolation Forest + Random Forest)
      │
      │  GATE B — Incident only if malicious AND confidence ≥ 85%
      ▼
Phase 3  Incident response (playbook map → simulated containment → evidence → PDF)
      │
      ▼
Advanced Features  Same Project ID: dashboard, phase engine, forensics, compliance, chat
```

This is **not** a microservice mesh and **not** three standalone prototypes. Phase 2 is blocked until Phase 1 approval. Phase 3 is blocked until Phase 2 confidence clears the threshold.

### 3.2 Hybrid intelligence method

| Layer | Method | Why this method |
|---|---|---|
| Phase 1 | **Rule-based static analysis** | Source-code vulns are pattern-detectable (keys, SQLi, open CIDR). There is no large labelled corpus of *this user’s* ZIP in the repo. |
| Phase 1 score | **Weighted penalty + exponential saturation** | Raw finding counts must become a 0–100 residual score that does not collapse every busy scan to zero. |
| Phase 2 | **Unsupervised + supervised ensemble** | Isolation Forest catches unseen outliers; Random Forest supplies a probability used as **confidence %**. |
| Phase 2 fallback | **Weighted rules** | Monitoring must still run if Joblib model files are missing. |
| Phase 3 | **Deterministic playbook map** | Containment must be explainable and repeatable; it is simulated, not live cloud mutation. |
| Assistant | **Gemini (optional) → OpenAI (optional) → knowledge base** | Wording and general Q&A; never used as the Phase 2 detector. |
| Forensics | **SHA-256 and MD5** | Integrity of evidence, not ML. |
| Compliance | **Control-to-evidence mapping** | ISO/NIST/CIS/GDPR/HIPAA scored from live Phase 1–3 facts. |

### 3.3 Development and runtime method

- **Local three-tier architecture:** React SPA (port 5173) → Flask REST API (port 5000) → MongoDB (port 27017).
- **Application factory + blueprints:** Auth, Projects, Phase 1, Phase 2, Phase 3, Dashboard, Notifications, Chatbot, Advanced.
- **Offline ML training:** `python ai/train_model.py` writes artifacts under `trained_models/`. The web app **never retrains** while serving requests.
- **Simulation where the cloud would be dangerous or unavailable:** CloudTrail events, IP block, IAM disable, resource isolate.
- **Graceful degradation:** missing models → rules; SMTP failure is logged and register still succeeds; missing Gemini → knowledge base; Mongo down → health reports degraded.
- **Flask runtime:** `use_reloader=False`, `threaded=True`. Backend edits need a restart. Vite `/api` proxy timeout is 30 minutes for large scans.

---

## 4. How the project works (end-to-end method)

This is the operational methodology of a single user session.

```
1. Register (user name, email, location, role) → welcome SMTP email
      Login with that email only → JWT → dashboard
      Every /api call sends Authorization: Bearer <token>
2. Create a project (name + category, e.g. Banking, Hospital)
3. Upload a ZIP of the application (≤ 1000 MB)
4. Phase 1 validates, extracts, detects (thread pool), scores, decides, writes PDF
5. If Approved → status Monitoring Enabled; user starts Phase 2
6. Scheduler emits a simulated cloud event every few seconds
7. Features → Isolation Forest + Random Forest (or rules)
8. If confidence ≥ 85% and malicious → Phase 3 incident
9. Playbook executes (simulation) → evidence → timeline → incident PDF
      Incident stays In Progress until the analyst closes it
10. Advanced pages read the same Project ID for charts, forensics, compliance
```

Typical project statuses:

`Created` → `Uploaded` → `Scanning` → `Approved` / `Pending Remediation` → `Monitoring Enabled` → `Incident Detected`

The **Project ID** is the spine: Phase 1 reports, Phase 2 events, Phase 3 incidents, forensic hashes, and compliance scores all attach to it. Reused IDs (P001, …) are filtered by `created_date` on dashboard / threats / incidents so leftover history is not mixed with the current project.

---

## 5. Environment and data methodology

### 5.1 Runtime topology

| Process | Address | Role in the method |
|---|---|---|
| MongoDB | `127.0.0.1:27017`, database `cloud_security_db` | System of record |
| Flask | `http://127.0.0.1:5000` | All business logic and inference |
| Vite / React | `http://127.0.0.1:5173` | Presentation; `/api` is proxied to Flask |

Start (Windows): `.\scripts\start-platform.ps1`, or two terminals (`python app.py` and `npm run dev`).

### 5.2 Data sources

| Source | Nature | Used by |
|---|---|---|
| User-uploaded ZIP | Real untrusted input | Phase 1 detectors |
| Synthetic cloud events (~8000 for training; live generator at runtime) | Simulated | Phase 2 models |
| JWT identity (`user_id`) | Real session | Ownership checks |
| Optional `GEMINI_API_KEY` | Remote LLM | Assistant wording |
| Filesystem `uploads/`, `INCIDENT_REPORTS_FOLDER`, `trained_models/` | Local artifacts | Extracted code, all downloadable PDFs, Joblib models |

### 5.3 Collections (conceptual)

Users, projects, security reports, monitoring state, cloud logs, threat summaries, incidents, responses, evidence, timeline, notifications, chat history, counters, plus Advanced collections used by the live overlay (`phase1_analysis`, `forensic_reports`, `chain_of_custody`, compliance-related documents).

The UI never talks to MongoDB. All reads and writes go through Flask.

---

## 6. Phase 1 methodology — static security assessment

**Goal:** Decide whether a project is safe enough to monitor.

**Method type:** Deterministic static analysis + residual risk scoring. **Not** Isolation Forest or Random Forest.

### 6.1 Upload hardening

The ZIP is treated as hostile input.

| Check | Method |
|---|---|
| Empty / oversize file | Size vs `MAX_UPLOAD_SIZE_MB` (default 1000) |
| Encrypted archive | ZIP encryption flag refused |
| Zip bomb | Entry count cap, uncompressed size cap, compression-ratio cap |
| Zip Slip / absolute paths | Every entry path must stay inside `uploads/<project_id>/` |
| Noise in the tree | Skip extracting `node_modules`, `.git`, `venv`, `__pycache__`, `dist`, etc. |

Extraction does **not** use unsafe `extractall()`. Paths are resolved under the project extract root.

### 6.2 Technology detection

After extract, the tree is classified (language, framework, dependency manifests). Detectors then apply language-appropriate rules.

### 6.3 Five independent detectors

Each detector walks relevant files, emits findings `{problem, severity, location, …}`, then findings are de-duplicated.

| Detector | Input | Method | Typical findings |
|---|---|---|---|
| Secret scanner | Source, `.env`, IaC | Pattern / entropy-style rules | API keys, tokens, hardcoded passwords |
| Static code analysis | `.py .js .ts .java .php .cs .rb .go` | AST/regex insecure-pattern rules | SQLi, XSS, command injection, weak crypto |
| Configuration | Env, YAML/JSON, settings | Policy rules | Debug on, default passwords, open CORS |
| Infrastructure | Terraform, CloudFormation, Docker, Kubernetes | IaC policy rules | `0.0.0.0/0`, public buckets, privileged containers |
| Dependencies | `requirements.txt`, `package.json`, `pom.xml`, … | Version vs curated advisory table | Known-vulnerable libraries |

Phase 1 is called “AI-based assessment” in the product sense (automated analysis + recommendations). The **detection method itself is rules**, which keeps every finding auditable for a viva or audit.

### 6.4 Scoring method

Implemented in `backend/phase1/scoring/engine.py`.

**Severity base penalties**

| Severity | Base penalty |
|---|---|
| Critical | 15 |
| High | 8 |
| Medium | 3.5 |
| Low | 1.2 |

**Repeat decay:** the *n*-th occurrence of the same `severity:problem` is multiplied by `0.55^n` so duplicate copies of one issue do not dominate the score.

**Category weights:** sensitive categories raise selected problems (example: Banking / Financial Application multiplies hardcoded password, SQLi, and API keys by 1.35; Hospital / Healthcare by 1.25).

**Soft saturation** so a long finding list does not always map to 0:

```
mapped = 100 × (1 − exp(−raw_penalty / 55))
score  = clamp(100 − mapped, 0, 100)
```

Empty scan → score 100. A floor of 12 is applied when the scan is heavily flagged but not an extreme critical storm.

**Risk band:** Critical / High / Medium / Low from score and critical count (for display).

### 6.5 Decision method (Gate A)

Implemented in `DecisionEngine.decide` with `APPROVAL_SCORE_THRESHOLD` (default **65**):

- **Approved** if `score ≥ 65` and `critical_count ≤ 2`, **or** if `score ≥ 75` and `critical_count ≤ 4`.
- Otherwise **Pending Remediation**. Phase 2 monitoring is **not** started.

This is a residual-risk gate: a score of 65+ unlocks monitoring even if a small number of critical findings remain. The user can still remediate, re-upload, and rescan.

### 6.6 Outputs of Phase 1

- Project document (score, status, category).
- Security report (counts, recommendation text, PDF path under `INCIDENT_REPORTS_FOLDER`).
- Detectors run concurrently (`ThreadPoolExecutor`, four workers). MongoDB stores `findings[:800]` so the UI stays responsive on large trees.
- Scan history / score trend.
- Advanced hook: same Project ID copied into `phase1_analysis` and the Phase Engine workflow.

---

## 7. Phase 2 methodology — cloud monitoring and threat detection

**Goal:** Continuously watch **Approved** projects.

**Method type:** Simulated event stream + feature engineering + hybrid ML inference. No live AWS API is required.

### 7.1 Event generation method

A background scheduler (`MONITORING_INTERVAL_SECONDS`, default **5**) creates CloudTrail-style events: console login, failed login, IAM change, object get/put, large download, security-group change, and similar.

Each event is normalised (user, IP, country, bytes, MFA, success/failure, hour, event type).

The SOC UI polls the API on a similar cadence so the analyst sees a live feed.

### 7.2 Feature engineering

The feature vector is a **contract** between `ai/train_model.py` and `phase2/ai/threat_detector.py`. Order must match or every prediction is silently wrong.

| # | Feature | Construction |
|---|---|---|
| 1 | `loginHour` | Hour 0–23 |
| 2 | `eventTypeEncoded` | Integer index of CloudTrail-style event name |
| 3 | `failedLogin` | 1 if login failed |
| 4 | `iamChange` | 1 if IAM/policy changed |
| 5 | `dataTransfer` | 1 if data movement |
| 6 | `mfaEnabled` | 1 if MFA present |
| 7 | `isSuspicious` | Generator/rule suspicious flag |
| 8 | `gigabytesTransferred` | `bytesTransferred / 1e9` |
| 9 | `highRiskCountry` | 1 if country ∈ {Russia, China, Unknown, North Korea, Iran} |
| 10 | `requestFailed` | 1 if status is Failure |

Features are passed through the **same StandardScaler** fitted at training time.

### 7.3 Offline training method

Script: `backend/ai/train_model.py`. Run **once** before relying on ML (or whenever models must be rebuilt).

| Step | Method |
|---|---|
| Dataset | **8000** synthetic events, **15%** labelled malicious (`ATTACK_RATE = 0.15`) |
| Realism | Attack and benign classes **overlap** (stealth factor, unusual-but-legitimate on-call behaviour) so metrics are not from linearly separable toy data |
| Split | 80/20 train/test, **stratified**, `random_state=42` |
| Scaling | `StandardScaler.fit` on **training split only** |
| Isolation Forest | Fit on **benign rows only**; `n_estimators=200`, `contamination=0.15` |
| Random Forest | Fit on labelled train set; `n_estimators=200`, `max_depth=12`, `min_samples_leaf=2`, `class_weight="balanced"` |
| Evaluation | Precision, recall, F1, accuracy, ROC-AUC, 5-fold CV F1, confusion matrix, feature importance |
| Persist | Joblib + `model_metadata.json` under `trained_models/` |

**Saved artifacts**

| File | Contents |
|---|---|
| `threat_detector.joblib` | Isolation Forest |
| `threat_classifier.joblib` | Random Forest |
| `feature_scaler.joblib` | StandardScaler |
| `model_metadata.json` | Metrics and settings for dashboards / viva |

Nothing in `app.py` retrains these files.

### 7.4 Live inference method

For each event:

1. Build the 10-feature vector.
2. Scale with the saved scaler.
3. **Isolation Forest:** `predict` → outlier (−1) or inlier (+1).
4. **Random Forest:** `predict_proba` for class “malicious”.
5. Combined decision: malicious if `probability ≥ 0.5` **or** Isolation Forest flagged an anomaly.
6. **Confidence:** if malicious, `probability × 100`; otherwise `(1 − probability) × 100`. If only Isolation Forest is present, confidence is derived from distance to the decision boundary.
7. **Threat class / severity** from event type, then overrides (e.g. data transfer → Data Exfiltration / Critical; failed login + suspicious → Brute Force; IAM change without MFA → Privilege Escalation; high-risk country without MFA raises severity).
8. **Gate B:** `isThreat` / forward to Phase 3 only if `is_malicious` **and** `confidence ≥ THREAT_CONFIDENCE_THRESHOLD` (default **85**).

`modelUsed` is reported as `RandomForest + IsolationForest` when both artifacts load.

### 7.5 Rule fallback method

If Joblib files are missing or inference throws, a transparent score is used:

| Signal | Points |
|---|---|
| `isSuspicious` | +40 |
| `failedLogin` | +25 |
| `iamChange` | +30 |
| `dataTransfer` | +35 |
| High-risk country | +20 |
| MFA absent | +10 |

Malicious if total ≥ 50. This keeps Phase 2 runnable on a fresh checkout.

### 7.6 Correlation

Related events can be grouped into one narrative so the SOC is not flooded with duplicate cards. Low-confidence anomalies remain **observations** on the Monitoring page.

Advanced Features also receive event/alert copies for the same Project ID so the overlay dashboard stays consistent with Phase 2.

---

## 8. Phase 3 methodology — incident response and forensics

**Goal:** Contain (in simulation), record, and close a validated threat.

**Method type:** Rule map from threat category → playbook. **Not** an ML classifier.

### 8.1 Incident opening

When Phase 2 sets `isThreat` true:

1. Incident manager creates an incident linked to Project ID, user, IP, threat, severity, confidence.
2. Project status becomes **Incident Detected**.
3. Rule engine selects a playbook key.

### 8.2 Playbook mapping (examples)

| Threat | Playbook key | Simulated actions (examples) |
|---|---|---|
| Credential Theft | `credential_theft` | Lock account, disable sessions, force reset, rotate keys, report |
| Brute Force | `brute_force` | Temporary lock, record IP, raise risk, notify |
| Data Exfiltration | `data_exfiltration` | Suspend download, record transfer, block IP, report |
| Privilege Escalation / Suspicious API | `privilege_escalation` | Revoke elevation, audit IAM, notify |
| Malware Activity | `malware` | Quarantine resource, save evidence, report |
| Public Resource Exposure | `public_exposure` | Playbook-specific isolate / restrict (simulation) |
| Default / unknown | `suspicious_login` | Flag login, MFA re-verify, record, notify |

**Important methodological choice:** every containment step is labelled **Simulation**. The platform does **not** call AWS IAM, does **not** change a real security group, and does **not** disable a real human’s account. The method still demonstrates SOAR-style orchestration, evidence, and reporting.

### 8.3 Evidence, timeline, notification, PDF

1. Each playbook step is stored as a **Response**.
2. Evidence collector writes forensic documents (incident context, log snapshot, actions).
3. Timeline builder orders events for the incident detail page.
4. Notification (in-app; email if SMTP is configured).
5. Incident PDF under `INCIDENT_REPORTS_FOLDER`.
6. Incident status stays **In Progress** after the playbook. Analysts review, optionally re-run, and **close** from the UI (`Closed` + `resolved_time`).
7. Incidents **Response Success** is computed from `Response.result` (successful simulated playbook steps), not from closed-case count.

Advanced Features receive the same Project ID for dashboard, forensics, and compliance. SIEM/SOAR screens are not in the live UI.

---

## 9. Advanced Features methodology

Advanced Features **reuse Phase 1–3 data**. They do not replace those pages. SIEM, SOAR, Assets, Vulnerabilities, and Threat Intel screens were removed from the UI; remaining modules below are the live Advanced surface.

### 9.1 Unified Security Dashboard

**Method:** Aggregate MongoDB + Phase APIs into widgets and Chart.js series (severity pie, horizontal risk bars, score history). Executive PDF is a reporting view, not a new detector. All PDFs land in `INCIDENT_REPORTS_FOLDER`.

### 9.2 Phase Integration Engine

**Method:** One row per project: score, workflow status, monitoring flag, **deploy blocked if score &lt; 65**, latest incident. Eight-step workflow visualisation. **SHAP-style** explanation uses Random Forest `feature_importances_` × scaled values (no `shap` package). **LIME-style** perturbs one feature at a time and re-runs `ThreatDetector.predict` (no `lime` package). These explain Phase 2; they are not extra trained models.

### 9.3 Compliance Manager

**Method:** Map live evidence (Phase 1 findings, Phase 2/3 incidents, monitoring state) onto **ISO 27001, NIST CSF, CIS Controls, GDPR, HIPAA**. Each control is pass/fail with a reason. Percentage and PDF are rule outputs, not an ML score.

### 9.4 Digital forensics (Advanced)

**Method:**

1. User uploads a file or pastes text.
2. Server computes **SHA-256** and **MD5**, size, filename, optional Project ID / Incident ID.
3. A chain-of-custody log is opened (`Evidence received and hashed` / `Sealed`).
4. Record is stored (MongoDB when available, plus in-process/disk fallback so the card still renders).
5. Analyst adds further custody actions (transferred, locker, analysis, archived).
6. **Custody `.txt`** and **Forensic PDF** are generated from that record (hashes + custody table).

Hashes prove **integrity**. They are not threat classifiers.

### 9.5 AI Security Assistant

**Method:** User question ± optional Project ID.

1. Build context from that user’s projects, latest scan, threats, incidents.
2. Call **Google Gemini** (`GEMINI_API_KEY`, configured Flash model) with an instruction **not to invent project facts**.
3. If Gemini fails, optional **OpenAI**.
4. If no LLM is available, **local knowledge base** (product/security topics only).
5. Store Q&A in chat history.

Gemini is a **remote LLM**. It is independent of Isolation Forest / Random Forest.

---

## 10. Authentication, authorisation, and security methodology

### 10.1 Identity

1. Register with **user name, email, location, and role**. Phone and password are not collected.
2. The account is **auto-verified**. Gmail SMTP sends a **project welcome email** to that address. SMTP failure is logged; registration still succeeds.
3. Login is **email only**: lookup by registered address, issue a **JWT** whose identity is `user_id`, lifetime `SESSION_TIMEOUT_MINUTES` (default 60), then open the dashboard.
4. React `AuthContext` keeps `token` and `user` in `localStorage`; Axios attaches `Authorization: Bearer`.
5. Private routes redirect to `/login`. Role labels do not bypass Project ID ownership.

### 10.2 Authorisation

Project, report, incident, and forensic routes check that the resource belongs to the signed-in user. PDF downloads use the same JWT (blob download), not a public file URL.

### 10.3 Defence in depth (method of protecting the platform itself)

| Control | Method |
|---|---|
| Untrusted ZIP | Size, encryption, bomb, Zip Slip checks |
| Identity | Registered email → JWT |
| Sessions | JWT expiry handlers |
| CORS | Allow-list (`FRONTEND_URL`, localhost:5173) |
| Uploads | `MAX_CONTENT_LENGTH` before the view |
| Audit | Auth, scan, and response events under `logs/` |
| ML | Inference-only at runtime |

---

## 11. Evaluation methodology

The project is evaluated at three levels, matching how it is built.

### 11.1 Phase 1 evaluation

- Qualitative: findings must be inspectable (file, line/pattern, severity).
- Quantitative: score 0–100, counts by severity, Approved vs Pending.
- Gate test: a project below threshold cannot start monitoring.

### 11.2 Phase 2 evaluation (offline)

Held-out 20% of the synthetic set plus 5-fold CV F1 on the Random Forest. Isolation Forest is scored as binary outlier vs label. Metrics are stored in `model_metadata.json` so a viva can cite **measured** precision/recall/AUC rather than claimed accuracy.

Live evaluation is operational: confidence histogram on the SOC page, and **only ≥ 85%** creates incidents (precision-oriented gate).

### 11.3 Phase 3 and Advanced evaluation

- Playbook steps appear as Response rows and timeline entries.
- PDFs exist on disk and download through authenticated APIs.
- Forensics shows SHA256, MD5, and custody on the card and in the PDF/txt.
- Assistant answers remain grounded when a Project ID is supplied.

### 11.4 What is in scope vs out of scope

| In scope (real) | Out of scope (simulated by design) |
|---|---|
| ZIP scan, MongoDB, JWT, PDFs, hashes | Live AWS CloudTrail |
| Isolation Forest + Random Forest on generated events | Blocking a real ISP IP or disabling a real IAM user |
| Gemini answers if a key is set | Production multi-tenant SaaS hardening |

---

## 12. Configuration knobs (method parameters)

All live in `backend/.env` / `config/settings.py`.

| Parameter | Default | Methodological role |
|---|---|---|
| `APPROVAL_SCORE_THRESHOLD` | 65 | Gate A (Phase 1 → Phase 2) |
| `THREAT_CONFIDENCE_THRESHOLD` | 85 | Gate B (Phase 2 → Phase 3) |
| `MONITORING_INTERVAL_SECONDS` | 5 | Event generation period |
| `SESSION_TIMEOUT_MINUTES` | 60 | JWT lifetime |
| `MAX_UPLOAD_SIZE_MB` | 1000 | Phase 1 input bound |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | empty / `gemini-3.5-flash-lite` | Assistant LLM |
| `OPENAI_API_KEY` | empty | Assistant fallback |
| `MAIL_*` | Gmail SMTP | Welcome email on register |
| `INCIDENT_REPORTS_FOLDER` | `D:\mainproject papers\Documents\Incident reports` | All downloadable PDFs |
| `MONGO_URI` | localhost `cloud_security_db` | Data store |

Changing Gate A or Gate B is how the lab tunes strictness without rewriting detectors.

---

## 13. Limitations of the methodology

1. **Phase 2 events are simulated.** The ML method is real; the packet/cloud API is not. Transfer to a live trail would require a collector replacing `event_generator.py` while keeping the same 10 features.
2. **Training data is synthetic.** Overlap was designed in, but it is not a public labelled CloudTrail corpus.
3. **Phase 1 rules can false-positive or miss novel vulns.** There is no neural SAST in this repo.
4. **Playbooks do not mutate cloud state.** They are pedagogic SOAR.
5. **Gemini is optional and external.** Product security detections do not depend on it.
6. **XGBoost** may appear in Python requirements; **live training and inference use Isolation Forest + Random Forest**, not XGBoost.
7. Flask is started with `use_reloader=False` in `app.py`; backend route changes require a process restart.

---

## 14. Summary: how the project works

The methodology is a **gated SOC pipeline implemented as a local three-tier web application**.

1. **Identity method** — email registration (name, location, role), welcome SMTP mail, email-only JWT login so every scan, event, and PDF is attributable.
2. **Assessment method** — five static detectors (parallel), decaying weighted penalties, exponential score mapping, approval gate at score 65 with limited residual criticals, ZIP cap 1000 MB.
3. **Detection method** — 10 numeric features, StandardScaler, Isolation Forest (unsupervised baseline on benign traffic) plus Random Forest (supervised probability), 85% confidence gate; rules if models are absent.
4. **Response method** — threat-to-playbook table, simulated containment, evidence, timeline, PDF; incident stays In Progress until close; Response Success from playbook results.
5. **Overlay method** — Advanced dashboard, SHA256/MD5 forensics with chain of custody, framework compliance mapping, optional Gemini assistant — all keyed by **Project ID**. Dashboard cards use current-project lifetime only.

That combination is the working methodology of **Cloud Security Monitoring and Automated Incident Response using AI**.
