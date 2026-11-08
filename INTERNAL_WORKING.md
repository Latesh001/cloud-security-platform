# Cloud Security Platform — Internal Working (Phase 1 → Phase 3)

**Project title:** Cloud Security Monitoring and Automated Incident Response using AI

This document describes **what happens inside the backend** from the moment a ZIP is uploaded through Phase 1 assessment, Phase 2 monitoring, and Phase 3 incident response. It follows the running code, not a conceptual sketch.

Related files: [METHODOLOGY.md](./METHODOLOGY.md) (why these methods), [WORKING_PROCESS.md](./WORKING_PROCESS.md) (what the user clicks), [ARCHITECTURE.md](./ARCHITECTURE.md) (layers).

---

## 0. How a request enters the pipeline

Every protected call is:

```
Browser (port 5173)
  → Vite proxy /api → Flask (port 5000)
  → JWT interceptor: Authorization Bearer token
  → Blueprint route (@jwt_required)
  → Domain function
  → MongoDB document and/or filesystem
  → JSON (or PDF blob) back to the UI
```

Identity inside the JWT is integer `user_id`, issued after **email-only login**. Project, report, and incident routes check **ownership** (`user_id` + `project_id`) before any scan or monitor starts.

The three phases share one **Project ID**. That ID is created in the Projects module **before** Phase 1 runs.

```
POST /api/projects          → Project document (status: Created)
POST /api/projects/upload/<project_id>
        save ZIP → uploads/<project_id>/original.zip
        status → Uploaded
        immediately calls trigger_scan(project_id)   ← Phase 1 starts here
```

---

## 1. Phase 1 — internal working of the security scan

**Entry:** `phase1.api.routes.trigger_scan(project_id)`  
**Usually started by:** ZIP upload (`projects.routes.upload_project`) or a later `POST /api/phase1/scan/<project_id>` (rescan).

### 1.1 Status lock and ZIP validation

Internally the function does the following **in order**:

1. Load the `Project` document. If `upload_path` is missing, return `{error: Project or upload not found}`.
2. Set `project.status = "Scanning"` and commit. The UI now shows a scan in progress.
3. `ZipValidator.validate(upload_path)`:
   - File exists and is non-empty
   - Size ≤ `MAX_UPLOAD_SIZE_MB` (default 1000)
   - Not encrypted
   - Entry count ≤ 100000
   - Uncompressed size / ratio within bomb limits
   - No Zip Slip (`..`), no absolute paths
   - Dependency folders (`node_modules`, `.git`, `venv`, …) are skipped from bomb accounting and later extraction
4. If invalid → `status = "Upload Failed"` and stop. Phase 2 never starts.

### 1.2 Safe extract and technology detection

```
extract_dir = uploads/<project_id>/extracted
shutil.rmtree(extract_dir)     # rescan never uses stale files
ZipExtractor.extract(original.zip, extract_dir)
TechnologyDetector.detect(extract_dir, file_list)
```

- Every ZIP entry path is resolved **inside** `extract_dir` (no `extractall()`).
- Detector returns primary language, frameworks, and manifests.
- Project fields `programming_language` and `framework` are updated in MongoDB.

### 1.3 Five detectors (internal)

Findings start as an empty list. The five detectors run in a **`ThreadPoolExecutor` (four workers)**. Each walks the extracted tree and **appends** dictionaries `{detector, problem, severity, location, …}`. Extension filters skip irrelevant files so large ZIPs stay practical.

| Order | Class | What it walks internally |
|---|---|---|
| 1 | `SecretScanner` | Source, `.env`, IaC — regex/entropy for keys and passwords |
| 2 | `StaticAnalyzer` | `.py .js .ts .java .php .cs .rb .go` — SQLi, XSS, command injection, weak crypto |
| 3 | `ConfigAnalyzer` | Env / YAML / JSON / settings — debug, default passwords, open CORS |
| 4 | `InfrastructureAnalyzer` | Terraform, CloudFormation, Docker, Kubernetes — `0.0.0.0/0`, public buckets, privileged containers |
| 5 | `DependencyAnalyzer` | `requirements.txt`, `package.json`, `pom.xml`, … vs a curated advisory table |

Then `deduplicate(findings)` collapses identical problem+location pairs so scoring is not inflated by copies.

**This step does not call Isolation Forest or Random Forest.** Phase 1 is rule-based.

### 1.4 Scoring (internal formula)

`ScoringEngine.calculate(findings, project.category)`:

1. Count Critical / High / Medium / Low.
2. For each finding, take a **base penalty** (Critical 15, High 8, Medium 3.5, Low 1.2).
3. Repeat occurrences of the same `severity:problem` decay by `0.55^n`.
4. Project **category** can multiply selected problems (e.g. Banking hardcoded password × 1.35).
5. Soft map unbounded penalty into 0–100:

```
mapped = 100 × (1 − exp(−raw_penalty / 55))
score  = clamp(100 − mapped, 0, 100)
```

Empty findings → 100. Risk band (Critical/High/Medium/Low) is derived from score + critical count.

### 1.5 Decision gate (Gate A)

`DecisionEngine.decide(score, critical_count, threshold=65)`:

| Condition | Internal result |
|---|---|
| `score ≥ 65` and `critical_count ≤ 2` | `"Approved"` |
| `score ≥ 75` and `critical_count ≤ 4` | `"Approved"` |
| Anything else | `"Pending Remediation"` |

### 1.6 Recommendation and PDF

- `RecommendationEngine.generate` builds prioritised remediation text from findings + score + category.
- `RecommendationEngine.top_risks` picks the worst items for the report header.
- `PDFReportGenerator.generate` writes through `pdf_output_path` into  
  `INCIDENT_REPORTS_FOLDER` (default `D:\mainproject papers\Documents\Incident reports`).

### 1.7 What is written to the database

A `SecurityReport` document is inserted with counts, score, risk, recommendation, approval, PDF path.

Project fields are updated:

| If Approved | If not Approved |
|---|---|
| `security_score` = score | `security_score` = score |
| `status` = **Monitoring Enabled** | `status` = **Pending Remediation** |
| `monitoring_enabled` = True | monitoring stays off |
| `ProjectMonitoring` created or set enabled, state `Idle` | no monitor record / not enabled |

Mongo `scan_logs` gets findings (capped at **800** rows), tech stack, scoring, duration, and whether monitoring auto-started.

### 1.8 Automatic hand-off to Phase 2

**Inside the same `trigger_scan` call**, if approval is `"Approved"`:

```
MonitoringScheduler.start_monitoring(project_id, flask_app)
```

If that thread starts, `monitoring_started = True`. If it throws, the scan still succeeds; the user can start monitoring later from Phase 2.

Notifications:

- Always: “Scan Completed” with the score.
- Approved: “Project Approved” (+ email if SMTP is set).
- Else: “Remediation Required”.

### 1.9 Advanced Features hook (does not replace Phase 1)

`on_phase1_complete(...)` upserts:

- `phase1_analysis` — score, counts, first 80 findings, `phase2_enabled`, `deployment_blocked`
- `phase_integration` — workflow status `Monitoring` or `Failed`

If this hook fails, the scan **still succeeds**. Phase 1 never depends on Advanced Features.

### 1.10 What the UI reads afterwards

`GET /api/phase1/result/<project_id>` joins:

- Project fields
- Latest `SecurityReport`
- Latest `scan_logs` Mongo document (findings list)

That is the internal end of Phase 1.

---

## 2. Gate between Phase 1 and Phase 2

Monitoring cannot start unless all of these are true (`_check_eligibility` plus the scheduler):

| Check | Internal rule |
|---|---|
| Flag | `project.monitoring_enabled` is True (set only on Approved) |
| Report exists | Latest `SecurityReport` for that Project ID |
| Score | `report.score ≥ APPROVAL_SCORE_THRESHOLD` (65) |
| Residual criticals | Not more than 4 criticals; if score &lt; 75, not more than 2 |
| Scheduler extra | If latest report has `critical > 8`, the background thread **refuses** to start |

Manual start: `POST /api/monitoring/start/<project_id>` after the same checks.  
Auto start: already described in §1.8.

If the project is Pending Remediation, internally `monitoring_enabled` is false, so the scheduler returns `False` immediately.

---

## 3. Phase 2 — internal working of continuous monitoring

**Entry:** `MonitoringScheduler.start_monitoring(project_id, app)`  
**Blueprint:** `/api/monitoring`

### 3.1 Thread model

Inside a process-wide lock:

1. If this `project_id` is already in `_active_monitors`, do nothing (already running).
2. Confirm project exists and `monitoring_enabled`.
3. Create a `CloudEventGenerator(project_id)` stored in `_generators`.
4. Create a `threading.Event` used as a stop flag.
5. Start a **daemon thread** `monitor_loop` with the Flask **app context** (so Mongo and config work inside the thread).
6. Set `ProjectMonitoring.current_state = "Running"`.

The loop sleeps `MONITORING_INTERVAL_SECONDS` (default **5**) between events.  
Stop: `POST /api/monitoring/stop/<project_id>` sets the event; state becomes `Stopped`; generator is discarded.

### 3.2 One tick of the loop (`_process_event`)

Every interval the thread does **exactly this sequence**:

```
1. CloudEventGenerator.generate()
      → synthetic CloudTrail-style dict
        (eventType, username, sourceIP, country, bytes, MFA, status, timestamp, …)

2. LogPreprocessor.process(raw)
      → drop if required fields missing
      → drop if duplicate hash (projectId_timestamp_eventType_username)
      → derive loginHour, failedLogin, iamChange, dataTransfer, isSuspicious, mfaEnabled

3. mongo_insert("cloud_logs", processed + raw)

4. ProjectMonitoring.total_logs += 1; last_updated = now

5. ThreatDetector.predict(processed)
      → { threat, severity, confidence, isAnomaly, isThreat, modelUsed, threshold }

6. Keep last 50 events in memory for correlation

7. mongo_insert("ai_inference", { projectId, prediction, log })

8. on_phase2_event(project_id, processed, prediction)   # Advanced overlay hook; failures ignored

9. If isAnomaly:
      insert ThreatSummary
      status = "Validated" if isThreat else "Observation"
      if isThreat: total_threats += 1

10. If isThreat (Gate B):
      notify user “Threat Detected”
      IncidentManager.create_from_threat(...)     ← Phase 3 starts

11. EventCorrelationEngine.correlate(recent_events)
      if a new attack-chain name appears:
          mongo_insert("threat_history")
          notify “Correlated Attack Chain”
          IncidentManager.create_from_threat(...)  ← another Phase 3 open
```

### 3.3 Event generation (internal)

`CloudEventGenerator` does **not** call AWS. It samples event types such as `ConsoleLogin`, `ConsoleLoginFailure`, `CreateAccessKey`, `ModifyPolicy`, `LargeFileDownload`, `AssumeRole`, etc., plus IP, country, bytes, MFA. Some events are flagged `isSuspicious` so both the ML path and the rule fallback have signal.

### 3.4 Feature vector (internal, order is a contract)

`ThreatDetector.extract_features` builds a 1×10 NumPy row **in this order** (must match `ai/train_model.py`):

1. `loginHour`
2. `eventTypeEncoded` (index in a fixed event-name list)
3. `failedLogin`
4. `iamChange`
5. `dataTransfer`
6. `mfaEnabled`
7. `isSuspicious`
8. `gigabytesTransferred` = bytes / 1e9
9. `highRiskCountry` (Russia, China, Unknown, North Korea, Iran)
10. `requestFailed` (status == Failure)

### 3.5 ML inference (internal)

On first loop iteration: `ThreatDetector.load_model(MODELS_FOLDER, threshold=85)` loads:

- `threat_detector.joblib` — Isolation Forest  
- `threat_classifier.joblib` — Random Forest  
- `feature_scaler.joblib` — StandardScaler  

**If models loaded:**

```
scaled = scaler.transform(features)
anomaly_detected = (IsolationForest.predict == -1)
probability = RandomForest.predict_proba[:, malicious]
malicious = (probability ≥ 0.5) OR anomaly_detected
confidence = probability×100 if malicious else (1−probability)×100
modelUsed = "RandomForest + IsolationForest"
```

If only Isolation Forest exists, confidence is `min(99, 70 + |decision_function|×100)`.

**If models missing or inference throws — rule fallback:**

```
score = 0
+40 isSuspicious, +25 failedLogin, +30 iamChange, +35 dataTransfer
+20 high-risk country, +10 no MFA
malicious if score ≥ 50
```

### 3.6 Threat label (internal)

If not malicious → `("Normal", "Low")`.  
If malicious → map `eventType` through `THREAT_CATEGORIES` (e.g. `CreateAccessKey` → Credential Theft / Critical), then overrides:

- `dataTransfer` → Data Exfiltration / Critical  
- failed login + suspicious → Brute Force / High  
- IAM change without MFA → Privilege Escalation / High  
- high-risk country without MFA → severity raised one band  

### 3.7 Gate B (Phase 2 → Phase 3)

```
forward_to_response = is_malicious AND confidence ≥ THREAT_CONFIDENCE_THRESHOLD (85)
isThreat = forward_to_response
isAnomaly = is_malicious
```

- Anomaly but confidence &lt; 85 → **ThreatSummary Observation only**. No incident.
- `isThreat` true → **Phase 3** `IncidentManager.create_from_threat`.

### 3.8 Correlation (second way into Phase 3)

The last 10 in-memory event types are matched against sequences, for example:

| Sequence | Incident type |
|---|---|
| LoginFailure, LoginFailure, ConsoleLogin | Brute Force Attack |
| ConsoleLogin, CreateAccessKey, LargeFileDownload | Credential Theft & Data Exfiltration |
| ConsoleLogin, ModifyPolicy, DeleteBucket | Privilege Escalation & Sabotage |
| AssumeRole, CreateUser, AttachUserPolicy | Insider Threat Pattern |

Each chain name is escalated **once** per monitor session (`escalated_chains` set). Confidence is forced to 95. That also calls `IncidentManager.create_from_threat`.

---

## 4. Phase 3 — internal working of incident response

**Entry:** `IncidentManager.create_from_threat(project_id, log, prediction)`  
**Triggered only from Phase 2** (direct `isThreat` or correlated chain). Analyst close/re-run uses the incidents API afterwards.

### 4.1 Incident record

1. Allocate next `incident_id` (`INC-0001`, …).
2. Insert `Incident`: threat, severity, confidence, affected user, source IP, `status = Open`.
3. Set `project.status = "Incident Detected"`.
4. `mongo_insert("incident_evidence", { incidentId, log, prediction })`.
5. Immediately call `RuleEngine.process_incident(incident, log, auto_mode=True)`.
6. `on_incident_created(...)` Advanced hook (workflow `Incident`). Failures ignored.
7. Audit log: incident created.

### 4.2 Rule engine (internal)

`PLAYBOOK_MAP` converts the threat string to a playbook **key**:

| Threat (from Phase 2) | Playbook key |
|---|---|
| Credential Theft | `credential_theft` |
| Brute Force / Brute Force Attack | `brute_force` |
| Data Exfiltration | `data_exfiltration` |
| Privilege Escalation / Suspicious API Usage | `privilege_escalation` |
| Malware Activity | `malware` |
| Suspicious Login / default | `suspicious_login` |
| Configuration Tampering | `config_tampering` |
| Public Resource Exposure | `public_exposure` |
| Insider Threat | `insider_threat` |

Unknown threat → `suspicious_login`.

Then `PlaybookExecutor.execute(playbook_key, incident, log)` walks the step list and returns, for each step:

```
{ action, result: "Simulated Successfully", step, incident_id, target_user, source_ip }
```

**No AWS/IAM/firewall API is called.** The result string is always simulated success.

Each step is stored as a `Response` row. Incident status is set to **In Progress** and committed.

### 4.3 Evidence

`EvidenceCollector.collect` writes `forensic_logs` with:

- incident / project IDs, threat, severity, confidence  
- affected user, source IP, country, browser, event type, resource  
- full event history (`log`)  
- the list of response actions  

### 4.4 Timeline

`TimelineBuilder.build` writes `timeline_history` as an ordered list:

1. Security Event Detected (event type from the log)  
2. AI Threat Prediction (threat + confidence %)  
3. Incident Created (`incident_id`)  
4. One “Response Executed” row per playbook step  
5. Evidence Stored  
6. Notification Sent  

### 4.5 Notify, PDF, remain open for the analyst

Inside the same `process_incident` call:

1. `NotificationService.create` — “Incident INC-… — severity” (email if SMTP configured).
2. `IncidentReportGenerator.generate` — PDF under `INCIDENT_REPORTS_FOLDER` using incident, project, responses, Mongo evidence, timeline, and the threat narrative.
3. `incident.status = "In Progress"` and commit. The Open tab and Open counter include these live cases. `_live_status` also treats a leftover `Resolved` row without `resolved_time` as In Progress.

The analyst UI (`/api/incidents/...`) lists **current-project lifetime** cases only (`created_time` ≥ project `created_date`). **Response Success** is `successful Response rows / all Response rows` for those incidents. `close_incident` sets **Closed**, `resolved_time`, and `on_incident_closed` (workflow → Resolved).

---

## 5. End-to-end internal sequence (one project)

```
POST /api/projects
    MongoDB: projects { status: Created }

POST /api/projects/upload/<P>
    Disk: uploads/<P>/original.zip
    MongoDB: projects { status: Uploaded, upload_path }
    ── calls trigger_scan(P) ──────────────────────────────────────────

PHASE 1  trigger_scan
    status Scanning
    ZipValidator → ZipExtractor → TechnologyDetector
    SecretScanner + StaticAnalyzer + ConfigAnalyzer
      + InfrastructureAnalyzer + DependencyAnalyzer
    deduplicate
    ScoringEngine → DecisionEngine (Gate A)
    RecommendationEngine → PDF in INCIDENT_REPORTS_FOLDER
    MongoDB: security_reports, scan_logs
    projects.security_score, status Approved/Pending
    if Approved:
        monitoring_enabled True
        ProjectMonitoring Idle
        MonitoringScheduler.start_monitoring   ← PHASE 2 thread
    notifications
    on_phase1_complete → phase1_analysis, phase_integration

PHASE 2  monitor_loop  (every 5 s, while not stopped)
    generate → preprocess → cloud_logs
    ThreatDetector.predict  (IF + RF or rules)
    ai_inference
    on_phase2_event
    if anomaly: threat_summary
    if isThreat AND confidence ≥ 85:          ← Gate B
        IncidentManager.create_from_threat    ← PHASE 3
    if correlated chain (once per name):
        IncidentManager.create_from_threat    ← PHASE 3

PHASE 3  create_from_threat
    incidents { Open }
    projects.status = Incident Detected
    incident_evidence
    RuleEngine → PlaybookExecutor (simulated steps)
    responses rows
    forensic_logs + timeline_history
    notification + incident PDF (Incident reports folder)
    incidents.status = In Progress  (until analyst Close)
    on_incident_created
```

---

## 6. Internal data map (Phase 1–3)

| Store | Written in | Contents |
|---|---|---|
| `projects` | Create, upload, scan, incident | Status, score, monitoring flag |
| `uploads/<id>/` | Upload / extract | `original.zip`, `extracted/` tree |
| `security_reports` | Phase 1 | Score, counts, PDF path, approval |
| `INCIDENT_REPORTS_FOLDER` | Phase 1, 3, Advanced PDFs | Security, incident, forensic, compliance, executive PDFs |
| `scan_logs` | Phase 1 | Full findings + scoring JSON |
| `project_monitoring` | Phase 1/2 | Enabled, Running/Stopped, log/threat counters |
| `cloud_logs` | Phase 2 | Each processed event |
| `ai_inference` | Phase 2 | Feature prediction per event |
| `threat_summary` | Phase 2 | Anomalies (Observation vs Validated) |
| `threat_history` | Phase 2 | Correlated chains |
| `incidents` | Phase 3 | Case header |
| `responses` | Phase 3 | Playbook steps |
| `incident_evidence` | Phase 3 open | Log + prediction snapshot |
| `forensic_logs` | Phase 3 | Evidence pack |
| `timeline_history` | Phase 3 | Ordered narrative |
| `notifications` | All phases | In-app (optional email) |
| `phase1_analysis` / `phase_integration` | Hooks | Advanced copy of the same Project ID |
| `trained_models/*.joblib` | Offline only | Loaded by Phase 2; never rewritten by the scan loop |

---

## 7. What is computed vs simulated internally

| Real computation | Simulated by design |
|---|---|
| ZIP validation, extract, five detectors, score, PDF | AWS CloudTrail / live cloud APIs |
| Isolation Forest + Random Forest on the 10-feature vector | Blocking a real IP, disabling a real IAM user |
| JWT ownership, Mongo writes, incident IDs | Production containment APIs |
| SHA/report generation for incidents | Changing the developer’s actual cloud account |

Playbook `result` is always `"Simulated Successfully"`. The **orchestration, evidence, and timeline** are real documents in MongoDB; the **cloud side-effect** is not.

---

## 8. Failure behaviour (internal)

| Failure | What the pipeline does |
|---|---|
| Bad ZIP | Phase 1 stops at `Upload Failed`; no detectors, no Phase 2 |
| Detector exception | Depends on the detector; scan function is one try-path per upload |
| Score below gate | `Pending Remediation`; scheduler will not start |
| Missing Joblib models | Phase 2 uses weighted rules; still emits `isThreat` using the same 85% gate on the rule confidence |
| Monitor tick exception | Logged, session rolled back, loop continues after the interval |
| Advanced hook exception | Logged; Phase 1/2/3 documents already committed |
| Playbook unknown threat | Falls back to `suspicious_login` steps |

---

## 9. One-sentence internal summary

**Phase 1** turns an untrusted ZIP into a scored `SecurityReport` and, if Gate A passes, flips `monitoring_enabled` and starts a background thread. **Phase 2** that thread synthesises an event, vectorises it, runs Isolation Forest + Random Forest (or rules), and only when Gate B (`isThreat`, confidence ≥ 85) or a correlated chain fires does it call Phase 3. **Phase 3** allocates an incident, maps the threat to a simulated playbook, writes responses, forensic logs, a timeline, and a PDF, and leaves the case **In Progress** until an analyst closes it — all keyed by the same Project ID. Dashboard / Monitoring / Incidents then count only records from this project’s current lifetime.
