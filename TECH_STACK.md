# Cloud Security Platform — Technology Stack

**Project title:** Cloud Security Monitoring and Automated Incident Response using AI

This document records the technologies present in the project and how they are
used. It distinguishes the active runtime stack from dependencies retained in
the backend requirements file for compatibility. For component relationships
and data flow, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## 1. Stack at a glance

| Area | Active technologies |
|---|---|
| Frontend | React 18, Vite 5, Tailwind CSS 3, React Router 6, Chart.js 4, Framer Motion, Formik, Yup, Axios, React Icons |
| Main API | Python 3.12+, Flask 3, Flask-JWT-Extended, Flask-CORS, Flask-Mail, Werkzeug |
| Persistence | MongoDB, PyMongo, and the project’s custom Mongo model/query layer |
| AI / ML | scikit-learn, NumPy, Pandas, XGBoost, Joblib, custom security rules, Gemini REST API, optional OpenAI REST API |
| Optional AI service | FastAPI, Uvicorn, Pydantic, Requests |
| Reports and operations | ReportLab PDFs, APScheduler, SMTP/Gmail, filesystem storage, PowerShell/npm/pip |

```
Presentation   React, Vite, Tailwind, Chart.js, Formik, Axios, Framer Motion
API            Flask, JWT, CORS, Mail, APScheduler, ReportLab
Intelligence   scikit-learn, NumPy, Pandas, XGBoost, Joblib, custom rules, Gemini/OpenAI
Data           MongoDB, PyMongo, uploads, reports, trained models, datasets, logs
Optional       FastAPI sidecar for direct Gemini chat requests
```

The core product runs locally. Docker and a cloud account are not required.

---

## 2. Runtime and tooling

| Role | Technology | Source / notes |
|---|---|---|
| Backend language | Python | 3.12+ is required by the project documentation |
| Frontend language | JavaScript with ES modules and JSX | `frontend/package.json` sets `"type": "module"` |
| Backend dependency manager | pip | `backend/requirements.txt` |
| Frontend dependency manager | npm | `frontend/package.json` and `frontend/package-lock.json` |
| Environment configuration | python-dotenv | Loads `backend/.env`; defaults are documented in `backend/.env.example` |
| Frontend dev server | Vite | `127.0.0.1:5173`; proxies `/api` to Flask |
| Backend server | Flask development server | `0.0.0.0:5000` in `backend/app.py` |
| Optional AI server | Uvicorn running FastAPI | `127.0.0.1:8001` when started from `ai_service` |
| Local database | MongoDB | URI defaults to `mongodb://127.0.0.1:27017/cloud_security_db` |
| Local automation | PowerShell | Project start scripts and documented commands |

### Main commands

```powershell
# Frontend
cd frontend
npm install
npm run dev

# Backend
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py

# Optional AI sidecar
cd ai_service
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8001
```

---

## 3. Frontend stack

| Package | Declared version | Use |
|---|---:|---|
| **React** | `^18.3.1` | Component-based single-page application |
| **React DOM** | `^18.3.1` | Browser rendering |
| **React Router DOM** | `^6.26.2` | Client-side routes and protected pages |
| **Vite** | `^5.4.3` | Development server and production bundling |
| **@vitejs/plugin-react** | `^4.3.1` | React/JSX integration with Vite |
| **Tailwind CSS** | `^3.4.10` | Utility styling and SOC dashboard theme |
| **PostCSS** | `^8.4.45` | CSS processing |
| **Autoprefixer** | `^10.4.20` | Browser vendor prefixes |
| **Axios** | `^1.7.7` | API calls, JWT header handling, and PDF/blob downloads |
| **Chart.js** | `^4.4.4` | Chart rendering |
| **react-chartjs-2** | `^5.2.0` | React bindings for Chart.js |
| **Framer Motion** | `^11.5.4` | Page and component animations |
| **Formik** | `^2.4.6` | Form state management |
| **Yup** | `^1.4.0` | Form schema validation |
| **React Icons** | `^5.3.0` | UI icons |

**Entry point:** `frontend/src/main.jsx`  
**Development URL:** `http://127.0.0.1:5173`  
**API proxy:** `/api` → `http://127.0.0.1:5000`

The Vite production build separates React, charts, motion, and form libraries
into cacheable chunks.

---

## 4. Main backend stack

| Package | Declared version | Use |
|---|---:|---|
| **Flask** | `>=3.0.3,<4.0` | REST API and application factory |
| **Flask-JWT-Extended** | `>=4.6.0,<5.0` | Bearer JWT authentication and session expiry |
| **Flask-CORS** | `>=4.0.1,<7.0` | Restricts browser origins to the frontend |
| **Flask-Mail** | `>=0.10.0,<1.0` | Optional SMTP welcome, verification, and recovery mail |
| **Werkzeug** | `>=3.0.3,<4.0` | Flask runtime and upload-size enforcement |
| **itsdangerous** | `>=2.2.0,<3.0` | Signed, expiring recovery tokens |
| **bcrypt** | `>=4.2.0` | Password hashing |
| **email-validator** | `>=2.2.0` | Registration email validation |
| **APScheduler** | `>=3.10.4` | Background monitoring scheduler |
| **Requests** | `>=2.32.3` | GitHub downloads and LLM HTTP requests |
| **ReportLab** | `>=4.2.2` | Phase 1, incident, forensic, compliance, and executive PDFs |
| **python-dotenv** | `>=1.0.1` | Environment loading |

**Entry point:** `backend/app.py` → `create_app()`  
**Health endpoint:** `http://localhost:5000/api/health`

Flask blueprints provide the Auth, Projects, Phase 1, Monitoring, Incidents,
Dashboard, Notifications, Chatbot, and Advanced API surfaces.

### Retained compatibility dependencies

`backend/requirements.txt` also declares **Flask-SQLAlchemy**, **SQLAlchemy**,
and **psycopg2-binary**. They are not the active persistence implementation:
the application uses `database/extensions.py`, `database/models.py`, PyMongo,
and a `DummyDB`/session-compatible wrapper around MongoDB. PostgreSQL and
SQLAlchemy should therefore not be described as active databases for this
project unless the persistence implementation changes.

---

## 5. Database and persistence

| Technology | Role |
|---|---|
| **MongoDB** | Primary and sole application database at runtime |
| **PyMongo** (`>=4.8.0,<5.0`) | Connection, indexes, CRUD, counters, and document operations |
| **Custom Mongo model layer** | SQLAlchemy-style query methods backed by MongoDB collections |

| Setting | Value |
|---|---|
| Database name | `cloud_security_db` |
| Default URI | `mongodb://127.0.0.1:27017/cloud_security_db` |
| Health status | `/api/health` reports `connected` or `unavailable` |

The model layer stores users, projects, security reports, monitoring records,
threat summaries, cloud events, incidents, responses, notifications, chat
history, verification/recovery records, evidence, timelines, and counters.

The filesystem stores:

| Folder | Contents |
|---|---|
| `uploads/<project_id>/` | Original ZIP files and safely extracted project trees |
| `trained_models/` | Serialized ML models, scaler, and metadata |
| `datasets/` | Synthetic training data |
| `logs/` | Application and audit logs |
| `INCIDENT_REPORTS_FOLDER` | Downloadable Phase 1/3 and Advanced PDF reports |

---

## 6. AI and machine-learning stack

| Technology | Declared version | Role |
|---|---:|---|
| **NumPy** | `>=1.26.4` | Numeric feature arrays |
| **Pandas** | `>=2.2.2` | Training tables and feature frames |
| **scikit-learn** | `>=1.5.1` | Isolation Forest, Random Forest, scaling, and metrics |
| **XGBoost** | `>=2.1.1` | Training dependency/tooling |
| **Joblib** | `>=1.4.2` | Serialization of model artifacts |
| **Custom Python rule engines** | Project code | Phase 1 findings, Phase 2 fallback detection, and Phase 3 playbooks |
| **Google Gemini API** | HTTP integration via Requests | Preferred assistant provider when `GEMINI_API_KEY` is configured |
| **OpenAI API** | HTTP integration via Requests | Optional fallback provider when `OPENAI_API_KEY` is configured |

Phase 1 uses rule-based source and configuration detectors. Phase 2 combines
anomaly detection, supervised classification, and a rule fallback. Training is
offline; inference loads artifacts from `trained_models/` and does not retrain
during requests.

```powershell
cd backend
python ai\train_model.py
```

If the model artifacts are unavailable, Phase 2 uses the rule-based detector.
The assistant falls back to the curated knowledge base if no configured LLM
provider can answer.

---

## 7. Optional FastAPI AI sidecar

The `ai_service` directory contains a separate, optional service for direct
Gemini chat calls. The Flask application already exposes the chatbot routes, so
the sidecar is not required by the frontend.

| Package | Declared version | Use |
|---|---:|---|
| **FastAPI** | `>=0.115.0` | Sidecar HTTP API |
| **Uvicorn** | `>=0.30.0` | ASGI server |
| **Pydantic** | `>=2.8.0` | Request validation |
| **Requests** | `>=2.32.3` | Shared HTTP dependency |
| **python-dotenv** | `>=1.0.1` | Reads the backend environment |

**Endpoints:** `GET /health`, `POST /chat`  
**Default URL:** `http://127.0.0.1:8001`

---

## 8. Reporting, mail, and external integrations

| Technology | Used for |
|---|---|
| **ReportLab** | Security, incident-response, forensics, compliance, and executive PDFs |
| **Flask-Mail + SMTP** | Optional account and notification email |
| **Gmail SMTP** | Local mail provider when `MAIL_USERNAME` and an app password are configured |
| **Gemini API** | Preferred assistant wording and contextual answers |
| **OpenAI API** | Optional assistant fallback |
| **Simulated CloudTrail-style events** | Local Phase 2 monitoring without AWS credentials |
| **GitHub download requests** | Optional project source acquisition |

When SMTP is not configured, local account flows continue without external mail.

---

## 9. Ports and process map

| Process | Technology | Port |
|---|---|---:|
| Web UI | Vite + React | 5173 |
| Main API | Flask | 5000 |
| Optional AI sidecar | FastAPI + Uvicorn | 8001 |
| Database | MongoDB | 27017 |

```
Vite React :5173 ──/api proxy──► Flask :5000 ──► MongoDB :27017
                                      │
                                      └── optional ──► FastAPI AI :8001
```

---

## 10. Why this stack is used

| Decision | Rationale |
|---|---|
| React + Vite | Fast UI iteration, route-based screens, and a simple local API proxy |
| Flask blueprints | Clear separation between authentication and the three security phases |
| MongoDB | Flexible documents for findings, events, evidence, and incident timelines |
| Hybrid AI | Deterministic rules cover sparse labelled security data; ML handles event scoring |
| Isolation Forest + Random Forest | Combines anomaly detection with supervised threat confidence |
| ReportLab | Generates downloadable audit artefacts without a paid reporting service |
| Local event simulation | Demonstrates SOC workflows without AWS credentials |
| Optional LLM providers | Improves assistant phrasing while preserving a knowledge-base fallback |
| JWT + bcrypt | Local authentication without an external identity provider |

---

## 11. Authoritative project files

| File | What it defines |
|---|---|
| `backend/requirements.txt` | Main Python dependency ranges |
| `ai_service/requirements.txt` | Optional FastAPI sidecar dependency ranges |
| `frontend/package.json` | Frontend dependencies and npm scripts |
| `frontend/package-lock.json` | Resolved frontend dependency tree |
| `backend/.env.example` | Runtime settings and integration defaults |
| `frontend/vite.config.js` | Frontend host, port, proxy, and build chunks |
| `frontend/tailwind.config.js` | Tailwind content paths and theme |
| `backend/config/settings.py` | Environment-backed application configuration |

Related document: [ARCHITECTURE.md](./ARCHITECTURE.md)
