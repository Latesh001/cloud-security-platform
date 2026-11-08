"""AI Security Assistant.

Answers are grounded in the developer's own project data (scan report, findings,
threats, incidents) plus a curated knowledge base. Each question is routed by
intent so different questions never collapse into the same generic reply.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

import requests
from flask import current_app

from database.extensions import db, mongo_find_one
from database.models import ChatHistory, Incident, Project, SecurityReport, ThreatSummary
from ai.knowledge_base.content import (
    KNOWLEDGE_BASE, TAB_SUGGESTIONS, VIVA_ANSWERS,
)

STOP_WORDS = {
    "what", "why", "how", "does", "did", "the", "this", "that", "explain", "tell",
    "about", "with", "from", "into", "your", "you", "and", "for", "are", "was",
    "have", "has", "can", "should", "would", "could", "please", "give", "show",
    "mean", "means", "work", "works", "when", "which", "will", "into", "than",
}

# Explicit aliases so common phrasings map to the right knowledge entry.
TOPIC_ALIASES: Dict[str, Tuple[str, ...]] = {
    "sql injection": ("sql injection", "sqli", "sql inject"),
    "xss": ("xss", "cross site scripting", "cross-site scripting"),
    "csrf": ("csrf", "cross site request forgery", "cross-site request forgery"),
    "command injection": ("command injection", "os command", "shell injection", "rce"),
    "hardcoded secret": ("hardcoded secret", "hardcoded password", "hardcoded api", "secret key", "api key leaked"),
    "insecure deserialization": ("deserialization", "pickle", "unserialize"),
    "path traversal": ("path traversal", "directory traversal", "../", "lfi"),
    "weak hashing": ("weak hashing", "md5", "sha1", "sha-1"),
    "owasp": ("owasp", "owasp top 10", "top 10"),
    "mfa": ("mfa", "multi-factor", "2fa", "two factor"),
    "jwt": ("jwt", "json web token"),
    "bcrypt": ("bcrypt",),
    "encryption": ("encryption", "tls", "https encrypt"),
    "zero trust": ("zero trust",),
    "cloudtrail": ("cloudtrail",),
    "cloudwatch": ("cloudwatch",),
    "guardduty": ("guardduty", "guard duty"),
    "iam": ("iam permission", "iam policy", "aws iam"),
    "s3": ("s3 bucket", "amazon s3", "public s3"),
    "ec2": ("ec2", "security group"),
    "security hub": ("security hub",),
    "vpc flow logs": ("vpc flow", "flow logs"),
    "isolation forest": ("isolation forest",),
    "random forest": ("random forest",),
    "false positive": ("false positive", "false positives"),
    "user behaviour analytics": ("uba", "user behaviour", "user behavior"),
    "event correlation": ("event correlation", "correlation engine", "correlated"),
    "siem": ("siem",),
    "soar": ("soar",),
    "digital forensics": ("forensic", "forensics", "evidence collection"),
    "incident response": ("incident response", "ir process"),
    "mitre att&ck": ("mitre", "att&ck", "attack framework"),
    "credential theft": ("credential theft", "stolen credential"),
    "brute force": ("brute force", "bruteforce"),
    "data exfiltration": ("exfiltration", "data exfil"),
    "privilege escalation": ("privilege escalation", "priv esc"),
    "insider threat": ("insider threat",),
    "ddos": ("ddos", "denial of service"),
    "reconnaissance": ("reconnaissance", "recon "),
    "phase 1": ("phase 1", "phase1", "static assessment", "security assessment"),
    "phase 2": ("phase 2", "phase2", "threat detection", "runtime monitoring", "continuous monitoring"),
    "phase 3": ("phase 3", "phase3", "automated response", "incident response phase"),
    "security score": ("security score", "risk score", "my score", "scoring"),
    "project category": ("project category", "choose a category", "categories"),
    "decision engine": ("decision engine", "approval rule", "pending remediation"),
    "playbook": ("playbook", "response playbook"),
}

VIVA_MATCHERS = [
    (("three", "phase", "architecture", "design"), "three-phase"),
    (("threshold", "65", "sixty"), "threshold"),
    (("siem", "soar"), "siem vs soar"),
    (("isolation", "forest", "algorithm"), "isolation forest"),
    (("category", "categories", "domain"), "category"),
    (("hybrid", "rule-based", "rule based", "machine learning", "ml"), "hybrid"),
    (("simulate", "simulation", "aws", "deploy"), "simulate"),
    (("connect", "connected", "project id", "link"), "connect"),
    (("false positive", "false positives", "noise"), "false positive"),
    (("real aws", "integration", "future", "production"), "aws integration"),
]


class ChatbotService:
    # ------------------------------------------------------------------ public

    @staticmethod
    def get_suggested_questions(tab: str = "security") -> List[str]:
        return TAB_SUGGESTIONS.get(tab, TAB_SUGGESTIONS["security"])

    @staticmethod
    def answer(user_id: int, question: str, project_id: Optional[str] = None,
               tab: str = "security") -> Dict:
        question = (question or "").strip()
        if not question:
            return {"question": "", "answer": "Please type a question.", "category": "general",
                    "chat_id": None, "grounded_on": []}

        # If the user asks about "my project" without selecting one, use the latest.
        if not project_id and ChatbotService._wants_project_context(question):
            latest = Project.query.filter_by(user_id=user_id).order_by(
                Project.created_date.desc()
            ).first()
            if latest:
                project_id = latest.project_id

        context = ChatbotService.build_context(user_id, project_id)
        context["platform_handbook"] = ChatbotService._platform_handbook()
        intent = ChatbotService._detect_intent(question, tab)
        category = intent

        try:
            answer, source = ChatbotService._generate_answer(question, context, intent, tab)
        except Exception as exc:
            answer = (
                "I could not complete that answer just now. Please try again. "
                f"({exc.__class__.__name__})"
            )
            source = "error"

        chat_id = None
        try:
            chat = ChatHistory(
                user_id=user_id,
                project_id=project_id,
                question=question,
                answer=answer,
                category=category,
            )
            db.session.add(chat)
            db.session.commit()
            chat_id = chat.chat_id
        except Exception:
            db.session.rollback()

        return {
            "question": question,
            "answer": answer,
            "category": category,
            "chat_id": chat_id,
            "grounded_on": ChatbotService._context_labels(context),
            "intent": intent,
            "project_id": project_id,
            "source": source,
        }

    @staticmethod
    def build_context(user_id: int, project_id: Optional[str] = None) -> Dict:
        context: Dict = {
            "user_id": user_id,
            "project": None,
            "report": None,
            "findings": [],
            "all_projects": [],
            "threats": [],
            "incidents": [],
            "project_count": Project.query.filter_by(user_id=user_id).count(),
        }

        projects = Project.query.filter_by(user_id=user_id).order_by(
            Project.created_date.desc()
        ).limit(10).all()
        context["all_projects"] = [
            {
                "id": p.project_id,
                "name": p.project_name,
                "category": p.category,
                "score": p.security_score,
                "status": p.status,
                "monitoring": p.monitoring_enabled,
            }
            for p in projects
        ]

        if not project_id:
            return context

        project = Project.query.filter_by(project_id=project_id, user_id=user_id).first()
        if not project:
            return context

        context["project"] = {
            "id": project.project_id,
            "name": project.project_name,
            "category": project.category,
            "score": project.security_score,
            "status": project.status,
            "language": project.programming_language,
            "framework": project.framework,
            "monitoring": project.monitoring_enabled,
        }

        report = SecurityReport.query.filter_by(project_id=project_id).order_by(
            SecurityReport.created_date.desc()
        ).first()
        if report:
            context["report"] = {
                "score": report.score,
                "critical": report.critical,
                "high": report.high,
                "medium": report.medium,
                "low": report.low,
                "risk_level": report.risk_level,
                "status": report.approval_status,
                "recommendation": report.recommendation,
            }

        scan_log = mongo_find_one("scan_logs", {"projectId": project_id},
                                  sort=[("timestamp", -1)])
        if scan_log:
            order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            findings = sorted(scan_log.get("findings", []),
                              key=lambda f: order.get(f.get("severity"), 3))
            context["findings"] = findings[:15]
            context["technologies"] = scan_log.get("technologies") or {}
            context["detector_summary"] = scan_log.get("detectorSummary") or {}
            context["files_scanned"] = scan_log.get("filesScanned")

        context["threats"] = [
            {"type": t.threat_type, "severity": t.severity,
             "confidence": t.confidence, "status": t.status}
            for t in ThreatSummary.query.filter_by(project_id=project_id).order_by(
                ThreatSummary.created_date.desc()).limit(8).all()
        ]
        context["incidents"] = [
            {"id": i.incident_id, "threat": i.threat, "severity": i.severity,
             "status": i.status, "user": i.affected_user, "ip": i.source_ip,
             "confidence": i.confidence}
            for i in Incident.query.filter_by(project_id=project_id).order_by(
                Incident.created_time.desc()).limit(8).all()
        ]
        return context

    @staticmethod
    def get_history(user_id: int, limit: int = 30) -> List[Dict]:
        chats = ChatHistory.query.filter_by(user_id=user_id).order_by(
            ChatHistory.created_date.desc()
        ).limit(limit).all()
        return [{
            "chat_id": c.chat_id,
            "question": c.question,
            "answer": c.answer,
            "category": c.category,
            "project_id": c.project_id,
            "created_date": c.created_date.isoformat() if c.created_date else None,
        } for c in reversed(chats)]

    @staticmethod
    def clear_history(user_id: int) -> int:
        deleted = ChatHistory.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        return deleted

    # ----------------------------------------------------------- intent routing

    @staticmethod
    def _wants_project_context(question: str) -> bool:
        q = question.lower()
        return any(word in q for word in (
            "my project", "my score", "my report", "my finding", "my incident",
            "this project", "fix first", "why was my", "not approved", "improve my",
            "detected in my", "technologies were detected", "architecture",
            "lifecycle", "after i upload", "zip file",
        ))

    @staticmethod
    def _detect_intent(question: str, tab: str) -> str:
        if tab == "viva":
            return "viva"

        q = question.lower()

        # Specific knowledge topics first so "Explain Isolation Forest" is never
        # swallowed by the Phase 2 keyword list (that caused identical replies).
        topic = ChatbotService._match_topic(q)
        definition_cues = (
            "what is", "what's", "whats", "explain", "define", "definition",
            "tell me about", "how does", "how do", "meaning of", "difference between",
        )
        if topic and (
            any(c in q for c in definition_cues)
            or topic not in ("phase 1", "phase 2", "phase 3", "decision engine", "security score")
            or len(q.split()) <= 8
        ):
            # Route platform phase topics to dedicated phase handlers.
            if topic == "phase 1":
                return "phase1"
            if topic == "phase 2":
                return "phase2"
            if topic == "phase 3":
                return "phase3"
            if topic == "security score":
                return "score"
            if topic == "project category":
                return "category"
            return "concept"

        rules = [
            ("architecture", (
                "architecture", "three phase", "three-phase", "how do the three",
                "phases connect", "lifecycle", "workflow", "pipeline", "end to end",
                "end-to-end", "how does this platform", "project structure",
                "about this project", "about the project", "this fyp", "final year",
            )),
            ("score", (
                "security score", "my score", "risk score", "scoring", "above 90",
                "improve my score", "how is the score", "calculated",
            )),
            ("findings", (
                "fix first", "finding", "vulnerability", "vulnerabilities",
                "what should i fix", "critical finding", "not approved", "remediation",
                "why was my project",
            )),
            ("upload", (
                "upload", "zip", "extract", "after i upload", "scan process",
            )),
            ("category", (
                "project category", "choose a category", "categories",
            )),
            ("technology", (
                "technolog", "language", "framework", "stack detected",
            )),
            ("phase1", ("phase 1", "phase1", "static assessment", "security assessment")),
            ("phase2", (
                "phase 2", "phase2", "continuous monitoring", "runtime monitoring",
                "threat detection", "confidence threshold",
            )),
            ("phase3", (
                "phase 3", "phase3", "playbook", "automated response",
                "forensic evidence", "containment action",
            )),
            ("incident", ("incident", "inc0", "inc1", "inc2", "inc3", "inc4", "inc5")),
            ("threat", ("threat detected", "anomaly", "prediction", "validated threat")),
        ]
        for name, keywords in rules:
            if any(k in q for k in keywords):
                return name

        if topic:
            return "concept"

        # Never force every unmatched security question into the same findings reply.
        return "general"

    @staticmethod
    def _context_labels(context: Dict) -> List[str]:
        labels = ["Knowledge Base"]
        if context.get("project"):
            labels.append(f"Project {context['project']['id']}")
        if context.get("report"):
            labels.append("Security Report")
        if context.get("findings"):
            labels.append("Scan Findings")
        if context.get("threats"):
            labels.append("Threat Detections")
        if context.get("incidents"):
            labels.append("Incident History")
        if context.get("platform_handbook"):
            labels.append("Platform documentation")
        return labels

    # -------------------------------------------------------------- answering

    @staticmethod
    def _grounded_answer(question: str, context: Dict, intent: str) -> str:
        q = question.lower()

        if intent == "viva":
            return ChatbotService._viva_answer(question, context)

        handlers = {
            "architecture": ChatbotService._architecture_answer,
            "score": ChatbotService._score_answer,
            "findings": ChatbotService._findings_answer,
            "upload": ChatbotService._upload_answer,
            "category": ChatbotService._category_answer,
            "technology": ChatbotService._technology_answer,
            "phase1": lambda qq, ctx: ChatbotService._phase_answer(qq, ctx, "phase 1"),
            "phase2": lambda qq, ctx: ChatbotService._phase_answer(qq, ctx, "phase 2"),
            "phase3": lambda qq, ctx: ChatbotService._phase_answer(qq, ctx, "phase 3"),
            "incident": ChatbotService._incident_answer,
            "threat": ChatbotService._threat_answer,
            "concept": ChatbotService._concept_answer,
            "general": ChatbotService._general_answer,
        }
        handler = handlers.get(intent)
        if handler:
            answer = handler(q, context)
            if answer:
                return answer

        # Concept match as secondary path.
        topic = ChatbotService._match_topic(q)
        if topic:
            return ChatbotService._format_topic(topic, context)

        return ChatbotService._fallback(context, intent)

    @staticmethod
    def _match_topic(question: str) -> Optional[str]:
        q = question.lower()
        best_key, best_score = None, 0

        for key, aliases in TOPIC_ALIASES.items():
            score = 0
            for alias in aliases:
                if alias in q:
                    # Longer / more specific aliases win.
                    score = max(score, 10 + len(alias.split()) * 2)
            if key in KNOWLEDGE_BASE and key in q:
                score = max(score, 12 + len(key.split()) * 2)

            # Require a solid match — avoid weak single-token collisions.
            if score > best_score:
                best_key, best_score = key, score

        return best_key if best_score >= 10 else None

    @staticmethod
    def _format_topic(topic: str, context: Dict) -> str:
        entry = KNOWLEDGE_BASE[topic]
        title_map = {
            "xss": "XSS (Cross-Site Scripting)",
            "csrf": "CSRF",
            "sql injection": "SQL Injection",
            "owasp": "OWASP Top 10",
            "mfa": "MFA",
            "jwt": "JWT",
            "iam": "IAM",
            "s3": "Amazon S3",
            "ec2": "Amazon EC2",
            "siem": "SIEM",
            "soar": "SOAR",
            "ddos": "DDoS",
            "mitre att&ck": "MITRE ATT&CK",
        }
        title = title_map.get(topic, topic.title())
        lines = [
            f"**{title}**",
            "",
            entry["definition"],
            "",
            f"**Why it matters**\n{entry['impact']}",
            "",
            f"**Recommendation**\n{entry['fix']}",
            "",
            f"**Reference**\n{entry['reference']}",
        ]

        # Project-specific deep dive for how this topic is used in THIS platform.
        platform_notes = {
            "isolation forest": (
                "In this FYP, Isolation Forest runs in Phase 2 on engineered cloud-event features "
                "(login bursts, failed auth, unusual API volume, geo jumps, etc.). Anomalies are "
                "candidates; Random Forest then assigns a class and confidence before escalation."
            ),
            "random forest": (
                "In Phase 2, Random Forest turns anomalous feature vectors into a labelled threat "
                "type plus a confidence percentage. Only high-confidence predictions become "
                "Validated threats that open Phase 3 incidents."
            ),
            "sql injection": (
                "Phase 1 static detectors look for unsafe SQL concatenation / string formatting "
                "in uploaded source. Critical SQLi findings heavily reduce the security score "
                "and keep the project in Pending Remediation until fixed and rescanned."
            ),
            "xss": (
                "Phase 1 flags unescaped output sinks and dangerous DOM APIs in web projects. "
                "Remediate encoding/CSP issues, then re-upload so the Decision Engine can approve monitoring."
            ),
            "hardcoded secret": (
                "Secret scanners in Phase 1 search for API keys, passwords, and tokens in source "
                "and configs. Exposed secrets are usually Critical — rotate them outside git and remove from the ZIP."
            ),
            "phase 1": (
                "Gate for the whole pipeline: upload ZIP → scan → score → approve/remediate. "
                "Only approved projects unlock Phase 2 monitoring."
            ),
            "phase 2": (
                "Continuous monitoring after approval. Events are simulated (no live AWS required), "
                "normalized, scored by AI, correlated into attack chains, and escalated when confident."
            ),
            "phase 3": (
                "Automated incident response: playbook selection, simulated containment, evidence pack, "
                "and PDF report — all tied back to the same Project ID from Phase 1."
            ),
            "security score": (
                "Shown on the dashboard and project report. It is residual risk after diminishing "
                "penalties — not a simple linear deduction that always hits zero."
            ),
            "siem": (
                "This platform acts like a lightweight SIEM+SOAR learning system: Phase 2 is detection "
                "(SIEM-like), Phase 3 is automated response (SOAR-like), linked by Project ID."
            ),
            "soar": (
                "Phase 3 is the SOAR-style layer: rule engine + playbooks + evidence, without "
                "touching real cloud resources (actions are simulated and logged)."
            ),
        }
        note = platform_notes.get(topic)
        if note:
            lines += ["", "**In this project (Cloud Security Platform)**", note]

        project = context.get("project")
        findings = context.get("findings") or []
        related = [
            f for f in findings
            if topic.split()[0] in (f.get("problem") or "").lower()
            or any(tok in (f.get("problem") or "").lower() for tok in topic.split() if len(tok) > 3)
        ]
        if project and related:
            lines += ["", f"**In your uploaded project ({project['id']} — {project['name']})**"]
            for finding in related[:5]:
                lines.append(
                    f"- [{finding.get('severity')}] {finding.get('problem')} in "
                    f"`{finding.get('file')}` line {finding.get('line')}"
                )
                if finding.get("solution"):
                    lines.append(f"  Fix: {finding['solution']}")
        elif project:
            lines += [
                "",
                f"**Your selected project context**",
                f"`{project['id']}` — {project['name']} · status `{project['status']}` · "
                f"score `{project['score']}/100` · category `{project['category']}`.",
            ]
        return "\n".join(lines)

    @staticmethod
    def _general_answer(question: str, context: Dict) -> str:
        """Last-resort smart reply — still unique to the question, never a blank template."""
        q = question.lower()
        if any(k in q for k in ("project", "platform", "fyp", "system", "architecture", "phase")):
            return ChatbotService._architecture_answer(question, context)
        topic = ChatbotService._match_topic(q)
        if topic:
            return ChatbotService._format_topic(topic, context)
        return ""

    # ---------------------------------------------------- detailed project answers

    @staticmethod
    def _architecture_answer(question: str, context: Dict) -> str:
        project = context.get("project")
        lines = [
            "**Cloud Security Platform — Three-Phase Architecture**",
            "",
            "This platform is an end-to-end security pipeline. Each phase has one job, "
            "and the Project ID links them across the UI, PostgreSQL/Mongo data, and reports.",
            "",
            "### Phase 1 — AI-Based Security Assessment",
            "- You upload a project ZIP (any internal file extensions are accepted).",
            "- Detectors scan secrets, insecure code, configs, IaC, and dependencies.",
            "- A security score (0–100) is produced with diminishing penalties so results stay readable.",
            "- Decision: Approved when residual risk is acceptable; otherwise Pending Remediation.",
            "",
            "### Phase 2 — Cloud Security Monitoring & AI Threat Detection",
            "- After approval, monitoring starts (auto-started when approved).",
            "- Simulated cloud events are normalized and scored by Isolation Forest + Random Forest.",
            "- High-confidence threats and correlated attack chains escalate forward.",
            "",
            "### Phase 3 — Automated Incident Response & Forensics",
            "- Validated threats become incidents.",
            "- A rule engine selects a response playbook (simulated containment actions).",
            "- Evidence, timeline, and a PDF incident report are generated.",
            "",
            "**How the phases connect:** Phase 1 gate → Phase 2 continuous detection → "
            "Phase 3 automated response. One Project ID ties scan reports, live threats, "
            "and incidents together on the dashboard analytics charts.",
        ]
        if project:
            lines += [
                "",
                f"**Applied to your project `{project['id']}` — {project['name']}**",
                f"- Category: {project['category']}",
                f"- Stack: {project.get('language') or 'n/a'} / {project.get('framework') or 'n/a'}",
                f"- Status: {project['status']}",
                f"- Security score: {project['score']}/100",
                f"- Monitoring enabled: {'Yes' if project.get('monitoring') else 'No'}",
            ]
            report = context.get("report")
            if report:
                lines.append(
                    f"- Latest findings: {report['critical']} critical, {report['high']} high, "
                    f"{report['medium']} medium, {report['low']} low (risk: {report['risk_level']})"
                )
            threats = context.get("threats") or []
            incidents = context.get("incidents") or []
            lines.append(f"- Phase 2 detections on record: {len(threats)}")
            lines.append(f"- Phase 3 incidents on record: {len(incidents)}")
        elif context.get("all_projects"):
            lines += ["", "**Your projects**"]
            for p in context["all_projects"][:5]:
                lines.append(
                    f"- `{p['id']}` {p['name']} — score {p['score']}/100 — {p['status']}"
                )
            lines.append("")
            lines.append("Select a project in the assistant Context dropdown for a deeper walkthrough.")
        return "\n".join(lines)

    @staticmethod
    def _score_answer(question: str, context: Dict) -> str:
        project = context.get("project")
        report = context.get("report")
        threshold = current_app.config.get("APPROVAL_SCORE_THRESHOLD", 65)

        lines = [
            "**How the Security Score Works**",
            "",
            "The score starts at **100**. Each finding adds a severity-based penalty. "
            "Repeated findings of the same type cost less than the first (diminishing returns), "
            "and total penalties are soft-saturated so busy scans do not always collapse to 0.",
            "",
            "- Critical findings weigh most heavily",
            "- High / Medium / Low add progressively smaller impact",
            "- Project category can amplify domain-critical issues (e.g. banking credentials)",
            "",
            f"Approval typically needs a score near **{threshold}+** with manageable residual critical risk, "
            "after which Phase 2 monitoring can run.",
        ]

        if not project:
            lines += [
                "",
                "Select your project in **Context** and ask again — I will explain *your* exact score and findings.",
            ]
            return "\n".join(lines)

        lines += [
            "",
            f"**Your project: {project['name']} (`{project['id']}`)**",
            f"- Current score: **{project['score']}/100**",
            f"- Status: {project['status']}",
            f"- Category: {project['category']}",
        ]
        if report:
            lines += [
                f"- Risk level: {report['risk_level']}",
                f"- Findings: {report['critical']} critical · {report['high']} high · "
                f"{report['medium']} medium · {report['low']} low",
                "",
            ]
            if report["critical"] > 2 and report["score"] < threshold:
                lines.append(
                    f"**Why monitoring may be blocked:** {report['critical']} critical findings "
                    f"and a score of {report['score']} keep the project in remediation."
                )
            elif project["status"] in ("Approved", "Monitoring Enabled"):
                lines.append(
                    "**Approved for monitoring.** Phase 2 can (or already did) start continuous detection."
                )
            else:
                gap = max(0, round(threshold - float(report["score"] or 0), 1))
                lines.append(
                    f"**To reach approval:** reduce residual risk — roughly {gap} score points "
                    "and/or clear excess critical findings, then rescan."
                )

        findings = context.get("findings") or []
        if findings:
            lines += ["", "**Highest-impact fixes for your score**"]
            for index, finding in enumerate(findings[:6], 1):
                lines.append(
                    f"{index}. **[{finding.get('severity')}] {finding.get('problem')}** "
                    f"in `{finding.get('file')}` (line {finding.get('line')})"
                )
                if finding.get("explanation"):
                    lines.append(f"   - Why: {finding['explanation'][:220]}")
                if finding.get("solution"):
                    lines.append(f"   - Fix: {finding['solution']}")
                if finding.get("reference"):
                    lines.append(f"   - Ref: {finding['reference']}")
        return "\n".join(lines)

    @staticmethod
    def _findings_answer(question: str, context: Dict) -> str:
        project = context.get("project")
        findings = context.get("findings") or []
        report = context.get("report")

        if not project:
            return (
                "**Findings help**\n\n"
                "Select a project in the Context dropdown, then ask \"What should I fix first?\" "
                "I will list your Critical/High findings with file paths and remediations."
            )

        lines = [
            f"**Security findings for {project['name']} (`{project['id']}`)**",
            "",
            f"Status: {project['status']} · Score: {project['score']}/100 · Category: {project['category']}",
        ]
        if report:
            lines.append(
                f"Breakdown: {report['critical']} critical, {report['high']} high, "
                f"{report['medium']} medium, {report['low']} low (risk {report['risk_level']})."
            )
        det = context.get("detector_summary") or {}
        if det:
            lines.append("Detectors that fired: " + ", ".join(f"{k} ({v})" for k, v in det.items()))

        if not findings:
            lines += [
                "",
                "No detailed findings are stored yet. Upload/rescan a ZIP so Phase 1 can populate the report.",
            ]
            return "\n".join(lines)

        lines += ["", "**Prioritized remediation plan**"]
        for index, finding in enumerate(findings[:10], 1):
            lines.append(
                f"\n### {index}. [{finding.get('severity')}] {finding.get('problem')}"
            )
            lines.append(f"- File: `{finding.get('file')}` line {finding.get('line')}")
            lines.append(f"- Detector: {finding.get('detector', 'n/a')}")
            if finding.get("explanation"):
                lines.append(f"- Explanation: {finding['explanation']}")
            if finding.get("solution"):
                lines.append(f"- How to fix: {finding['solution']}")
            if finding.get("reference"):
                lines.append(f"- Reference: {finding['reference']}")
            if finding.get("snippet"):
                snippet = str(finding["snippet"]).strip()[:160]
                lines.append(f"- Snippet: `{snippet}`")

        lines += [
            "",
            "**Next step:** fix Critical items first, rescan the ZIP, then confirm the score and approval status.",
        ]
        return "\n".join(lines)

    @staticmethod
    def _upload_answer(question: str, context: Dict) -> str:
        lines = [
            "**What happens after you upload a ZIP**",
            "",
            "1. **Validate** — size, Zip Slip, zip bombs, and encryption are checked. "
            "File extensions inside the archive are *not* blocked (`.bat`, `.exe`, etc. are scanned).",
            "2. **Extract safely** — each entry is confined to the project folder; dependency trees "
            "like `.venv` / `node_modules` are skipped for speed.",
            "3. **Detect technology** — language and framework fingerprints are recorded.",
            "4. **Run five detectors** — secrets, static code, configs, infrastructure, dependencies.",
            "5. **Score & decide** — produce the security score, PDF report, and Approved / Pending Remediation.",
            "6. **Pipeline hand-off** — if approved, Phase 2 monitoring is enabled and auto-started; "
            "validated threats later become Phase 3 incidents.",
        ]
        project = context.get("project")
        if project:
            lines += [
                "",
                f"**Your project `{project['id']}`:** currently `{project['status']}` "
                f"with score `{project['score']}/100`.",
            ]
            if context.get("files_scanned"):
                lines.append(f"Last scan covered **{context['files_scanned']}** files.")
        return "\n".join(lines)

    @staticmethod
    def _category_answer(question: str, context: Dict) -> str:
        entry = KNOWLEDGE_BASE.get("project category", {})
        lines = [
            "**Why project category matters**",
            "",
            entry.get("definition", ""),
            "",
            f"**Impact:** {entry.get('impact', '')}",
            "",
            f"**Guidance:** {entry.get('fix', '')}",
        ]
        project = context.get("project")
        if project:
            lines += [
                "",
                f"Your project `{project['id']}` is categorized as **{project['category']}**, "
                "so domain-sensitive issues (e.g. credentials in financial apps) receive higher weight.",
            ]
        return "\n".join(lines)

    @staticmethod
    def _technology_answer(question: str, context: Dict) -> str:
        project = context.get("project")
        tech = context.get("technologies") or {}
        if not project:
            return (
                "Select a project in Context, then ask again. I will list the languages, "
                "frameworks, and dependency signals Phase 1 detected from your ZIP."
            )
        lines = [
            f"**Technologies detected in {project['name']} (`{project['id']}`)**",
            "",
            f"- Primary language: {project.get('language') or tech.get('primary_language') or 'Not detected'}",
            f"- Framework: {project.get('framework') or 'General'}",
        ]
        frameworks = tech.get("frameworks") or []
        if frameworks:
            lines.append("- Frameworks: " + ", ".join(frameworks))
        languages = tech.get("languages") or tech.get("language_counts") or {}
        if isinstance(languages, dict) and languages:
            lines.append("- Language signals: " + ", ".join(f"{k} ({v})" for k, v in list(languages.items())[:8]))
        elif isinstance(languages, list) and languages:
            lines.append("- Languages: " + ", ".join(languages))
        lines += [
            "",
            "Technology detection helps detectors pick the right rule packs "
            "(e.g. Python vs JavaScript static checks) and shows on the project detail page.",
        ]
        return "\n".join(lines)

    @staticmethod
    def _phase_answer(question: str, context: Dict, phase_key: str) -> str:
        base = ChatbotService._format_topic(phase_key, context)
        project = context.get("project")
        extra: List[str] = []
        if project:
            if phase_key == "phase 1":
                report = context.get("report")
                extra = [
                    "",
                    f"**Your Phase 1 status for `{project['id']}`**",
                    f"- Score {project['score']}/100 · Status {project['status']}",
                ]
                if report:
                    extra.append(
                        f"- Findings {report['critical']}/{report['high']}/{report['medium']}/{report['low']} "
                        f"(C/H/M/L) · Risk {report['risk_level']}"
                    )
            elif phase_key == "phase 2":
                threats = context.get("threats") or []
                extra = [
                    "",
                    f"**Your Phase 2 status for `{project['id']}`**",
                    f"- Monitoring enabled: {'Yes' if project.get('monitoring') else 'No'}",
                    f"- Recent detections: {len(threats)}",
                ]
                for threat in threats[:5]:
                    extra.append(
                        f"  - {threat['type']} ({threat['severity']}) "
                        f"{threat['confidence']}% — {threat['status']}"
                    )
            elif phase_key == "phase 3":
                incidents = context.get("incidents") or []
                extra = [
                    "",
                    f"**Your Phase 3 status for `{project['id']}`**",
                    f"- Incidents on record: {len(incidents)}",
                ]
                for incident in incidents[:5]:
                    extra.append(
                        f"  - `{incident['id']}` {incident['threat']} "
                        f"({incident['severity']}) — {incident['status']}"
                    )
        return base + ("\n".join(extra) if extra else "")

    @staticmethod
    def _incident_answer(question: str, context: Dict) -> str:
        incidents = context.get("incidents") or []
        project = context.get("project")
        if not incidents:
            msg = [
                "**Incidents (Phase 3)**",
                "",
                "No incidents are recorded yet for this context. Incidents appear after Phase 2 "
                "validates a high-confidence threat or a correlated attack chain.",
            ]
            if project and not project.get("monitoring"):
                msg.append(
                    f"Project `{project['id']}` does not have monitoring enabled — complete Phase 1 approval first."
                )
            return "\n".join(msg)

        match = re.search(r"(inc[\-_ ]?\d+)", question, re.IGNORECASE)
        if match:
            wanted = re.sub(r"[\s\-_]", "", match.group(1)).upper()
            target = next(
                (i for i in incidents if re.sub(r"[\s\-_]", "", i["id"]).upper() == wanted),
                None,
            )
            if target:
                knowledge = KNOWLEDGE_BASE.get((target["threat"] or "").lower())
                # fuzzy threat topic
                if not knowledge:
                    threat_topic = ChatbotService._match_topic(target["threat"] or "")
                    knowledge = KNOWLEDGE_BASE.get(threat_topic or "", {})
                lines = [
                    f"**Incident {target['id']} — detailed explanation**",
                    "",
                    f"- Threat: **{target['threat']}**",
                    f"- Severity: {target['severity']}",
                    f"- AI confidence: {target['confidence']}%",
                    f"- Affected user: {target.get('user') or 'n/a'}",
                    f"- Source IP: {target.get('ip') or 'n/a'}",
                    f"- Status: {target['status']}",
                    "",
                    "Phase 3 selected a response playbook for this threat, executed **simulated** "
                    "containment actions, preserved forensic evidence, and generated an incident report.",
                ]
                if knowledge:
                    lines += [
                        "",
                        f"**What {target['threat']} means**",
                        knowledge.get("definition", ""),
                        "",
                        f"**Impact**\n{knowledge.get('impact', '')}",
                        "",
                        f"**How to prevent recurrence**\n{knowledge.get('fix', '')}",
                    ]
                return "\n".join(lines)

        lines = ["**Your recent Phase 3 incidents**", ""]
        for incident in incidents:
            lines.append(
                f"- `{incident['id']}` **{incident['threat']}** "
                f"({incident['severity']}, {incident['confidence']}%) — {incident['status']}"
            )
        lines += [
            "",
            f"Ask for a deep dive, e.g. \"Explain incident {incidents[0]['id']}\".",
        ]
        return "\n".join(lines)

    @staticmethod
    def _threat_answer(question: str, context: Dict) -> str:
        threats = context.get("threats") or []
        threshold = current_app.config.get("THREAT_CONFIDENCE_THRESHOLD", 85)
        project = context.get("project")

        lines = [
            "**Phase 2 AI Threat Detection**",
            "",
            "Cloud events are normalized into features, then scored by a hybrid model:",
            "- **Isolation Forest** flags anomalous behaviour",
            "- **Random Forest** estimates threat class and confidence",
            f"- Predictions at or above **{threshold}%** become Validated threats and escalate to Phase 3",
            "- Lower-confidence anomalies stay Observations (noise control)",
            "- Correlation can also escalate multi-step attack chains",
        ]
        if project:
            lines += [
                "",
                f"**Detections on `{project['id']}`** "
                f"(monitoring {'ON' if project.get('monitoring') else 'OFF'}):",
            ]
            if not threats:
                lines.append("- None yet. Keep monitoring running to accumulate detections.")
            for threat in threats:
                lines.append(
                    f"- {threat['type']} · {threat['severity']} · "
                    f"{threat['confidence']}% · {threat['status']}"
                )
        return "\n".join(lines)

    @staticmethod
    def _concept_answer(question: str, context: Dict) -> str:
        topic = ChatbotService._match_topic(question)
        if topic:
            return ChatbotService._format_topic(topic, context)
        return ""

    @staticmethod
    def _viva_answer(question: str, context: Dict) -> str:
        q = question.lower()
        for keywords, key in VIVA_MATCHERS:
            if sum(1 for keyword in keywords if keyword in q) >= 1 and (
                any(k in q for k in keywords[:2]) or key.replace("-", " ") in q
            ):
                # Prefer stronger overlap
                hits = sum(1 for keyword in keywords if keyword in q)
                if hits >= 1:
                    answer = VIVA_ANSWERS[key]
                    project = context.get("project")
                    tail = ""
                    if project:
                        tail = (
                            f"\n\n---\n\n**Tie it to your demo:** project `{project['id']}` "
                            f"({project['name']}) is currently `{project['status']}` "
                            f"with score `{project['score']}/100`."
                        )
                    return (
                        f"**Model viva answer**\n\n{answer}\n\n---\n\n"
                        "**Tip:** lead with the decision, then the reason, then the trade-off."
                        f"{tail}"
                    )

        # Rank viva matchers by hit count
        best_key, best_hits = None, 0
        for keywords, key in VIVA_MATCHERS:
            hits = sum(1 for keyword in keywords if keyword in q)
            if hits > best_hits:
                best_key, best_hits = key, hits
        if best_key and best_hits >= 1:
            answer = VIVA_ANSWERS[best_key]
            return (
                f"**Model viva answer**\n\n{answer}\n\n---\n\n"
                "**Tip:** lead with the decision, then the reason, then the trade-off."
            )

        topic = ChatbotService._match_topic(q)
        if topic:
            return ChatbotService._format_topic(topic, context)

        return (
            "**Viva preparation**\n\n"
            "Ask any of these for a model answer you can defend:\n\n"
            "1. Three-phase architecture and why phases are separated\n"
            "2. Why the score threshold is 65\n"
            "3. SIEM vs SOAR in this project\n"
            "4. Why Isolation Forest for threat detection\n"
            "5. How project category changes recommendations\n"
            "6. Hybrid rule-based + AI design\n"
            "7. Why cloud events are simulated\n"
            "8. How Project ID connects all phases\n"
            "9. How false positives are reduced\n"
            "10. What real AWS integration would change\n"
        )

    @staticmethod
    def _fallback(context: Dict, intent: str = "general") -> str:
        project = context.get("project")
        lines = [
            "I could not map that exact phrasing, but I can still help with a detailed answer.",
            "",
            "**Try asking more specifically, for example:**",
            "- Explain my project architecture",
            "- Explain my security score",
            "- What should I fix first?",
            "- How do Phase 1, Phase 2, and Phase 3 work?",
            "- What is SQL Injection?",
            "- Explain my recent incidents",
        ]
        if project:
            lines += [
                "",
                f"Context is set to **{project['name']} (`{project['id']}`)** — "
                f"score {project['score']}/100, status {project['status']}.",
                "Ask about this project's score, findings, threats, or incidents for a grounded explanation.",
            ]
        else:
            lines += [
                "",
                "Select a project in the Context dropdown for answers grounded in your scan results.",
            ]
        return "\n".join(lines)

    # -------------------------------------------------------------------- LLM

    GEMINI_FALLBACK_MODELS = (
        "gemini-3.5-flash-lite",
        "gemini-3.1-flash-lite",
        "gemini-3.8-flash",
    )

    _HANDBOOK_CACHE = None

    @staticmethod
    def _platform_handbook() -> Dict[str, str]:
        """Full local design docs so Gemini can answer any question about this product."""
        if ChatbotService._HANDBOOK_CACHE is not None:
            return ChatbotService._HANDBOOK_CACHE

        base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        docs = {}
        for name in ("ARCHITECTURE.md", "TECH_STACK.md", "README.md"):
            path = os.path.join(base, name)
            try:
                with open(path, encoding="utf-8") as handle:
                    text = handle.read().strip()
                if len(text) > 24000:
                    text = text[:24000] + "\n\n[Document truncated for context size]"
                docs[name] = text
            except OSError:
                continue

        docs["product_facts"] = (
            "Product title: Cloud Security Monitoring and Automated Incident Response using AI.\n"
            "Local three-tier app: React+Vite UI on :5173, Flask API on :5000, MongoDB on :27017 "
            "(database cloud_security_db).\n"
            "Start: CloudSecurityPlatform\\scripts\\start-platform.ps1 or "
            "backend `python app.py` plus frontend `npm run dev`.\n"
            "Phase 1: ZIP upload, five detectors (secrets, code, config, infrastructure, "
            "dependencies), score 0-100, approve at 65 with zero criticals.\n"
            "Phase 2: simulated CloudTrail events, Isolation Forest + Random Forest, "
            "escalate at 85% confidence.\n"
            "Phase 3: incident, playbook (simulated), evidence, timeline, full PDF report.\n"
            "Auth: JWT + bcrypt. Assistant: Google Gemini with knowledge-base fallback.\n"
            "Containment actions are simulated and never change a real cloud account.\n"
            "Key files: backend/app.py, backend/phase1, backend/phase2, backend/phase3, "
            "backend/ai/chatbot, frontend/src/pages, ARCHITECTURE.md, TECH_STACK.md."
        )
        ChatbotService._HANDBOOK_CACHE = docs
        return docs

    @staticmethod
    def _compact_llm_context(question: str, context: Dict, intent: str, tab: str) -> str:
        """Small grounding payload so Gemini is not flooded and still answers general questions."""
        handbook = context.get("platform_handbook") or {}
        q = (question or "").lower()
        wants_platform = any(token in q for token in (
            "this project", "this product", "this platform", "phase 1", "phase 2",
            "phase 3", "architecture", "tech stack", "mongodb", "flask", "vite",
            "isolation forest", "random forest", "playbook", "viva", "how do i run",
            "start the", "cloud security",
        ))
        payload = {
            "assistant_tab": tab,
            "detected_intent": intent,
            "developer_projects": context.get("all_projects") or [],
            "selected_project": context.get("project"),
            "selected_report": context.get("report"),
            "findings": (context.get("findings") or [])[:12],
            "threats": (context.get("threats") or [])[:8],
            "incidents": (context.get("incidents") or [])[:8],
        }
        if wants_platform:
            payload["product_facts"] = handbook.get("product_facts")
            architecture = handbook.get("ARCHITECTURE.md") or ""
            if architecture:
                payload["architecture_excerpt"] = architecture[:2500]
        return json.dumps(payload, default=str, ensure_ascii=False)

    @staticmethod
    def _generate_answer(question: str, context: Dict, intent: str, tab: str) -> Tuple[str, str]:
        """Gemini first for any question, then OpenAI, then the local knowledge base."""
        provider = (current_app.config.get("LLM_PROVIDER") or "auto").strip().lower()
        gemini_key = (current_app.config.get("GEMINI_API_KEY") or "").strip()
        openai_key = (current_app.config.get("OPENAI_API_KEY") or "").strip()

        try_gemini = provider in ("auto", "gemini") and bool(gemini_key)
        try_openai = provider in ("auto", "openai") and bool(openai_key)

        if try_gemini:
            answer = ChatbotService._gemini_answer(question, context, intent, tab, gemini_key)
            if answer:
                return answer, "gemini"

        if try_openai:
            answer = ChatbotService._openai_answer(question, context, intent, tab, openai_key)
            if answer:
                return answer, "openai"

        grounded = ChatbotService._grounded_answer(question, context, intent)
        if try_gemini and not gemini_key:
            return (
                grounded + "\n\n_Note: GEMINI_API_KEY is not set, so this reply used the local knowledge base._",
                "knowledge_base",
            )
        if try_gemini:
            return (
                grounded
                + "\n\n_Note: Google Gemini did not return a reply just now, so this used the local knowledge base. "
                "General questions need a working GEMINI_API_KEY._",
                "knowledge_base",
            )
        return grounded, "knowledge_base"

    @staticmethod
    def _assistant_system_prompt() -> str:
        from ai.chatbot.gemini_client import GENERAL_SYSTEM_PROMPT
        return GENERAL_SYSTEM_PROMPT

    @staticmethod
    def _llm_user_prompt(question: str, context: Dict, intent: str, tab: str) -> str:
        return ChatbotService._compact_llm_context(question, context, intent, tab)

    @staticmethod
    def _gemini_answer(question: str, context: Dict, intent: str, tab: str, api_key: str) -> Optional[str]:
        from ai.chatbot.gemini_client import answer_any

        model = (current_app.config.get("GEMINI_MODEL") or "gemini-3.5-flash-lite").strip()
        extra = ChatbotService._compact_llm_context(question, context, intent, tab)
        result = answer_any(question, api_key, model=model, extra_context=extra)
        if result.get("ok") and result.get("text"):
            return result["text"]
        return None

    @staticmethod
    def _openai_answer(question: str, context: Dict, intent: str, tab: str, api_key: str) -> Optional[str]:
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}",
                         "Content-Type": "application/json"},
                json={
                    "model": current_app.config.get("OPENAI_MODEL", "gpt-4o-mini"),
                    "messages": [
                        {"role": "system", "content": ChatbotService._assistant_system_prompt()},
                        {"role": "user", "content": ChatbotService._llm_user_prompt(question, context, intent, tab)},
                    ],
                    "max_tokens": 1600,
                    "temperature": 0.4,
                },
                timeout=45,
            )
            if response.status_code == 200:
                text = response.json()["choices"][0]["message"]["content"]
                return (text or "").strip() or None
        except (requests.RequestException, KeyError, ValueError, IndexError):
            return None
        return None

    @staticmethod
    def _llm_answer(question: str, context: Dict, intent: str, api_key: str) -> str:
        """Kept for callers that still pass an OpenAI key directly."""
        answer = ChatbotService._openai_answer(question, context, intent, "security", api_key)
        return answer or ChatbotService._grounded_answer(question, context, intent)
