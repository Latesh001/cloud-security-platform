"""Phase 3 incident PDF report.

Builds a complete forensic report from the incident record, project metadata,
playbook responses, MongoDB evidence, timeline, and AI prediction — not just
the handful of header fields.
"""
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from database.extensions import mongo_find_one
from database.models import Incident, Project, Response

HEADER_BG = colors.HexColor("#0f172a")
ACCENT = colors.HexColor("#1e3a5f")
ROW_ALT = colors.HexColor("#f0f4f8")
SEVERITY_COLORS = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#9a3412"),
    "Medium": colors.HexColor("#854d0e"),
    "Low": colors.HexColor("#1e3a8a"),
}

THREAT_NARRATIVE = {
    "Credential Theft": (
        "An identity credential was created, stolen, or reused. An attacker who holds a "
        "valid key or password can impersonate the user and move laterally without triggering "
        "simple login-failure alerts."
    ),
    "Brute Force": (
        "Repeated failed authentication attempts were observed against the same identity. "
        "This pattern typically precedes account takeover if lockout and MFA are not enforced."
    ),
    "Brute Force Attack": (
        "Repeated failed authentication attempts were observed against the same identity. "
        "This pattern typically precedes account takeover if lockout and MFA are not enforced."
    ),
    "Data Exfiltration": (
        "A large or unusual outbound data transfer was detected. Sensitive project or cloud "
        "data may have been copied off the environment."
    ),
    "Privilege Escalation": (
        "An IAM policy, role, or permission change granted broader access than expected. "
        "This is a common step in turning a foothold into administrative control."
    ),
    "Configuration Tampering": (
        "A security-relevant cloud configuration was modified or deleted. The change can "
        "weaken isolation, logging, or access control."
    ),
    "Public Resource Exposure": (
        "A resource was opened to the public internet (for example a security-group or "
        "storage change). Public exposure greatly increases the attack surface."
    ),
    "Insider Threat": (
        "Privileged activity from an internal identity did not match the expected pattern. "
        "The actor may be a compromised insider account or a malicious privileged user."
    ),
    "Suspicious Login": (
        "A login event was unusual in time, location, client, or MFA state. It may be a "
        "stolen session or an attacker testing valid credentials."
    ),
    "Suspicious API Usage": (
        "An API or role-assumption call was inconsistent with normal project activity and "
        "was treated as a high-risk reconnaissance or staging action."
    ),
    "Suspicious Activity": (
        "The detector flagged activity that does not match a single named playbook but "
        "still exceeds the confidence threshold for automated response."
    ),
    "Malware Activity": (
        "Behaviour consistent with malware execution or staging was observed on a monitored "
        "resource. Containment and forensic capture are required."
    ),
}

RECOMMENDATIONS = {
    "Credential Theft": {
        "immediate": [
            "Disable the affected identity and terminate active sessions.",
            "Rotate every access key, password, and token belonging to that identity.",
            "Force a password reset and require MFA before the account is re-enabled.",
        ],
        "containment": [
            "Revoke temporary credentials issued during the incident window.",
            "Review IAM policies attached to the user and remove unused privileges.",
        ],
        "prevention": [
            "Enforce MFA on every console and API identity.",
            "Replace long-lived access keys with short-lived roles.",
            "Alert on CreateAccessKey and UpdateLoginProfile events.",
        ],
    },
    "Brute Force": {
        "immediate": [
            "Temporarily lock the targeted account.",
            "Record and block the source IP at the edge or WAF.",
            "Notify the legitimate user of the failed-login burst.",
        ],
        "containment": [
            "Increase the account risk score and require MFA re-verification.",
            "Review other identities for the same source IP.",
        ],
        "prevention": [
            "Enable account lockout and CAPTCHA after repeated failures.",
            "Rate-limit authentication endpoints and monitor ConsoleLoginFailure volume.",
        ],
    },
    "Data Exfiltration": {
        "immediate": [
            "Suspend the download or transfer session.",
            "Block the source IP and quarantine the destination bucket or share.",
            "Preserve transfer logs and object-access records as evidence.",
        ],
        "containment": [
            "Review recent GetObject / LargeFileDownload activity for the same identity.",
            "Enable DLP or object-lock on sensitive buckets.",
        ],
        "prevention": [
            "Apply least-privilege download policies and alert on multi-GB transfers.",
            "Require MFA for high-volume data access.",
        ],
    },
    "Privilege Escalation": {
        "immediate": [
            "Revoke the newly granted permissions or attached policy.",
            "Audit IAM changes in the same time window.",
            "Notify the security team and the project owner.",
        ],
        "containment": [
            "Disable the identity that performed AttachUserPolicy / ModifyPolicy.",
            "Confirm CloudTrail (or equivalent) logging is still enabled.",
        ],
        "prevention": [
            "Require approval for IAM mutations and apply least privilege.",
            "Alert on policy changes that include wildcard actions or resources.",
        ],
    },
    "Configuration Tampering": {
        "immediate": [
            "Restore the last known-good configuration.",
            "Enable enhanced logging on the affected service.",
            "Generate this incident report for the change window.",
        ],
        "containment": [
            "Lock down who can DeleteBucket, TerminateInstances, or change security groups.",
        ],
        "prevention": [
            "Use infrastructure-as-code with change review.",
            "Alert on destructive configuration APIs.",
        ],
    },
    "Public Resource Exposure": {
        "immediate": [
            "Disable public access on the resource immediately.",
            "Mark the resource as critical until reviewed.",
        ],
        "containment": [
            "Scan for data that may have been reachable while public.",
        ],
        "prevention": [
            "Block 0.0.0.0/0 ingress by policy.",
            "Require a public-access block on storage accounts.",
        ],
    },
    "Insider Threat": {
        "immediate": [
            "Restrict the user's permissions to a minimum viable set.",
            "Enable detailed activity monitoring on that identity.",
            "Collect and retain forensic evidence before interviews.",
        ],
        "containment": [
            "Review other actions by the same user in the last 24 hours.",
        ],
        "prevention": [
            "Separate duties for privileged operations.",
            "Review privileged access on a fixed schedule.",
        ],
    },
    "Suspicious Login": {
        "immediate": [
            "Flag the session as high risk and require MFA re-verification.",
            "Record client, IP, country, and browser details.",
            "Notify the account owner.",
        ],
        "containment": [
            "Invalidate other sessions from the same IP if the login cannot be confirmed.",
        ],
        "prevention": [
            "Alert on logins from high-risk countries without MFA.",
            "Use geo and device baselines for each identity.",
        ],
    },
}

PLAYBOOK_LABELS = {
    "credential_theft": "Credential Theft Containment",
    "brute_force": "Brute-Force Containment",
    "data_exfiltration": "Data-Exfiltration Containment",
    "privilege_escalation": "Privilege-Escalation Containment",
    "malware": "Malware Quarantine",
    "suspicious_login": "Suspicious-Login Review",
    "config_tampering": "Configuration Restore",
    "public_exposure": "Public-Access Shutdown",
    "insider_threat": "Insider-Threat Restriction",
}


def _text(value, fallback="Not recorded"):
    if value is None or value == "":
        return fallback
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _esc(value, fallback="Not recorded"):
    return escape(_text(value, fallback))


def _fmt_dt(value):
    if not value:
        return "Not recorded"
    if hasattr(value, "isoformat"):
        try:
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            value = value.isoformat()
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return text


def _fmt_bytes(value):
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return "0 B"
    if number <= 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    return f"{number:.2f} {units[index]}"


def _duration(start, end):
    if not start:
        return "Not recorded"
    start_dt = start if hasattr(start, "timestamp") else None
    end_dt = end if hasattr(end, "timestamp") else None
    try:
        if start_dt is None:
            start_dt = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        if end_dt is None and end:
            end_dt = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        if end_dt is None:
            end_dt = datetime.now(timezone.utc)
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=timezone.utc)
        seconds = max(0, int((end_dt - start_dt).total_seconds()))
        hours, rem = divmod(seconds, 3600)
        minutes, secs = divmod(rem, 60)
        if hours:
            return f"{hours}h {minutes}m {secs}s"
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"
    except Exception:
        return "Not recorded"


class IncidentReportGenerator:
    @staticmethod
    def generate(incident: Incident) -> str:
        from phase3.rule_engine.engine import PLAYBOOK_MAP

        project = Project.query.get(incident.project_id)
        responses = Response.query.filter_by(incident_id=incident.incident_id).all()
        evidence = mongo_find_one("forensic_logs", {"incidentId": incident.incident_id}) or {}
        pack = mongo_find_one("incident_evidence", {"incidentId": incident.incident_id}) or {}
        timeline_doc = mongo_find_one("timeline_history", {"incidentId": incident.incident_id}) or {}
        timeline = timeline_doc.get("timeline") or []
        event = evidence.get("eventHistory") or pack.get("log") or {}
        prediction = pack.get("prediction") or {}
        playbook_key = PLAYBOOK_MAP.get(incident.threat, "suspicious_login")

        from utils.helpers import pdf_output_path
        report_path = pdf_output_path(
            f"{incident.project_id}_{incident.incident_id}_forensic_report.pdf"
        )

        styles = IncidentReportGenerator._styles()
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        elements = []

        elements.extend(IncidentReportGenerator._cover(incident, project, generated, styles))
        elements.extend(IncidentReportGenerator._executive_summary(
            incident, project, event, prediction, responses, styles,
        ))
        elements.append(IncidentReportGenerator._heading("1. Incident Identification", styles))
        elements.append(IncidentReportGenerator._kv_table([
            ("Incident ID", incident.incident_id),
            ("Status", incident.status),
            ("Threat category", incident.threat),
            ("Severity", incident.severity),
            ("AI confidence", f"{_text(incident.confidence, '0')}%"),
            ("Detected at", _fmt_dt(incident.created_time)),
            ("Resolved at", _fmt_dt(incident.resolved_time)),
            ("Time to contain", _duration(incident.created_time, incident.resolved_time)),
            ("Classification", "Confidential — Internal SOC Use"),
            ("Report generated", generated),
        ], styles))

        elements.append(IncidentReportGenerator._heading("2. Project Context", styles))
        elements.append(IncidentReportGenerator._kv_table([
            ("Project name", project.project_name if project else "Unknown"),
            ("Project ID", incident.project_id),
            ("Owner user ID", project.user_id if project else "Unknown"),
            ("Category", project.category if project else "Unknown"),
            ("Language / framework", (
                f"{_text(project.programming_language, 'Not detected')} / "
                f"{_text(project.framework, 'Not detected')}"
            ) if project else "Unknown"),
            ("Cloud provider", project.cloud_provider if project else "Unknown"),
            ("Phase 1 security score", f"{_text(project.security_score, '0')}/100" if project else "N/A"),
            ("Project status", project.status if project else "Unknown"),
            ("Monitoring enabled", "Yes" if project and project.monitoring_enabled else "No"),
        ], styles))

        elements.append(IncidentReportGenerator._heading("3. Threat Analysis", styles))
        narrative = THREAT_NARRATIVE.get(
            incident.threat,
            "The detection exceeded the configured confidence threshold and was escalated to Phase 3.",
        )
        elements.append(Paragraph(escape(narrative), styles["Body"]))
        elements.append(Spacer(1, 8))
        elements.append(IncidentReportGenerator._kv_table([
            ("Threat type", incident.threat),
            ("Severity", incident.severity),
            ("AI model used", prediction.get("modelUsed") or "Rule-based / recorded"),
            ("Confidence score", f"{_text(prediction.get('confidence', incident.confidence), '0')}%"),
            ("Escalation threshold", f"{_text(prediction.get('threshold'), '85')}%"),
            ("Forwarded to Phase 3", _text(prediction.get("isThreat"), "Yes")),
            ("Anomaly flagged", _text(prediction.get("isAnomaly"), "Yes")),
            ("Playbook selected", PLAYBOOK_LABELS.get(playbook_key, playbook_key)),
            ("Playbook key", playbook_key),
        ], styles))

        elements.append(IncidentReportGenerator._heading("4. Affected Assets and Event Details", styles))
        elements.append(IncidentReportGenerator._kv_table([
            ("Affected user", incident.affected_user or event.get("username")),
            ("Source IP", incident.source_ip or event.get("sourceIP")),
            ("Source country", evidence.get("country") or event.get("country")),
            ("Client / browser", evidence.get("browser") or event.get("browser")),
            ("Trigger event", evidence.get("eventType") or event.get("eventType")),
            ("Cloud resource", evidence.get("resource") or event.get("resource")),
            ("Log source", event.get("logType")),
            ("Event result", event.get("status")),
            ("MFA enabled", event.get("mfaEnabled")),
            ("Marked suspicious", event.get("isSuspicious")),
            ("Bytes transferred", _fmt_bytes(event.get("bytesTransferred"))),
            ("Event timestamp", _fmt_dt(event.get("timestamp") or evidence.get("timestamp"))),
        ], styles))

        elements.append(IncidentReportGenerator._heading("5. Incident Timeline", styles))
        if timeline:
            rows = [["#", "Time (UTC)", "Event", "Details"]]
            for index, entry in enumerate(timeline, start=1):
                rows.append([
                    str(index),
                    Paragraph(_esc(_fmt_dt(entry.get("time"))), styles["Cell"]),
                    Paragraph(_esc(entry.get("event")), styles["Cell"]),
                    Paragraph(_esc(entry.get("details"), "—"), styles["Cell"]),
                ])
            elements.append(IncidentReportGenerator._data_table(rows, [28, 130, 145, 215], styles))
        else:
            elements.append(Paragraph("No timeline was recorded for this incident.", styles["Body"]))

        elements.append(IncidentReportGenerator._heading("6. Response Playbook Actions", styles))
        elements.append(Paragraph(
            f"Playbook: <b>{escape(PLAYBOOK_LABELS.get(playbook_key, playbook_key))}</b>. "
            "Actions in this platform are <b>simulated</b> and stored as forensic evidence; "
            "no real cloud resource is modified.",
            styles["Body"],
        ))
        elements.append(Spacer(1, 8))
        if responses:
            rows = [["Step", "Action", "Result", "Executed"]]
            for index, response in enumerate(responses, start=1):
                rows.append([
                    str(index),
                    Paragraph(_esc(response.action), styles["Cell"]),
                    Paragraph(_esc(response.result), styles["Cell"]),
                    Paragraph(_esc(_fmt_dt(response.executed_time)), styles["Cell"]),
                ])
            elements.append(IncidentReportGenerator._data_table(rows, [40, 230, 130, 118], styles))
        else:
            elements.append(Paragraph(
                "No playbook actions have been executed yet.",
                styles["Body"],
            ))

        elements.append(IncidentReportGenerator._heading("7. Forensic Evidence", styles))
        elements.append(Paragraph(
            "Evidence is captured at response time and stored in MongoDB "
            "(<i>forensic_logs</i> and <i>incident_evidence</i>).",
            styles["Body"],
        ))
        elements.append(Spacer(1, 8))
        elements.append(IncidentReportGenerator._kv_table([
            ("Evidence record", evidence.get("_id") or pack.get("_id")),
            ("Captured at", _fmt_dt(evidence.get("timestamp") or pack.get("timestamp"))),
            ("Linked incident", evidence.get("incidentId") or incident.incident_id),
            ("Linked project", evidence.get("projectId") or incident.project_id),
            ("Recorded threat", evidence.get("threat") or incident.threat),
            ("Recorded severity", evidence.get("severity") or incident.severity),
            ("Recorded confidence", f"{_text(evidence.get('confidence', incident.confidence))}%"),
            ("Response actions captured", len(evidence.get("responseActions") or responses)),
        ], styles))

        raw_event = {k: v for k, v in event.items() if k != "_id"} if isinstance(event, dict) else {}
        if raw_event:
            elements.append(Spacer(1, 8))
            elements.append(Paragraph("<b>Raw triggering event</b>", styles["SubHead"]))
            rows = [["Field", "Value"]]
            for key in sorted(raw_event.keys(), key=lambda item: str(item)):
                value = raw_event[key]
                if key in ("bytesTransferred",):
                    display = _fmt_bytes(value)
                elif key in ("timestamp",):
                    display = _fmt_dt(value)
                else:
                    display = _text(value)
                rows.append([
                    Paragraph(_esc(key), styles["Cell"]),
                    Paragraph(_esc(display), styles["Cell"]),
                ])
            elements.append(IncidentReportGenerator._data_table(rows, [180, 338], styles))

        elements.append(IncidentReportGenerator._heading("8. Recommendations", styles))
        recs = RECOMMENDATIONS.get(incident.threat) or RECOMMENDATIONS.get(
            "Suspicious Login"
        )
        elements.append(Paragraph(
            "Recommendations follow the NIST incident-response lifecycle: immediate action, "
            "containment, then longer-term prevention.",
            styles["Body"],
        ))
        for title, items in (
            ("Immediate actions", recs["immediate"]),
            ("Containment and analysis", recs["containment"]),
            ("Prevention", recs["prevention"]),
        ):
            elements.append(Paragraph(f"<b>{title}</b>", styles["SubHead"]))
            for item in items:
                elements.append(Paragraph(f"• {escape(item)}", styles["Bullet"]))

        elements.append(IncidentReportGenerator._heading("9. Closure and Sign-off", styles))
        elements.append(IncidentReportGenerator._kv_table([
            ("Current status", incident.status),
            ("Containment complete", "Yes" if responses else "Pending"),
            ("Evidence preserved", "Yes" if evidence or pack else "No"),
            ("Timeline reconstructed", "Yes" if timeline else "No"),
            ("Resolved at", _fmt_dt(incident.resolved_time)),
            ("Next review", "Confirm preventive controls and keep monitoring enabled."),
        ], styles))
        elements.append(Spacer(1, 14))
        elements.append(Paragraph(
            "This report was generated by <b>Cloud Security Monitoring and Automated "
            "Incident Response using AI</b> (Phase 3). It is intended for the project "
            "owner and SOC review. Simulated containment actions are labelled as such "
            "and must not be treated as changes to a live cloud account.",
            styles["FooterNote"],
        ))

        doc = SimpleDocTemplate(
            report_path,
            pagesize=letter,
            leftMargin=0.7 * inch,
            rightMargin=0.7 * inch,
            topMargin=0.65 * inch,
            bottomMargin=0.65 * inch,
            title=f"Incident Report {incident.incident_id}",
            author="Cloud Security Platform",
        )
        doc.build(elements)
        from utils.helpers import archive_forensic_report
        archive_forensic_report(
            report_path,
            f"{incident.project_id}_{incident.incident_id}_forensic_report.pdf",
        )
        return report_path

    @staticmethod
    def _styles():
        base = getSampleStyleSheet()
        return {
            "Banner": ParagraphStyle(
                "Banner", parent=base["Title"], fontSize=16, leading=20,
                textColor=colors.white, alignment=TA_CENTER, spaceAfter=0,
            ),
            "BannerSub": ParagraphStyle(
                "BannerSub", parent=base["Normal"], fontSize=9, leading=12,
                textColor=colors.HexColor("#cbd5e1"), alignment=TA_CENTER,
            ),
            "Heading": ParagraphStyle(
                "IncHeading", parent=base["Heading2"], fontSize=12, leading=16,
                textColor=ACCENT, spaceBefore=14, spaceAfter=8,
            ),
            "SubHead": ParagraphStyle(
                "IncSubHead", parent=base["Normal"], fontSize=10, leading=13,
                textColor=ACCENT, spaceBefore=8, spaceAfter=4,
            ),
            "Body": ParagraphStyle(
                "IncBody", parent=base["Normal"], fontSize=9, leading=13,
                alignment=TA_JUSTIFY, spaceAfter=4,
            ),
            "Bullet": ParagraphStyle(
                "IncBullet", parent=base["Normal"], fontSize=9, leading=12,
                leftIndent=12, spaceAfter=2,
            ),
            "Cell": ParagraphStyle(
                "IncCell", parent=base["Normal"], fontSize=8, leading=11,
            ),
            "CellHead": ParagraphStyle(
                "IncCellHead", parent=base["Normal"], fontSize=8, leading=11,
                textColor=colors.white, fontName="Helvetica-Bold",
            ),
            "FooterNote": ParagraphStyle(
                "IncFooter", parent=base["Normal"], fontSize=8, leading=11,
                textColor=colors.HexColor("#475569"), alignment=TA_JUSTIFY,
            ),
        }

    @staticmethod
    def _cover(incident, project, generated, styles):
        severity_color = SEVERITY_COLORS.get(incident.severity, ACCENT)
        banner = Table(
            [[
                Paragraph("CLOUD SECURITY PLATFORM", styles["Banner"]),
            ], [
                Paragraph("Phase 3 — Automated Incident Response Report", styles["BannerSub"]),
            ]],
            colWidths=[518],
        )
        banner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), HEADER_BG),
            ("TOPPADDING", (0, 0), (-1, 0), 14),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 12),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ]))

        project_name = project.project_name if project else incident.project_id
        meta = Table(
            [[
                Paragraph(
                    f"<b>{escape(incident.incident_id)}</b>  ·  {escape(_text(incident.threat))}",
                    styles["Body"],
                ),
                Paragraph(
                    f"<b>{escape(_text(incident.severity))}</b>  ·  {escape(_text(incident.status))}",
                    styles["Body"],
                ),
            ], [
                Paragraph(f"Project: {escape(_text(project_name))}", styles["Body"]),
                Paragraph(f"Generated: {escape(generated)}", styles["Body"]),
            ]],
            colWidths=[320, 198],
        )
        meta.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), ROW_ALT),
            ("BOX", (0, 0), (-1, -1), 0.5, severity_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        return [
            banner,
            Spacer(1, 10),
            meta,
            Spacer(1, 6),
            HRFlowable(width="100%", thickness=1, color=severity_color),
        ]

    @staticmethod
    def _executive_summary(incident, project, event, prediction, responses, styles):
        project_name = project.project_name if project else incident.project_id
        model = prediction.get("modelUsed") or "the configured detector"
        summary = (
            f"On {_fmt_dt(incident.created_time)}, Phase 2 monitoring on project "
            f"<b>{escape(_text(project_name))}</b> ({escape(_text(incident.project_id))}) "
            f"classified a <b>{escape(_text(event.get('eventType'), 'cloud'))}</b> event as "
            f"<b>{escape(_text(incident.threat))}</b> with "
            f"<b>{escape(_text(incident.severity))}</b> severity and "
            f"<b>{escape(_text(incident.confidence))}%</b> confidence using {escape(_text(model))}. "
            f"The affected identity was <b>{escape(_text(incident.affected_user, 'unknown'))}</b> "
            f"from <b>{escape(_text(incident.source_ip, 'an unknown IP'))}</b>. "
            f"Phase 3 opened incident <b>{escape(_text(incident.incident_id))}</b>, "
            f"executed <b>{len(responses)}</b> simulated containment action"
            f"{'' if len(responses) == 1 else 's'}, and preserved forensic evidence. "
            f"Current status: <b>{escape(_text(incident.status))}</b>."
        )
        return [
            IncidentReportGenerator._heading("Executive Summary", styles),
            Paragraph(summary, styles["Body"]),
        ]

    @staticmethod
    def _heading(text, styles):
        return KeepTogether([
            Spacer(1, 4),
            Paragraph(escape(text), styles["Heading"]),
            HRFlowable(width="100%", thickness=0.4, color=colors.HexColor("#94a3b8")),
            Spacer(1, 6),
        ])

    @staticmethod
    def _kv_table(pairs, styles):
        rows = [[
            Paragraph("Attribute", styles["CellHead"]),
            Paragraph("Value", styles["CellHead"]),
        ]]
        for label, value in pairs:
            rows.append([
                Paragraph(escape(str(label)), styles["Cell"]),
                Paragraph(_esc(value), styles["Cell"]),
            ])
        return IncidentReportGenerator._data_table(rows, [200, 318], styles)

    @staticmethod
    def _data_table(rows, col_widths, styles):
        header = []
        for cell in rows[0]:
            if isinstance(cell, str):
                header.append(Paragraph(escape(cell), styles["CellHead"]))
            else:
                header.append(cell)
        body = [header] + rows[1:]
        table = Table(body, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table
