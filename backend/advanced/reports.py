"""Downloadable Advanced Features PDFs."""
import os
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from advanced import store

ACCENT = colors.HexColor("#1e3a5f")


def _styles():
    base = getSampleStyleSheet()
    return {
        "h": ParagraphStyle("h", parent=base["Heading1"], fontSize=14, textColor=ACCENT),
        "n": ParagraphStyle("n", parent=base["Normal"], fontSize=9, leading=12),
    }


def _table(rows, widths):
    table = Table(rows, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _path(folder, filename):
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, filename)


def compliance_pdf(project_id: str, summary: dict, output_dir: str) -> str:
    styles = _styles()
    path = _path(output_dir, f"compliance_{project_id}.pdf")
    doc = SimpleDocTemplate(path, pagesize=letter)
    bits = [
        Paragraph("Compliance Report", styles["h"]),
        Paragraph(f"Project {escape(project_id)} · {summary.get('percentage')}% controls passed", styles["n"]),
        Spacer(1, 12),
    ]
    rows = [["Control", "Framework", "Result", "Reason"]]
    for item in summary.get("controls") or []:
        rows.append([
            item.get("control_id"), item.get("framework"),
            "Passed" if item.get("passed") else "Failed",
            (item.get("reason") or "")[:90],
        ])
    bits.append(_table(rows, [90, 90, 60, 260]))
    doc.build(bits)
    return path


def _forensic_story(record: dict):
    styles = _styles()
    fid = record.get("forensic_id") or "forensic"

    def cell(value):
        return str(value or "")

    bits = [
        Paragraph("Digital Forensics Report", styles["h"]),
        Paragraph(
            f"ID {escape(str(fid))} · File {escape(cell(record.get('filename')))} · "
            f"Incident {escape(cell(record.get('incident_id') or 'n/a'))}",
            styles["n"],
        ),
        Spacer(1, 10),
        Paragraph(f"SHA256: {escape(cell(record.get('sha256') or 'n/a'))}", styles["n"]),
        Paragraph(f"MD5: {escape(cell(record.get('md5') or 'n/a'))}", styles["n"]),
        Paragraph(f"Size: {escape(cell(record.get('size')))} bytes", styles["n"]),
        Paragraph(f"Status: {escape(cell(record.get('status') or 'Collected'))}", styles["n"]),
        Spacer(1, 10),
        Paragraph(escape(cell(record.get("notes") or "Evidence preserved with chain of custody.")), styles["n"]),
    ]
    custody = record.get("custody") or []
    if custody:
        rows = [["When", "Actor", "Action", "Status"]]
        for item in custody:
            rows.append([
                cell(item.get("time"))[:32],
                cell(item.get("actor")),
                cell(item.get("action")),
                cell(item.get("status")),
            ])
        bits += [Spacer(1, 10), Paragraph("Chain of custody", styles["h"]), Spacer(1, 6), _table(rows, [130, 100, 180, 90])]
    return bits


def forensic_pdf_bytes(record: dict) -> bytes:
    buffer = BytesIO()
    SimpleDocTemplate(buffer, pagesize=letter).build(_forensic_story(record))
    return buffer.getvalue()


def forensic_pdf(record: dict, output_dir: str) -> str:
    fid = record.get("forensic_id") or "forensic"
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(fid))
    path = _path(output_dir, f"{safe}_forensic_report.pdf")
    with open(path, "wb") as handle:
        handle.write(forensic_pdf_bytes(record))
    return path


def executive_pdf(metrics: dict, output_dir: str) -> str:
    styles = _styles()
    path = _path(output_dir, "executive_dashboard.pdf")
    doc = SimpleDocTemplate(path, pagesize=letter)
    bits = [
        Paragraph("Executive Security Dashboard", styles["h"]),
        Paragraph(f"Generated {store.utcnow()}", styles["n"]),
        Spacer(1, 12),
    ]
    rows = [["Metric", "Value"]]
    for key, value in (metrics or {}).items():
        if isinstance(value, (int, float, str)):
            rows.append([key.replace("_", " ").title(), str(value)])
    bits.append(_table(rows, [260, 240]))
    doc.build(bits)
    return path


def security_summary_pdf(project_id: str, analysis: dict, output_dir: str) -> str:
    styles = _styles()
    path = _path(output_dir, f"advanced_security_{project_id}.pdf")
    doc = SimpleDocTemplate(path, pagesize=letter)
    bits = [
        Paragraph("Advanced Security Summary", styles["h"]),
        Paragraph(
            f"Project {escape(project_id)} · Score {analysis.get('security_score')}/100 · "
            f"{escape(str(analysis.get('risk_level') or ''))}",
            styles["n"],
        ),
        Spacer(1, 10),
        Paragraph(
            f"Critical {analysis.get('critical', 0)} · High {analysis.get('high', 0)} · "
            f"Medium {analysis.get('medium', 0)} · Low {analysis.get('low', 0)}",
            styles["n"],
        ),
    ]
    doc.build(bits)
    return path
