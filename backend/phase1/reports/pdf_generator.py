import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


class PDFReportGenerator:
    @staticmethod
    def generate(report_data: dict, output_path: str) -> str:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=18, spaceAfter=20)
        elements = []

        elements.append(Paragraph("Cloud Security Assessment Report", title_style))
        elements.append(Paragraph(f"Project: {report_data.get('project_name', 'N/A')}", styles["Normal"]))
        elements.append(Paragraph(f"Project ID: {report_data.get('project_id', 'N/A')}", styles["Normal"]))
        elements.append(Paragraph(f"Category: {report_data.get('category', 'N/A')}", styles["Normal"]))
        elements.append(Paragraph(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph(f"<b>Security Score:</b> {report_data.get('score', 0)}/100", styles["Normal"]))
        elements.append(Paragraph(f"<b>Risk Level:</b> {report_data.get('risk_level', 'N/A')}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Status:</b> {report_data.get('approval_status', 'N/A')}", styles["Normal"]))
        elements.append(Spacer(1, 15))

        counts = report_data.get("counts", {})
        table_data = [
            ["Severity", "Count"],
            ["Critical", str(counts.get("Critical", 0))],
            ["High", str(counts.get("High", 0))],
            ["Medium", str(counts.get("Medium", 0))],
            ["Low", str(counts.get("Low", 0))],
        ]
        t = Table(table_data, colWidths=[200, 100])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("<b>Recommendations</b>", styles["Heading2"]))
        elements.append(Paragraph(report_data.get("recommendation", "").replace("\n", "<br/>"), styles["Normal"]))
        elements.append(Spacer(1, 15))

        findings = report_data.get("findings", [])[:20]
        if findings:
            elements.append(Paragraph("<b>Top Findings</b>", styles["Heading2"]))
            for f in findings:
                text = f"[{f.get('severity')}] {f.get('problem')} in {f.get('file')}:{f.get('line', 'N/A')}"
                elements.append(Paragraph(text, styles["Normal"]))
                elements.append(Spacer(1, 5))

        doc.build(elements)
        return output_path
