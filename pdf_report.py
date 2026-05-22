import io
import os
import argparse
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader

from evidence_client import EvidenceClient, EvidenceClientError
from log_config import get_logger

log = get_logger(__name__)

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

try:
    import weasyprint as _weasyprint
    _WEASYPRINT_AVAILABLE = True
except ImportError:
    _WEASYPRINT_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False

_STATUS_COLORS = {
    "pass":        "#16a34a",
    "fail":        "#dc2626",
    "not_started": "#d97706",
}


def _badge_color(status: str) -> str:
    return _STATUS_COLORS.get(status.lower(), "#64748b")


class AuditReportGenerator:
    def __init__(self, evidence_client: EvidenceClient) -> None:
        self._client = evidence_client
        self._env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=True,
        )

    def collect_data(self) -> Dict[str, Any]:
        company_name = os.getenv("COMPANY_NAME", "Acme Corp")
        generated_at = datetime.now(timezone.utc).isoformat()

        try:
            raw_controls: List[Dict[str, Any]] = self._client.get_controls()
        except EvidenceClientError as exc:
            log.warning("Evidence Tracker unavailable, generating empty report", extra={"error": str(exc)})
            raw_controls = []

        controls: List[Dict[str, Any]] = []
        for ctrl in raw_controls:
            ctrl_id = ctrl.get("id", "")
            try:
                evidence_items = self._client.get_evidence(control_id=ctrl_id)
            except EvidenceClientError as exc:
                log.warning(
                    "Failed to fetch evidence for control",
                    extra={"control_id": ctrl_id, "error": str(exc)},
                )
                evidence_items = []

            controls.append({
                "id":          ctrl_id,
                "code":        ctrl.get("code", ""),
                "title":       ctrl.get("title", ""),
                "status":      ctrl.get("status", "not_started"),
                "description": ctrl.get("description", ""),
                "evidence":    evidence_items,
            })

        status_pass        = sum(1 for c in controls if c["status"].lower() == "pass")
        status_fail        = sum(1 for c in controls if c["status"].lower() == "fail")
        status_not_started = sum(1 for c in controls if c["status"].lower() not in ("pass", "fail"))
        total = len(controls)
        compliance_pct = round(status_pass / total * 100) if total else 0

        return {
            "company_name":  company_name,
            "generated_at":  generated_at,
            "controls":      controls,
            "summary": {
                "pass":           status_pass,
                "fail":           status_fail,
                "not_started":    status_not_started,
                "total":          total,
                "compliance_pct": compliance_pct,
            },
        }

    def render_html(self, data: Dict[str, Any]) -> str:
        template = self._env.get_template("audit_report.html.j2")
        return template.render(**data)

    def _save_html(self, html: str, path: str) -> str:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return path

    def _render_pdf_weasyprint(self, html: str, path: str) -> str:
        _weasyprint.HTML(string=html).write_pdf(path)
        return path

    def _render_pdf_reportlab(self, data: Dict[str, Any], path: str) -> str:
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            rightMargin=1.5 * cm,
            leftMargin=1.5 * cm,
            topMargin=1.5 * cm,
            bottomMargin=1.5 * cm,
        )

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=16,
            spaceAfter=4,
        )
        h2_style = ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontSize=12,
            spaceAfter=6,
            spaceBefore=14,
        )
        h3_style = ParagraphStyle(
            "H3",
            parent=styles["Heading3"],
            fontSize=10,
            spaceAfter=4,
            spaceBefore=10,
        )
        normal = styles["Normal"]
        small = ParagraphStyle("Small", parent=normal, fontSize=8)

        story: list = []

        company = data["company_name"]
        generated_at = data["generated_at"]
        summary = data["summary"]
        controls = data["controls"]

        story.append(Paragraph(f"SOC 2 Type II Compliance Report — {company}", title_style))
        story.append(Paragraph(f"Generated: {generated_at}", small))
        story.append(Spacer(1, 0.4 * cm))

        # Summary table
        story.append(Paragraph("Executive Summary", h2_style))
        summary_data = [
            ["PASS", "FAIL", "NOT STARTED", "TOTAL", "COMPLIANCE"],
            [
                str(summary["pass"]),
                str(summary["fail"]),
                str(summary["not_started"]),
                str(summary["total"]),
                f"{summary['compliance_pct']}%",
            ],
        ]
        summary_table = Table(summary_data, colWidths=[2.8 * cm] * 5)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.5 * cm))

        # Controls overview
        story.append(Paragraph("Controls Overview", h2_style))
        if controls:
            ctrl_data = [["Code", "Title", "Status", "Evidence"]]
            for ctrl in controls:
                ctrl_data.append([
                    ctrl["code"],
                    ctrl["title"][:60] + ("…" if len(ctrl["title"]) > 60 else ""),
                    ctrl["status"].upper(),
                    str(len(ctrl["evidence"])),
                ])
            ctrl_table = Table(ctrl_data, colWidths=[2 * cm, 9 * cm, 3 * cm, 2 * cm])
            ctrl_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(ctrl_table)
        else:
            story.append(Paragraph("No controls found. Evidence Tracker may be unavailable.", small))

        story.append(PageBreak())

        # Evidence detail per control
        story.append(Paragraph("Evidence Detail", h2_style))
        if controls:
            for ctrl in controls:
                story.append(Paragraph(
                    f"{ctrl['code']} — {ctrl['title']}  [{ctrl['status'].upper()}]",
                    h3_style,
                ))
                if ctrl["evidence"]:
                    ev_data = [["Title", "Source", "Collected At", "SHA-256 (8)"]]
                    for ev in ctrl["evidence"]:
                        sha = (ev.get("sha256_hash") or "")[:8] or "—"
                        collected = (ev.get("collected_at") or "")[:19] or "—"
                        ev_data.append([
                            (ev.get("title") or "")[:50],
                            (ev.get("source") or "")[:30],
                            collected,
                            sha,
                        ])
                    ev_table = Table(
                        ev_data,
                        colWidths=[6.5 * cm, 4 * cm, 3.5 * cm, 2 * cm],
                    )
                    ev_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
                        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE",   (0, 0), (-1, -1), 7.5),
                        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
                    ]))
                    story.append(ev_table)
                else:
                    story.append(Paragraph("No evidence collected for this control.", small))
                story.append(Spacer(1, 0.3 * cm))
        else:
            story.append(Paragraph("No evidence data available.", small))

        doc.build(story)
        return path

    def generate(self, output_path: str) -> str:
        data = self.collect_data()
        html = self.render_html(data)

        if _WEASYPRINT_AVAILABLE:
            pdf_path = output_path if output_path.endswith(".pdf") else output_path + ".pdf"
            log.info("Generating PDF via WeasyPrint", extra={"path": pdf_path})
            return self._render_pdf_weasyprint(html, pdf_path)

        if _REPORTLAB_AVAILABLE:
            pdf_path = output_path if output_path.endswith(".pdf") else output_path + ".pdf"
            log.info("Generating PDF via ReportLab", extra={"path": pdf_path})
            return self._render_pdf_reportlab(data, pdf_path)

        html_path = output_path if output_path.endswith(".html") else output_path + ".html"
        log.info("No PDF backend available; saving HTML report", extra={"path": html_path})
        return self._save_html(html, html_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SOC 2 audit report")
    parser.add_argument(
        "--output",
        default="audit_report",
        help="Output file path (without extension)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open report after generation",
    )
    args = parser.parse_args()

    client = EvidenceClient(EVIDENCE_TRACKER_URL)
    generator = AuditReportGenerator(client)
    output_file = generator.generate(args.output)
    log.info("Report generated", extra={"path": output_file})

    if args.open:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", output_file])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", output_file])
        elif sys.platform.startswith("win"):
            os.startfile(output_file)  # type: ignore[attr-defined]


if __name__ == "__main__":
    main()
