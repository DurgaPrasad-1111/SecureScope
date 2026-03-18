import os
import textwrap
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from app.core.config import settings


class ReportService:
    def _draw_wrapped(self, c: canvas.Canvas, text: str, x: int, y: int, width: int = 110, line_height: int = 12) -> int:
        for line in textwrap.wrap(text or '', width=width) or ['']:
            c.drawString(x, y, line)
            y -= line_height
            if y < 70:
                c.showPage()
                y = 800
                c.setFont('Helvetica', 9)
        return y

    def generate_report(
        self,
        scan_id: int,
        domain: str,
        risk_score: int,
        findings: list[dict],
        path_token: str,
        module_results: dict | None = None,
        duration_ms: int | None = None,
    ) -> str:
        os.makedirs(settings.report_storage_path, exist_ok=True)
        file_path = os.path.join(settings.report_storage_path, f'scan_{scan_id}_{path_token}.pdf')

        c = canvas.Canvas(file_path, pagesize=A4)
        y = 800
        c.setFont('Helvetica-Bold', 16)
        c.drawString(40, y, f'SecureScope Security Report - {domain}')
        y -= 24

        c.setFont('Helvetica', 10)
        c.drawString(40, y, f'Executive Summary: Automated recon and risk analysis completed for {domain}.')
        y -= 16
        c.drawString(40, y, f'Weighted Risk Score: {risk_score}/100')
        y -= 16
        if duration_ms is not None:
            c.drawString(40, y, f'Total Scan Duration: {round(duration_ms / 1000, 2)} seconds')
            y -= 18

        c.setFont('Helvetica-Bold', 12)
        c.drawString(40, y, 'Findings, STRIDE Classification and Evidence')
        y -= 18

        c.setFont('Helvetica', 9)
        for idx, f in enumerate(findings, start=1):
            header = f"{idx}. [{f['severity']}] {f['title']} | STRIDE: {f['stride']}"
            y = self._draw_wrapped(c, header, 40, y, width=105)
            y = self._draw_wrapped(c, f"Description: {f['description']}", 50, y, width=100)
            y = self._draw_wrapped(c, f"Remediation: {f['remediation']}", 50, y, width=100)
            ev = str(f.get('evidence') or 'N/A')
            y = self._draw_wrapped(c, f"Raw Evidence: {ev}", 50, y, width=100)
            y -= 6

        if module_results:
            c.setFont('Helvetica-Bold', 12)
            c.drawString(40, y, 'Module Execution Telemetry')
            y -= 16
            c.setFont('Helvetica', 9)
            for mod, detail in module_results.items():
                y = self._draw_wrapped(c, f"- {mod}: {detail.get('duration_ms', 0)} ms", 40, y, width=105)
                raw = str(detail.get('raw'))
                y = self._draw_wrapped(c, f"Raw: {raw}", 50, y, width=100)
                y -= 4

        c.setFont('Helvetica-Bold', 12)
        c.drawString(40, y, 'Secure Coding Recommendations')
        y -= 16
        c.setFont('Helvetica', 10)
        y = self._draw_wrapped(
            c,
            'Use parameterized ORM queries, strict input validation, least-privilege access, secure session handling, and dependency patching.',
            40,
            y,
            width=95,
            line_height=13,
        )

        c.save()
        return file_path


report_service = ReportService()
