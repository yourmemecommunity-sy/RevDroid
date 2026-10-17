"""PDF report with ReportLab (pure Python, works the same on Windows, macOS and Docker)."""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

SEV_COLORS = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#64748b"}
GRADE_COLORS = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#b91c1c"}
INK, MUTED, LINE = colors.HexColor("#0f172a"), colors.HexColor("#475569"), colors.HexColor("#e2e8f0")

ss = getSampleStyleSheet()
S = {
    "title": ParagraphStyle("t", parent=ss["Title"], fontSize=30, leading=36, textColor=INK, alignment=TA_CENTER),
    "sub": ParagraphStyle("s", parent=ss["Normal"], fontSize=13, leading=18, textColor=MUTED, alignment=TA_CENTER),
    "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontSize=17, textColor=INK, spaceBefore=6, spaceAfter=8),
    "h2": ParagraphStyle("h2", parent=ss["Heading3"], fontSize=11.5, textColor=INK, spaceBefore=2, spaceAfter=3),
    "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=9.5, leading=13.5, textColor=INK),
    "small": ParagraphStyle("sm", parent=ss["Normal"], fontSize=8, leading=10.5, textColor=MUTED),
    "mono": ParagraphStyle("m", parent=ss["Code"], fontSize=7.5, leading=9.5, textColor=INK, spaceBefore=4, spaceAfter=2,
                           backColor=colors.HexColor("#f1f5f9"), borderPadding=3),
    "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=8.5, leading=11, textColor=INK),
}


def p(text: Any, style: str = "body") -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "-")), S[style])


def _table(rows: list[list[Any]], widths: list[float], header: bool = True) -> Table:
    data = [[c if isinstance(c, Paragraph) else p(c, "cell") for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9"))]
    t.setStyle(TableStyle(style))
    return t


def _badge(sev: str) -> Paragraph:
    return Paragraph(f'<font color="{SEV_COLORS[sev]}"><b>{sev.upper()}</b></font>', S["cell"])


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "RevDroid static analysis report - for authorised security testing only")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(r: dict[str, Any]) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm,
                            bottomMargin=18 * mm, title=f"RevDroid report - {r['identity'].get('package_name')}",
                            author="RevDroid")
    ident, risk, findings = r["identity"], r["risk"], r["findings"]
    width = A4[0] - 36 * mm
    story: list[Any] = []

    # ---------------- cover ----------------
    grade_color = GRADE_COLORS.get(risk["grade"], "#0f172a")
    story += [Spacer(1, 50 * mm), Paragraph("RevDroid", S["title"]),
              p("APK Reverse Engineering & Security Analysis Report", "sub"),
              Spacer(1, 18 * mm),
              Paragraph(f"<b>{escape(str(ident.get('app_name') or 'Unknown app'))}</b>",
                        ParagraphStyle("an", parent=S["sub"], fontSize=18, textColor=INK, leading=24)),
              p(ident.get("package_name"), "sub"),
              p(f"Version {ident.get('version_name')} ({ident.get('version_code')})", "sub"),
              Spacer(1, 14 * mm),
              Paragraph(f'<font size="44" color="{grade_color}"><b>{risk["grade"]}</b></font>', S["title"]),
              Spacer(1, 6 * mm),
              p(f"Risk score {risk['score']} / 100", "sub"),
              Spacer(1, 30 * mm),
              p(f"Generated {datetime.now().strftime('%d %B %Y, %H:%M')}  -  Scan {r['scan_id']}", "small"),
              p(f"File: {r['file']['file_name']}  -  SHA-256 {r['file']['sha256']}", "small"),
              PageBreak()]

    # ---------------- executive summary ----------------
    sc = risk["severity_counts"]
    top = [f for f in findings if f["severity"] in ("critical", "high")][:5]
    verdict = {"A": "shows no significant weaknesses in static analysis",
               "B": "has minor weaknesses that should be cleaned up",
               "C": "has several weaknesses that need attention before release",
               "D": "has serious weaknesses that put users or data at risk",
               "F": "has critical weaknesses and should not be released as-is"}[risk["grade"]]
    story += [p("Executive summary", "h1"),
              p(f"{ident.get('app_name') or ident.get('package_name')} received a risk score of "
                f"{risk['score']}/100 (grade {risk['grade']}). The app {verdict}. Static analysis found "
                f"{sc['critical']} critical, {sc['high']} high, {sc['medium']} medium and {sc['low']} low "
                f"severity issues, and the app requests {risk['permission_counts']['dangerous']} dangerous "
                f"permission(s)."),
              Spacer(1, 4 * mm)]
    if top:
        story.append(p("Most important issues", "h2"))
        story.append(_table([["Severity", "Issue", "Fix"]] +
                            [[_badge(f["severity"]), f["title"], f["recommendation"]] for f in top],
                            [22 * mm, 60 * mm, width - 82 * mm]))
    story += [Spacer(1, 6 * mm), p("Risk score breakdown", "h2"), p(risk["explanation"], "small"),
              Spacer(1, 2 * mm),
              _table([["Category", "Points", "Cap"]] +
                     [[b["category"], b["points"], b["cap"]] for b in risk["breakdown"]],
                     [70 * mm, 30 * mm, 30 * mm]),
              Spacer(1, 6 * mm), p("Application", "h2"),
              _table([["Package", ident.get("package_name")], ["Version", f"{ident.get('version_name')} "
                                                                          f"(code {ident.get('version_code')})"],
                      ["Min / target SDK", f"{ident.get('min_sdk')} / {ident.get('target_sdk')}"],
                      ["Main activity", ident.get("main_activity")],
                      ["Signature schemes", ", ".join(k for k in ("v1", "v2", "v3") if ident["signing"][k]) or "none"],
                      ["Signer", "; ".join(c["subject"] for c in ident["signing"]["certificates"]) or "-"]],
                     [40 * mm, width - 40 * mm], header=False)]
    if r.get("warnings"):
        story += [Spacer(1, 4 * mm), p("Analysis notes", "h2")] + [p(f"- {w}", "small") for w in r["warnings"]]
    story.append(PageBreak())

    # ---------------- findings ----------------
    story.append(p(f"Detailed findings ({len(findings)})", "h1"))
    for n, f in enumerate(findings, 1):
        refs = " - ".join(x for x in (f.get("cwe"), f.get("masvs"), f"category: {f['category']}") if x)
        block = [Paragraph(f'<font color="{SEV_COLORS[f["severity"]]}"><b>[{f["severity"].upper()}]</b></font> '
                           f'<b>{n}. {escape(f["title"])}</b>', S["h2"]),
                 p(refs + f"  -  {f['occurrences']} occurrence(s)", "small"), Spacer(1, 1.5 * mm),
                 p(f["description"]), Spacer(1, 1 * mm),
                 Paragraph(f"<b>Fix:</b> {escape(f['recommendation'])}", S["body"])]
        for loc in f["locations"][:3]:
            where = f"{loc['file']}" + (f":{loc['line']}" if loc.get("line") else "")
            block += [Spacer(1, 1 * mm), p(where, "small")]
            if loc.get("snippet"):
                block.append(p(loc["snippet"], "mono"))
        if len(f["locations"]) > 3:
            block.append(p(f"... and {f['occurrences'] - 3} more location(s)", "small"))
        block.append(Spacer(1, 5 * mm))
        story.append(KeepTogether(block))

    # ---------------- permissions ----------------
    story += [PageBreak(), p(f"Permissions ({len(r['permissions'])})", "h1")]
    if r["permissions"]:
        level_color = {"dangerous": "#ea580c", "signature": "#b91c1c", "custom": "#7c3aed", "normal": "#16a34a"}
        story.append(_table([["Permission", "Level", "Meaning"]] + [
            [perm["name"], Paragraph(f'<font color="{level_color[perm["protection_level"]]}"><b>'
                                     f'{perm["protection_level"]}</b></font>', S["cell"]), perm["description"]]
            for perm in r["permissions"]], [78 * mm, 22 * mm, width - 100 * mm]))

    # ---------------- appendix ----------------
    ep = r["endpoints"]
    story += [PageBreak(), p("Appendix A - File hashes", "h1"),
              _table([["File name", r["file"]["file_name"]], ["Size", f"{r['file']['size_bytes']:,} bytes"],
                      ["MD5", r["file"]["md5"]], ["SHA-1", r["file"]["sha1"]], ["SHA-256", r["file"]["sha256"]]] +
                     [[f"Cert SHA-256 #{i+1}", c["sha256"]] for i, c in enumerate(ident["signing"]["certificates"])],
                     [35 * mm, width - 35 * mm], header=False),
              Spacer(1, 6 * mm), p(f"Appendix B - Network endpoints ({len(ep['domains'])} domains)", "h1")]
    if ep["domains"]:
        story.append(_table([["Domain", "Schemes", "References"]] +
                            [[d["domain"], ", ".join(d["schemes"]), d["count"]] for d in ep["domains"][:150]],
                            [100 * mm, 40 * mm, width - 140 * mm]))
    if ep["ips"]:
        story += [Spacer(1, 4 * mm), p("IP addresses", "h2"),
                  _table([["IP", "Scope", "References"]] + [[i["ip"], i["scope"], i["count"]] for i in ep["ips"][:100]],
                         [60 * mm, 40 * mm, width - 100 * mm])]
    if ep["urls"]:
        story += [Spacer(1, 4 * mm), p("URLs", "h2")] + [p(u["url"], "mono") for u in ep["urls"][:150]]
    story += [Spacer(1, 8 * mm),
              p("Disclaimer: this report comes from automated static analysis and can contain false positives "
                "or miss issues that only appear at runtime. Analyse only apps you own or are authorised to test.",
                "small")]

    doc.build(story, onFirstPage=lambda c, d: None, onLaterPages=_footer)
    return buf.getvalue()
