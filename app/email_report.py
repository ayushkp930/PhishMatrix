"""Build a static, printable case summary from an email investigation."""

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer


def build_email_pdf(case: dict) -> bytes:
    output = BytesIO()
    document = SimpleDocTemplate(output, title="PhishMatrix Email Investigation", author="PhishMatrix",
                                 leftMargin=50, rightMargin=50, topMargin=50, bottomMargin=52)
    styles = getSampleStyleSheet()
    styles["Title"].textColor = colors.HexColor("#174b40")
    styles["Title"].alignment = 0
    styles["BodyText"].leading = 15
    styles["BodyText"].splitLongWords = True

    def line(text, style="BodyText"):
        return Paragraph(escape(str(text)), styles[style])

    def section(label, values):
        if values:
            return [line(label, "Heading2"), *[line(value) for value in values]]
        return []

    content = [line("Email investigation", "Title"),
               line(f"{case['verdict'].title()}  |  Evidence score {case['risk_score']}/100", "Heading2"),
               line(f"Case {case['case_id']}"), line(f"Generated {case['timestamp']}"), Spacer(1, 12)]
    content += section("Message details", [f"Subject: {case['subject']}", f"From: {case['from'] or 'Unavailable'}",
                                         f"Reply-To: {case['reply_to'] or 'Unavailable'}"])
    content.append(line("Evidence", "Heading2"))
    for evidence in case["evidence"]:
        weight = f"Weight {evidence['points']}" if evidence["points"] else "Context"
        content.append(KeepTogether([line(f"{evidence['label']} ({weight})", "Heading3"),
                                     line(f"{evidence['rule_id']} | {evidence['detail']}")]))
    if not case["evidence"]:
        content.append(line("The local checks returned no findings."))
    content += section("Score contributions", [f"{label.replace('_', ' ').title()}: {points}"
                                                for label, points in case["contributions"].items()])
    content += section("Extracted links", case["extracted_urls"])
    content += section("Attachment names", case["attachments"])
    content += section("Recommended checks", case["recommendations"])
    content += section("Analysis scope", ["Static email and MIME inspection. Sender authentication claims require gateway verification."])

    def footer(canvas, doc):
        canvas.setFillColor(colors.HexColor("#38564f"))
        canvas.setFont("Helvetica", 9)
        canvas.drawString(50, 30, "PhishMatrix | Email investigation")
        canvas.drawRightString(doc.pagesize[0] - 50, 30, str(doc.page))

    document.build(content, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
