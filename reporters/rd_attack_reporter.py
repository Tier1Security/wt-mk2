# reporters/rd_attack_reporter.py

import json
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, Preformatted
)

def generate_rd_attack_report(
    title: str,
    description: str,
    summary: dict,
    timeline: list,
    raw_events: list,
    output_path: str = None
) -> str:
    """
    Generates a PDF report for a Remote Desktop brute‐force incident.

    Args:
        title:          Main title of the report.
        description:    A short paragraph describing the attack type.
        summary:        Dict with keys ['Attack','Time','System','IP'].
        timeline:       List of dicts with keys ['Sequence','EventID','Timestamp'].
        raw_events:     List of raw event dicts to include as pretty JSON.
        output_path:    Optional PDF filepath; defaults to rd_attack_{ts}.pdf.

    Returns:
        The path to the generated PDF.
    """
    # 1) Determine output filename if not specified
    if output_path is None:
        ts = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        output_path = f"rd_attack_{ts}.pdf"

    # 2) Set up the document
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(title, styles["Title"]))
    # Description below title
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(description, styles["BodyText"]))
    elements.append(Spacer(1, 12))

    # High-Level Summary Table
    elements.append(Paragraph("High Level Summary", styles["Heading2"]))
    header = list(summary.keys())
    row    = list(summary.values())
    table_data = [header, row]
    tbl = Table(table_data, hAlign="LEFT")
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),    colors.grey),
        ("TEXTCOLOR",     (0, 0), (-1, 0),    colors.whitesmoke),
        ("ALIGN",         (0, 0), (-1, -1),   "CENTER"),
        ("FONTNAME",      (0, 0), (-1, 0),    "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, 0),    8),
        ("GRID",          (0, 0), (-1, -1),   0.5, colors.black),
    ]))
    elements.append(tbl)
    elements.append(Spacer(1, 12))

    # Timeline Table
    elements.append(Paragraph("Timeline of Events", styles["Heading2"]))
    tl_header = ["Sequence", "Event ID", "Timestamp"]
    tl_rows = [[ev["Sequence"], ev["EventID"], ev["Timestamp"]] for ev in timeline]
    tl_table = Table([tl_header] + tl_rows, hAlign="LEFT")
    tl_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),    colors.grey),
        ("TEXTCOLOR",     (0, 0), (-1, 0),    colors.whitesmoke),
        ("ALIGN",         (0, 0), (-1, -1),   "CENTER"),
        ("FONTNAME",      (0, 0), (-1, 0),    "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, 0),    8),
        ("GRID",          (0, 0), (-1, -1),   0.5, colors.black),
    ]))
    elements.append(tl_table)
    elements.append(Spacer(1, 12))

    # Raw Events JSON
    elements.append(Paragraph("Raw JSON Events", styles["Heading2"]))
    raw_json = json.dumps(raw_events, indent=2, ensure_ascii=False)
    pre_style = ParagraphStyle(
        "RawJSON", fontName="Courier", fontSize=6, leading=8, leftIndent=6
    )
    elements.append(Preformatted(raw_json, pre_style))

    # 3) Build PDF
    doc.build(elements)
    print(f"📄 PDF report written to {output_path}")
    return output_path
