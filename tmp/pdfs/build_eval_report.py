from __future__ import annotations

import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs" / "JTAGent-live-application-evaluation-2026-09-29.md"
OUTPUT = ROOT / "output" / "pdf" / "JTAGent-live-application-evaluation-2026-09-29.pdf"

PAGE = landscape(letter)
MARGIN = 0.52 * inch
CONTENT_W = PAGE[0] - 2 * MARGIN

INK = colors.HexColor("#14222b")
MUTED = colors.HexColor("#546773")
TEAL = colors.HexColor("#167d72")
LIGHT_TEAL = colors.HexColor("#e7f4f1")
PALE = colors.HexColor("#f3f6f7")
GRID = colors.HexColor("#b8c7cc")
AMBER = colors.HexColor("#8a5a12")

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="TitleX", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK, spaceAfter=14))
styles.add(ParagraphStyle(name="H1X", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=INK, spaceBefore=12, spaceAfter=7, keepWithNext=True))
styles.add(ParagraphStyle(name="H2X", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11.5, leading=14, textColor=TEAL, spaceBefore=9, spaceAfter=5, keepWithNext=True))
styles.add(ParagraphStyle(name="H3X", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=INK, spaceBefore=7, spaceAfter=4, keepWithNext=True))
styles.add(ParagraphStyle(name="BodyX", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.2, leading=11.2, textColor=INK, spaceAfter=5))
styles.add(ParagraphStyle(name="BulletX", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.0, leading=10.8, leftIndent=14, firstLineIndent=-8, bulletIndent=4, textColor=INK, spaceAfter=3))
styles.add(ParagraphStyle(name="CodeX", parent=styles["Code"], fontName="Courier", fontSize=7.1, leading=9.2, leftIndent=8, rightIndent=8, borderColor=GRID, borderWidth=0.5, borderPadding=6, backColor=PALE, textColor=INK, spaceAfter=6))
styles.add(ParagraphStyle(name="TableX", parent=styles["BodyText"], fontName="Helvetica", fontSize=6.3, leading=8.0, textColor=INK))
styles.add(ParagraphStyle(name="TableHeadX", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=6.4, leading=8.1, textColor=colors.white))
styles.add(ParagraphStyle(name="NoteX", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.4, leading=9.5, textColor=MUTED, spaceAfter=5))


def inline(text: str) -> str:
    value = html.escape(text, quote=False)
    value = re.sub(r"`([^`]+)`", r'<font name="Courier">\1</font>', value)
    value = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", value)
    value = re.sub(r"\[([^]]+)\]\(([^)]+)\)", r'<u><font color="#167d72">\1</font></u>', value)
    return value


def paragraph(text: str, style: str = "BodyX") -> Paragraph:
    return Paragraph(inline(text), styles[style])


def table_from(lines: list[str]) -> Table:
    rows = [[cell.strip() for cell in row.strip().strip("|").split("|")] for row in lines]
    rows = [rows[0]] + rows[2:]
    col_count = len(rows[0])
    if col_count == 6:
        widths = [0.09, 0.24, 0.14, 0.27, 0.08, 0.18]
    elif col_count == 5:
        widths = [0.12, 0.27, 0.18, 0.31, 0.12]
    elif col_count == 4:
        widths = [0.18, 0.28, 0.18, 0.36]
    elif col_count == 3:
        widths = [0.22, 0.32, 0.46]
    else:
        widths = [1 / col_count] * col_count
    data = []
    for r_i, row in enumerate(rows):
        style = "TableHeadX" if r_i == 0 else "TableX"
        data.append([Paragraph(inline(cell), styles[style]) for cell in row])
    table = Table(data, colWidths=[CONTENT_W * w for w in widths], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TEAL),
        ("GRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
    ]))
    return table


def image_from(rel: str) -> Image:
    path = (SOURCE.parent / rel).resolve()
    image = Image(str(path))
    max_w, max_h = CONTENT_W, 4.9 * inch
    scale = min(max_w / image.imageWidth, max_h / image.imageHeight, 1)
    image.drawWidth = image.imageWidth * scale
    image.drawHeight = image.imageHeight * scale
    image.hAlign = "CENTER"
    return image


def parse_markdown() -> list:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    story: list = []
    i = 0
    in_code = False
    code: list[str] = []
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            if in_code:
                story.append(Paragraph(html.escape("\n".join(code)).replace("\n", "<br/>"), styles["CodeX"]))
                code = []
                in_code = False
            else:
                in_code = True
            i += 1
            continue
        if in_code:
            code.append(line)
            i += 1
            continue
        if line.startswith("| ") and i + 1 < len(lines) and re.match(r"^\|[ :\-|]+\|$", lines[i + 1]):
            block = [line, lines[i + 1]]
            i += 2
            while i < len(lines) and lines[i].startswith("|"):
                block.append(lines[i])
                i += 1
            story.extend([table_from(block), Spacer(1, 7)])
            continue
        image_match = re.match(r"!\[([^]]*)\]\(([^)]+)\)", line)
        if image_match:
            story.extend([image_from(image_match.group(2)), Paragraph(inline(image_match.group(1)), styles["NoteX"]), Spacer(1, 6)])
        elif line.startswith("# "):
            story.append(Paragraph(inline(line[2:]), styles["TitleX"]))
        elif line.startswith("## "):
            story.append(Paragraph(inline(line[3:]), styles["H1X"]))
        elif line.startswith("### "):
            story.append(Paragraph(inline(line[4:]), styles["H2X"]))
        elif line.startswith("#### "):
            story.append(Paragraph(inline(line[5:]), styles["H3X"]))
        elif re.match(r"^[-*] ", line):
            story.append(Paragraph("• " + inline(line[2:]), styles["BulletX"]))
        elif re.match(r"^\d+\. ", line):
            number, value = line.split(". ", 1)
            story.append(Paragraph(f"{number}. " + inline(value), styles["BulletX"]))
        elif line.startswith("> "):
            story.append(Paragraph(inline(line[2:]), styles["NoteX"]))
        elif line.strip():
            story.append(paragraph(line))
        else:
            story.append(Spacer(1, 3))
        i += 1
    return story


def page_decor(canvas, doc):
    canvas.saveState()
    width, height = PAGE
    canvas.setFillColor(TEAL)
    canvas.rect(0, height - 8, width, 8, fill=1, stroke=0)
    canvas.setFont("Helvetica", 6.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN, 18, "JTAGent — Live Application Evaluation and Embedded Engineer Review")
    canvas.drawRightString(width - MARGIN, 18, f"Page {doc.page}")
    canvas.restoreState()


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    frame = Frame(MARGIN, 30, CONTENT_W, PAGE[1] - 30 - MARGIN, id="body")
    doc = BaseDocTemplate(
        str(OUTPUT),
        pagesize=PAGE,
        rightMargin=MARGIN,
        leftMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=30,
        title="JTAGent — Live Application Evaluation and Embedded Engineer Review",
        author="OpenAI Codex",
    )
    doc.addPageTemplates([PageTemplate(id="report", frames=[frame], onPage=page_decor)])
    story = parse_markdown()
    story.insert(1, KeepTogether([
        Paragraph("Evidence-backed review of the running dashboard, edge bridge, retained physical evidence, software checks, and engineering workflow readiness.", styles["BodyX"]),
        Paragraph("No new physical target operation was performed during this evaluation.", ParagraphStyle(name="Caution", parent=styles["BodyX"], textColor=AMBER, backColor=colors.HexColor("#fff6df"), borderColor=colors.HexColor("#e2bd63"), borderWidth=0.5, borderPadding=6)),
    ]))
    doc.build(story)
    print(OUTPUT)


if __name__ == "__main__":
    main()
