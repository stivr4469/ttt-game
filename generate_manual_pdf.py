#!/usr/bin/env python3
"""Генератор PDF-руководства по эксплуатации Sandbox Auditor."""

import re
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Preformatted,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ── Цвета бренда ──────────────────────────────────────────────────────────────
INDIGO      = colors.HexColor("#6366f1")
INDIGO_DARK = colors.HexColor("#4f46e5")
BG_DARK     = colors.HexColor("#07070e")
SURFACE     = colors.HexColor("#12121f")
PASS_GREEN  = colors.HexColor("#10b981")
FAIL_RED    = colors.HexColor("#f43f5e")
WARN_AMBER  = colors.HexColor("#f59e0b")
TEXT_MAIN   = colors.HexColor("#e2e8f0")
TEXT_MUTED  = colors.HexColor("#94a3b8")
BORDER      = colors.HexColor("#1e293b")
CODE_BG     = colors.HexColor("#0d0d18")
TABLE_HEAD  = colors.HexColor("#1e1b4b")
TABLE_ALT   = colors.HexColor("#0f172a")
WHITE       = colors.white

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm

# ── Стили ─────────────────────────────────────────────────────────────────────
def build_styles():
    base = getSampleStyleSheet()
    s = {}

    s["h1"] = ParagraphStyle(
        "H1",
        fontSize=22, leading=28, textColor=WHITE,
        fontName="Helvetica-Bold",
        spaceBefore=24, spaceAfter=8,
        borderPad=(0, 0, 6, 0),
    )
    s["h2"] = ParagraphStyle(
        "H2",
        fontSize=15, leading=20, textColor=INDIGO,
        fontName="Helvetica-Bold",
        spaceBefore=18, spaceAfter=6,
    )
    s["h3"] = ParagraphStyle(
        "H3",
        fontSize=12, leading=16, textColor=colors.HexColor("#818cf8"),
        fontName="Helvetica-Bold",
        spaceBefore=12, spaceAfter=4,
    )
    s["h4"] = ParagraphStyle(
        "H4",
        fontSize=11, leading=14, textColor=colors.HexColor("#a5b4fc"),
        fontName="Helvetica-BoldOblique",
        spaceBefore=8, spaceAfter=2,
    )
    s["body"] = ParagraphStyle(
        "Body",
        fontSize=9.5, leading=14, textColor=TEXT_MAIN,
        fontName="Helvetica",
        spaceAfter=4, alignment=TA_JUSTIFY,
    )
    s["bullet"] = ParagraphStyle(
        "Bullet",
        fontSize=9.5, leading=13, textColor=TEXT_MAIN,
        fontName="Helvetica",
        leftIndent=16, spaceAfter=2,
        bulletIndent=4,
    )
    s["sub_bullet"] = ParagraphStyle(
        "SubBullet",
        fontSize=9, leading=12, textColor=TEXT_MUTED,
        fontName="Helvetica",
        leftIndent=30, spaceAfter=2,
        bulletIndent=18,
    )
    s["code"] = ParagraphStyle(
        "Code",
        fontSize=8, leading=11, textColor=colors.HexColor("#7dd3fc"),
        fontName="Courier",
        backColor=CODE_BG,
        leftIndent=12, rightIndent=12,
        spaceBefore=4, spaceAfter=4,
        borderPad=6,
    )
    s["toc_title"] = ParagraphStyle(
        "TocTitle",
        fontSize=18, leading=24, textColor=WHITE,
        fontName="Helvetica-Bold",
        spaceAfter=16, alignment=TA_CENTER,
    )
    s["toc_item"] = ParagraphStyle(
        "TocItem",
        fontSize=10, leading=16, textColor=TEXT_MAIN,
        fontName="Helvetica",
    )
    s["caption"] = ParagraphStyle(
        "Caption",
        fontSize=8, leading=10, textColor=TEXT_MUTED,
        fontName="Helvetica-Oblique",
        alignment=TA_CENTER, spaceAfter=6,
    )
    s["cover_title"] = ParagraphStyle(
        "CoverTitle",
        fontSize=32, leading=40, textColor=WHITE,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER, spaceAfter=12,
    )
    s["cover_sub"] = ParagraphStyle(
        "CoverSub",
        fontSize=14, leading=20, textColor=TEXT_MUTED,
        fontName="Helvetica",
        alignment=TA_CENTER, spaceAfter=6,
    )
    s["cover_badge"] = ParagraphStyle(
        "CoverBadge",
        fontSize=11, leading=16, textColor=INDIGO,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    return s


# ── PDF canvas с header/footer ────────────────────────────────────────────────
def on_page(canvas, doc, styles):
    canvas.saveState()
    w, h = A4

    # Header bar
    canvas.setFillColor(SURFACE)
    canvas.rect(0, h - 1.2 * cm, w, 1.2 * cm, fill=1, stroke=0)
    canvas.setFillColor(INDIGO)
    canvas.rect(0, h - 1.2 * cm, 0.4 * cm, 1.2 * cm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawString(0.8 * cm, h - 0.8 * cm, "Sandbox Auditor")
    canvas.setFillColor(TEXT_MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - MARGIN, h - 0.8 * cm, "Руководство по эксплуатации v10.0")

    # Footer
    canvas.setFillColor(SURFACE)
    canvas.rect(0, 0, w, 0.9 * cm, fill=1, stroke=0)
    canvas.setFillColor(TEXT_MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawCentredString(w / 2, 0.32 * cm, f"Стр. {doc.page}")

    canvas.restoreState()


# ── Обёртка Paragraph с защитой от спецсимволов ──────────────────────────────
def safe_para(text, style):
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Восстанавливаем теги которые уже были корректными
    text = re.sub(r"&lt;b&gt;", "<b>", text)
    text = re.sub(r"&lt;/b&gt;", "</b>", text)
    return Paragraph(text, style)


def bold(text):
    text = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"<b>{text}</b>"


def escape(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── Таблица из markdown ───────────────────────────────────────────────────────
def parse_md_table(lines, styles):
    rows_raw = []
    for line in lines:
        if re.match(r"\s*\|[-: |]+\|\s*$", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows_raw.append(cells)

    if not rows_raw:
        return []

    max_cols = max(len(r) for r in rows_raw)
    rows_data = []
    for i, raw in enumerate(rows_raw):
        while len(raw) < max_cols:
            raw.append("")
        if i == 0:
            row = [Paragraph(f"<b>{escape(c)}</b>", styles["body"]) for c in raw]
        else:
            row = [Paragraph(escape(c), styles["body"]) for c in raw]
        rows_data.append(row)

    col_w = (PAGE_W - 2 * MARGIN) / max_cols
    col_widths = [col_w] * max_cols

    tbl = Table(rows_data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  TABLE_HEAD),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("LEADING",      (0, 0), (-1, -1), 11),
        ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [TABLE_ALT, SURFACE]),
        ("TEXTCOLOR",    (0, 1), (-1, -1), TEXT_MAIN),
        ("GRID",         (0, 0), (-1, -1), 0.3, BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    return [tbl, Spacer(1, 8)]


# ── Парсер markdown → Platypus flowables ─────────────────────────────────────
def md_to_flowables(md_text: str, styles: dict) -> list:
    story = []
    lines = md_text.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i]

        # Горизонтальная линия
        if re.match(r"^---+\s*$", line):
            story.append(HRFlowable(
                width="100%", thickness=0.5,
                color=BORDER, spaceAfter=4, spaceBefore=4,
            ))
            i += 1
            continue

        # Заголовки
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        if m:
            level = len(m.group(1))
            text = escape(m.group(2))
            key = f"h{level}" if level <= 4 else "h4"
            if level == 1:
                story.append(PageBreak())
            story.append(safe_para(text, styles[key]))
            i += 1
            continue

        # Таблица
        if "|" in line and line.strip().startswith("|"):
            tbl_lines = []
            while i < len(lines) and "|" in lines[i] and lines[i].strip().startswith("|"):
                tbl_lines.append(lines[i])
                i += 1
            story.extend(parse_md_table(tbl_lines, styles))
            continue

        # Блок кода
        if line.strip().startswith("```"):
            i += 1
            code_lines = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # закрывающий ```
            code_text = "\n".join(code_lines)
            story.append(Preformatted(code_text, styles["code"]))
            story.append(Spacer(1, 4))
            continue

        # Маркированный список (- или *)
        m = re.match(r"^(\s*)([-*])\s+(.*)", line)
        if m:
            indent = len(m.group(1))
            text = escape(m.group(3))
            # Bold **text**
            text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
            sty = styles["sub_bullet"] if indent >= 2 else styles["bullet"]
            story.append(Paragraph(f"• {text}", sty))
            i += 1
            continue

        # Нумерованный список
        m = re.match(r"^\s*\d+\.\s+(.*)", line)
        if m:
            text = escape(m.group(1))
            text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
            story.append(Paragraph(f"• {text}", styles["bullet"]))
            i += 1
            continue

        # Пустая строка
        if line.strip() == "":
            story.append(Spacer(1, 4))
            i += 1
            continue

        # Обычный параграф
        text = escape(line)
        text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
        text = re.sub(r"`(.+?)`", r"<font name='Courier' color='#7dd3fc'>\1</font>", text)
        story.append(safe_para(text, styles["body"]))
        i += 1

    return story


# ── Обложка ───────────────────────────────────────────────────────────────────
def build_cover(styles):
    story = []
    story.append(Spacer(1, 3 * cm))

    # Логотип-бейдж
    logo_data = [[Paragraph("<b>S2</b>", ParagraphStyle(
        "Logo", fontSize=28, textColor=WHITE,
        fontName="Helvetica-Bold", alignment=TA_CENTER,
    ))]]
    logo_tbl = Table(logo_data, colWidths=[3 * cm], rowHeights=[3 * cm])
    logo_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), INDIGO_DARK),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [8]),
    ]))
    # центрируем лого в широкой таблице
    wrap = Table([[logo_tbl]], colWidths=[PAGE_W - 2 * MARGIN])
    wrap.setStyle(TableStyle([("ALIGN", (0, 0), (0, 0), "CENTER")]))
    story.append(wrap)
    story.append(Spacer(1, 1 * cm))

    story.append(safe_para("Sandbox Auditor", styles["cover_title"]))
    story.append(safe_para("Руководство по эксплуатации", styles["cover_sub"]))
    story.append(Spacer(1, 0.6 * cm))

    # Badges
    badges = [
        ["Версия 10.0", "770 тестов ✅", "2026-05-24"],
    ]
    badge_tbl = Table(badges, colWidths=[(PAGE_W - 2 * MARGIN) / 3] * 3)
    badge_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), TABLE_HEAD),
        ("TEXTCOLOR",    (0, 0), (-1, -1), INDIGO),
        ("FONTNAME",     (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 10),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("GRID",         (0, 0), (-1, -1), 0.5, BORDER),
    ]))
    story.append(badge_tbl)
    story.append(Spacer(1, 2 * cm))

    desc = (
        "Полное руководство по автономной compliance-платформе для SOC 2 Type II. "
        "Охватывает архитектуру, установку, все 20+ функций, API, интеграции, "
        "мониторинг и честное сравнение с Vanta."
    )
    story.append(safe_para(desc, styles["cover_sub"]))
    story.append(PageBreak())
    return story


# ── Главная функция ───────────────────────────────────────────────────────────
def generate_pdf(md_path: str, out_path: str):
    styles = build_styles()
    md_text = Path(md_path).read_text(encoding="utf-8")

    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=1.6 * cm,
        bottomMargin=1.2 * cm,
        title="Sandbox Auditor — Руководство по эксплуатации",
        author="Sandbox Auditor",
        subject="SOC 2 Compliance Platform",
    )

    story = []
    story.extend(build_cover(styles))
    story.extend(md_to_flowables(md_text, styles))

    doc.build(
        story,
        onFirstPage=lambda c, d: on_page(c, d, styles),
        onLaterPages=lambda c, d: on_page(c, d, styles),
    )
    print(f"PDF сгенерирован: {out_path}")


if __name__ == "__main__":
    base = Path(__file__).parent
    md_file  = base / "РУКОВОДСТВО_ПО_ЭКСПЛУАТАЦИИ.md"
    pdf_file = base / "Sandbox_Auditor_Руководство_v10.pdf"
    generate_pdf(str(md_file), str(pdf_file))
