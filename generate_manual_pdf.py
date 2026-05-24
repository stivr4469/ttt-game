#!/usr/bin/env python3
"""Генератор PDF-руководства по эксплуатации Sandbox Auditor."""

import re
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Preformatted,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ── Регистрация шрифтов с кириллицей ─────────────────────────────────────────
FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")

pdfmetrics.registerFont(TTFont("DVSans",       str(FONT_DIR / "DejaVuSans.ttf")))
pdfmetrics.registerFont(TTFont("DVSans-Bold",  str(FONT_DIR / "DejaVuSans-Bold.ttf")))
pdfmetrics.registerFont(TTFont("DVSans-Ital",  str(FONT_DIR / "DejaVuSans-Oblique.ttf")))
pdfmetrics.registerFont(TTFont("DVMono",       str(FONT_DIR / "DejaVuSansMono.ttf")))
pdfmetrics.registerFont(TTFont("DVMono-Bold",  str(FONT_DIR / "DejaVuSansMono-Bold.ttf")))

# ── Цвета ─────────────────────────────────────────────────────────────────────
INDIGO      = colors.HexColor("#6366f1")
INDIGO_DARK = colors.HexColor("#4338ca")
INDIGO_LIGHT= colors.HexColor("#e0e7ff")
BG_PAGE     = colors.white
BG_HEADER   = colors.HexColor("#1e1b4b")  # тёмно-синий — только в header страницы
BG_CODE     = colors.HexColor("#f1f5f9")
BG_TABLE_H  = colors.HexColor("#4338ca")
BG_TABLE_A  = colors.HexColor("#f8f9ff")
BG_TABLE_B  = colors.white
TEXT_DARK   = colors.HexColor("#0f172a")
TEXT_BODY   = colors.HexColor("#1e293b")
TEXT_MUTED  = colors.HexColor("#64748b")
TEXT_CODE   = colors.HexColor("#1e40af")
TEXT_H1     = colors.HexColor("#1e1b4b")
TEXT_H2     = INDIGO_DARK
TEXT_H3     = colors.HexColor("#4f46e5")
TEXT_H4     = colors.HexColor("#7c3aed")
BORDER_CLR  = colors.HexColor("#c7d2fe")
HR_CLR      = colors.HexColor("#e2e8f0")
WHITE       = colors.white

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm


# ── Стили ─────────────────────────────────────────────────────────────────────
def build_styles():
    s = {}
    s["h1"] = ParagraphStyle(
        "H1", fontName="DVSans-Bold", fontSize=20, leading=26,
        textColor=TEXT_H1, spaceBefore=20, spaceAfter=8,
    )
    s["h2"] = ParagraphStyle(
        "H2", fontName="DVSans-Bold", fontSize=14, leading=20,
        textColor=TEXT_H2, spaceBefore=16, spaceAfter=6,
    )
    s["h3"] = ParagraphStyle(
        "H3", fontName="DVSans-Bold", fontSize=11, leading=16,
        textColor=TEXT_H3, spaceBefore=12, spaceAfter=4,
    )
    s["h4"] = ParagraphStyle(
        "H4", fontName="DVSans-Bold", fontSize=10, leading=14,
        textColor=TEXT_H4, spaceBefore=8, spaceAfter=2,
    )
    s["body"] = ParagraphStyle(
        "Body", fontName="DVSans", fontSize=9.5, leading=14,
        textColor=TEXT_BODY, spaceAfter=4, alignment=TA_JUSTIFY,
    )
    s["bullet"] = ParagraphStyle(
        "Bullet", fontName="DVSans", fontSize=9.5, leading=13,
        textColor=TEXT_BODY, leftIndent=14, spaceAfter=2,
    )
    s["sub_bullet"] = ParagraphStyle(
        "SubBullet", fontName="DVSans", fontSize=9, leading=12,
        textColor=TEXT_MUTED, leftIndent=28, spaceAfter=2,
    )
    s["code"] = ParagraphStyle(
        "Code", fontName="DVMono", fontSize=8, leading=11,
        textColor=TEXT_CODE, backColor=BG_CODE,
        leftIndent=10, rightIndent=10,
        spaceBefore=4, spaceAfter=6, borderPad=6,
    )
    s["cover_title"] = ParagraphStyle(
        "CoverTitle", fontName="DVSans-Bold", fontSize=30, leading=38,
        textColor=WHITE, alignment=TA_CENTER, spaceAfter=10,
    )
    s["cover_sub"] = ParagraphStyle(
        "CoverSub", fontName="DVSans", fontSize=13, leading=18,
        textColor=colors.HexColor("#c7d2fe"), alignment=TA_CENTER, spaceAfter=6,
    )
    s["cover_desc"] = ParagraphStyle(
        "CoverDesc", fontName="DVSans", fontSize=10, leading=15,
        textColor=colors.HexColor("#a5b4fc"), alignment=TA_CENTER, spaceAfter=4,
    )
    s["tbl_head"] = ParagraphStyle(
        "TblHead", fontName="DVSans-Bold", fontSize=8.5, leading=11,
        textColor=WHITE,
    )
    s["tbl_cell"] = ParagraphStyle(
        "TblCell", fontName="DVSans", fontSize=8.5, leading=11,
        textColor=TEXT_BODY,
    )
    return s


# ── Header / Footer ───────────────────────────────────────────────────────────
def on_page(canvas, doc):
    canvas.saveState()
    w, h = A4

    # Верхняя полоса
    canvas.setFillColor(BG_HEADER)
    canvas.rect(0, h - 1.1 * cm, w, 1.1 * cm, fill=1, stroke=0)
    canvas.setFillColor(INDIGO)
    canvas.rect(0, h - 1.1 * cm, 0.35 * cm, 1.1 * cm, fill=1, stroke=0)
    canvas.setFont("DVSans-Bold", 8)
    canvas.setFillColor(WHITE)
    canvas.drawString(0.7 * cm, h - 0.72 * cm, "Sandbox Auditor")
    canvas.setFont("DVSans", 8)
    canvas.setFillColor(colors.HexColor("#a5b4fc"))
    canvas.drawRightString(w - MARGIN, h - 0.72 * cm,
                           "Руководство по эксплуатации  v10.0")

    # Нижняя полоса
    canvas.setFillColor(colors.HexColor("#f8fafc"))
    canvas.rect(0, 0, w, 0.85 * cm, fill=1, stroke=0)
    canvas.setStrokeColor(HR_CLR)
    canvas.setLineWidth(0.5)
    canvas.line(0, 0.85 * cm, w, 0.85 * cm)
    canvas.setFont("DVSans", 7.5)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawCentredString(w / 2, 0.3 * cm, f"Стр. {doc.page}")

    canvas.restoreState()


# ── Экранирование HTML ────────────────────────────────────────────────────────
def esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def inline_fmt(text):
    """Применить **bold** и `code` inline-форматирование."""
    text = esc(text)
    text = re.sub(r"\*\*(.+?)\*\*", r'<b>\1</b>', text)
    text = re.sub(r"`(.+?)`",
                  r'<font name="DVMono" color="#1e40af">\1</font>', text)
    return text


def safe_para(text, style):
    return Paragraph(inline_fmt(text), style)


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
            row = [Paragraph(f"<b>{esc(c)}</b>", styles["tbl_head"]) for c in raw]
        else:
            row = [Paragraph(inline_fmt(c), styles["tbl_cell"]) for c in raw]
        rows_data.append(row)

    col_w = (PAGE_W - 2 * MARGIN) / max_cols

    tbl = Table(rows_data, colWidths=[col_w] * max_cols, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  BG_TABLE_H),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_TABLE_A, BG_TABLE_B]),
        ("TEXTCOLOR",      (0, 1), (-1, -1), TEXT_BODY),
        ("FONTSIZE",       (0, 0), (-1, -1), 8.5),
        ("LEADING",        (0, 0), (-1, -1), 11),
        ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",           (0, 0), (-1, -1), 0.4, BORDER_CLR),
        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
    ]))
    return [tbl, Spacer(1, 8)]


# ── Markdown → flowables ──────────────────────────────────────────────────────
def md_to_flowables(md_text: str, styles: dict) -> list:
    story = []
    lines = md_text.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i]

        # Горизонтальная линия
        if re.match(r"^---+\s*$", line):
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=HR_CLR, spaceBefore=4, spaceAfter=4))
            i += 1
            continue

        # Заголовки
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        if m:
            level = len(m.group(1))
            text = m.group(2)
            key = f"h{min(level, 4)}"
            if level == 1:
                story.append(PageBreak())
            story.append(Paragraph(inline_fmt(text), styles[key]))
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
            i += 1
            code_text = "\n".join(code_lines)
            story.append(Preformatted(code_text, styles["code"]))
            continue

        # Маркированный список
        m = re.match(r"^(\s*)([-*])\s+(.*)", line)
        if m:
            indent = len(m.group(1))
            text = m.group(3)
            sty = styles["sub_bullet"] if indent >= 2 else styles["bullet"]
            story.append(Paragraph("•  " + inline_fmt(text), sty))
            i += 1
            continue

        # Нумерованный список
        m = re.match(r"^\s*(\d+)\.\s+(.*)", line)
        if m:
            text = m.group(2)
            story.append(Paragraph(f"{m.group(1)}.  {inline_fmt(text)}", styles["bullet"]))
            i += 1
            continue

        # Пустая строка
        if line.strip() == "":
            story.append(Spacer(1, 5))
            i += 1
            continue

        # Обычный параграф
        story.append(Paragraph(inline_fmt(line), styles["body"]))
        i += 1

    return story


# ── Обложка ───────────────────────────────────────────────────────────────────
def build_cover(styles):
    story = []

    # Тёмный фон обложки
    story.append(Spacer(1, 2.5 * cm))

    # Плашка-логотип S2
    logo_cell = Paragraph("<b>S2</b>", ParagraphStyle(
        "LogoP", fontName="DVSans-Bold", fontSize=32,
        textColor=WHITE, alignment=TA_CENTER,
    ))
    logo_tbl = Table([[logo_cell]], colWidths=[3.2 * cm], rowHeights=[3.2 * cm])
    logo_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, 0), INDIGO_DARK),
        ("ALIGN",       (0, 0), (0, 0), "CENTER"),
        ("VALIGN",      (0, 0), (0, 0), "MIDDLE"),
        ("ROUNDEDCORNERS", [10]),
    ]))
    center_wrap = Table([[logo_tbl]], colWidths=[PAGE_W - 2 * MARGIN])
    center_wrap.setStyle(TableStyle([("ALIGN", (0, 0), (0, 0), "CENTER")]))

    # Тёмный баннер обложки
    cover_content = [
        [Paragraph("", styles["body"])],
        [center_wrap],
        [Spacer(1, 0.8 * cm)],
        [Paragraph("Sandbox Auditor", styles["cover_title"])],
        [Paragraph("Руководство по эксплуатации", styles["cover_sub"])],
        [Spacer(1, 0.5 * cm)],
        [Paragraph(
            "Автономная compliance-платформа для SOC 2 Type II",
            styles["cover_desc"],
        )],
        [Spacer(1, 0.8 * cm)],
    ]
    cover_tbl = Table(cover_content, colWidths=[PAGE_W - 2 * MARGIN],
                      rowHeights=None)
    cover_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), BG_HEADER),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(cover_tbl)
    story.append(Spacer(1, 0.8 * cm))

    # Бейджи-метрики
    badges = Table(
        [[
            Paragraph("<b>Версия 10.0</b>", styles["tbl_head"]),
            Paragraph("<b>770 тестов ✓</b>", styles["tbl_head"]),
            Paragraph("<b>2026-05-24</b>", styles["tbl_head"]),
        ]],
        colWidths=[(PAGE_W - 2 * MARGIN) / 3] * 3,
    )
    badges.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), BG_TABLE_H),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("GRID",         (0, 0), (-1, -1), 0.5, BORDER_CLR),
    ]))
    story.append(badges)
    story.append(Spacer(1, 1 * cm))

    desc = (
        "Полное руководство: архитектура, установка, все функции системы, "
        "API-справочник, интеграции, мониторинг и сравнение с Vanta."
    )
    story.append(Paragraph(desc, styles["body"]))
    story.append(PageBreak())
    return story


# ── Главная функция ───────────────────────────────────────────────────────────
def generate_pdf(md_path: str, out_path: str):
    styles = build_styles()
    md_text = Path(md_path).read_text(encoding="utf-8")

    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=1.5 * cm, bottomMargin=1.2 * cm,
        title="Sandbox Auditor — Руководство по эксплуатации",
        author="Sandbox Auditor",
        subject="SOC 2 Compliance Platform v10.0",
    )

    story = []
    story.extend(build_cover(styles))
    story.extend(md_to_flowables(md_text, styles))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f"PDF готов: {out_path}")


if __name__ == "__main__":
    base = Path(__file__).parent
    generate_pdf(
        str(base / "РУКОВОДСТВО_ПО_ЭКСПЛУАТАЦИИ.md"),
        str(base / "Sandbox_Auditor_Руководство_v10.pdf"),
    )
