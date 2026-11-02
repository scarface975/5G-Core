#!/usr/bin/env python3
"""Render a simple Markdown file (headings, paragraphs, bullets, tables, fenced code) to a PDF with reportlab.
   python tools/md_to_pdf.py docs/demo/host-demo.md docs/demo/host-demo.pdf"""
import re
import sys
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (ListFlowable, ListItem, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table,
                                TableStyle, KeepTogether)

ss = getSampleStyleSheet()
BODY = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
H1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=18, spaceAfter=8)
H2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13, spaceBefore=10, spaceAfter=4)
CODE = ParagraphStyle("c", fontName="Courier", fontSize=8.2, leading=10.5, backColor=colors.HexColor("#f0f2f5"),
                      borderPadding=(5, 5, 5, 5), leftIndent=6, rightIndent=6, spaceBefore=4, spaceAfter=8)
CELL = ParagraphStyle("t", parent=BODY, fontSize=8.8, leading=11.5)


def inline(t):
    t = escape(t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"`([^`]+)`", r'<font face="Courier" size="8.5" color="#1a3d7c">\1</font>', t)
    return t


def table(rows):
    rows = [r for r in rows if not re.match(r"^\s*\|?\s*:?-{2,}", r)]
    data = [[Paragraph(inline(c.strip()), CELL) for c in r.strip().strip("|").split("|")] for r in rows]
    n = max(len(r) for r in data)
    w = (A4[0] - 40 * mm)
    first = 12 * mm if n == 3 else w / n
    widths = [first, 52 * mm, w - first - 52 * mm] if n == 3 else [w / n] * n
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b8bfc9")),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e3e8ef")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return t


def build(src, dst):
    lines = open(src, encoding="utf-8").read().split("\n")
    out, i = [], 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            i += 1
            blk = []
            while not lines[i].startswith("```"):
                blk.append(lines[i])
                i += 1
            out.append(Preformatted("\n".join(blk), CODE))
        elif ln.startswith("# "):
            out.append(Paragraph(inline(ln[2:]), H1))
        elif ln.startswith("## "):
            out.append(Paragraph(inline(ln[3:]), H2))
        elif ln.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i])
                i += 1
            i -= 1
            out.append(table(rows))
            out.append(Spacer(1, 6))
        elif ln.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(ListItem(Paragraph(inline(lines[i][2:]), BODY), leftIndent=12))
                i += 1
            i -= 1
            out.append(ListFlowable(items, bulletType="bullet", start="•", leftIndent=12))
        elif ln.strip():
            para = [ln.strip()]
            while i + 1 < len(lines) and lines[i + 1].strip() and not re.match(r"^(```|#|\||- )", lines[i + 1]):
                i += 1
                para.append(lines[i].strip())
            out.append(Paragraph(inline(" ".join(para)), BODY))
            out.append(Spacer(1, 3))
        i += 1
    doc = SimpleDocTemplate(dst, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
                            title="Host demo: OCUDU gNB + srsUE against our 5G core")
    doc.build(out)


if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2])
