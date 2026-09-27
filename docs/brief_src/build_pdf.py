#!/usr/bin/env python3
"""Render the client acquisition brief to PDF from brief_content.json."""
import json
import os
import re
import sys

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    BaseDocTemplate, CondPageBreak, Frame, HRFlowable, ListFlowable, ListItem,
    PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

OUT = sys.argv[1] if len(sys.argv) > 1 else "ACQUISITION_BRIEF.pdf"
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "brief_content.json")) as fh:
    C = json.load(fh)

NAVY = colors.HexColor("#1F3A5F")
ACCENT = colors.HexColor("#2E6B8F")
GREY = colors.HexColor("#404040")
LIGHT = colors.HexColor("#EEF2F6")
RULE = colors.HexColor("#9DB2C6")
INNER = colors.HexColor("#D2DBE6")
MUTED = colors.HexColor("#8A8A8A")

PAGE_W, PAGE_H = letter
MARGIN = 0.9 * inch
CONTENT_W = PAGE_W - 2 * MARGIN


def markup(text):
    """Escape XML, then turn **bold** into <b> for reportlab."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)


def style(name, **kw):
    base = dict(fontName="Helvetica", fontSize=10, leading=14.5, textColor=GREY)
    base.update(kw)
    return ParagraphStyle(name, **base)


S = {
    "title": style("title", fontName="Helvetica-Bold", fontSize=26, leading=30, textColor=NAVY),
    "subtitle": style("subtitle", fontSize=15, leading=19, textColor=ACCENT, spaceAfter=4),
    "h1": style("h1", fontName="Helvetica-Bold", fontSize=13.5, leading=17, textColor=NAVY,
                spaceBefore=16, spaceAfter=6),
    "body": style("body", spaceAfter=7),
    "li": style("li", leading=14, spaceAfter=3),
    "cellh": style("cellh", fontName="Helvetica-Bold", fontSize=9.5, leading=12.5, textColor=colors.white),
    "cellk": style("cellk", fontName="Helvetica-Bold", fontSize=9.5, leading=12.5, textColor=NAVY),
    "cellv": style("cellv", fontSize=9.5, leading=12.5),
    "small": style("small", fontName="Helvetica-Oblique", fontSize=8.5, leading=12, textColor=MUTED),
}


def P(text, key="body", **overrides):
    st = S[key] if not overrides else ParagraphStyle(key + "x", parent=S[key], **overrides)
    return Paragraph(markup(text), st)


def table(spec, with_header=True):
    w1 = spec.get("w1", 2600) / 1440 * inch  # DXA -> points, same widths as the DOCX
    data = []
    if with_header:
        data.append([P(h, "cellh") for h in spec["header"]])
    data += [[P(k, "cellk"), P(v, "cellv")] for k, v in spec["rows"]]
    t = Table(data, colWidths=[w1, CONTENT_W - w1], repeatRows=1 if with_header else 0)
    cmds = [
        ("GRID", (0, 0), (-1, -1), 0.4, INNER),
        ("BOX", (0, 0), (-1, -1), 0.6, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
    ]
    start = 1 if with_header else 0
    if with_header:
        cmds.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    cmds.append(("ROWBACKGROUNDS", (0, start), (-1, -1), [LIGHT, colors.white]))
    t.setStyle(TableStyle(cmds))
    return t


def bullets(items):
    return ListFlowable(
        [ListItem(P(i, "li"), leftIndent=16, value="•") for i in items],
        bulletType="bullet", bulletColor=ACCENT, bulletFontSize=9, leftIndent=16, spaceAfter=6,
    )


def numbers(items):
    return ListFlowable(
        [ListItem(P(i, "li"), leftIndent=18) for i in items],
        bulletType="1", bulletFormat="%s.", bulletColor=NAVY, bulletFontName="Helvetica-Bold",
        bulletFontSize=10, leftIndent=18, spaceAfter=6,
    )


# --- story ------------------------------------------------------------------
story = [
    P(C["title"], "title"),
    P(C["subtitle"], "subtitle"),
    HRFlowable(width="100%", thickness=1.4, color=NAVY, spaceBefore=2, spaceAfter=12),
    table({"rows": C["meta"], "w1": 2200}, with_header=False),
]

for section in C["sections"]:
    # Start a new page only when too little room is left for the heading plus
    # a few lines of its content; otherwise let tables and lists split naturally.
    story.append(CondPageBreak(1.6 * inch))
    story.append(P(section["h"], "h1"))
    for b in section["blocks"]:
        if "p" in b:
            story.append(P(b["p"], spaceBefore=b["before"] / 20) if b.get("before") else P(b["p"]))
        elif "table" in b:
            story += [table(b["table"], with_header=any(b["table"]["header"])), Spacer(1, 6)]
        elif "bullets" in b:
            story.append(bullets(b["bullets"]))
        else:
            story.append(numbers(b["numbers"]))

story += [
    HRFlowable(width="100%", thickness=0.6, color=RULE, spaceBefore=12, spaceAfter=6),
    P(C["disclaimer"], "small"),
]


# --- canvas with "Page X of Y" ------------------------------------------------
class NumberedCanvas(rl_canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pages = []

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for state in self._pages:
            self.__dict__.update(state)
            self._draw_footer(total)
            super().showPage()
        super().save()

    def _draw_footer(self, total):
        y = MARGIN - 28
        self.saveState()
        self.setStrokeColor(RULE)
        self.setLineWidth(0.5)
        self.line(MARGIN, y + 12, PAGE_W - MARGIN, y + 12)
        self.setFont("Helvetica", 8)
        self.setFillColor(MUTED)
        self.drawString(MARGIN, y, C["footer"])
        self.drawRightString(PAGE_W - MARGIN, y, f"Page {self._pageNumber} of {total}")
        self.restoreState()


doc = BaseDocTemplate(
    OUT, pagesize=letter, leftMargin=MARGIN, rightMargin=MARGIN,
    topMargin=MARGIN, bottomMargin=MARGIN,
    title="Takeover Hunter Acquisition Brief", author="Takeover Hunter",
)
frame = Frame(MARGIN, MARGIN, CONTENT_W, PAGE_H - 2 * MARGIN,
              leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
doc.addPageTemplates([PageTemplate(id="main", frames=[frame])])

if os.environ.get("PAGEMAP"):
    _seen = set()
    def _after(fl):
        pg = doc.page
        if pg not in _seen and isinstance(fl, Table):
            _seen.add(pg)
            print(f"  p{pg} starts: <table>")
        elif pg not in _seen and hasattr(fl, "getPlainText"):
            _seen.add(pg)
            print(f"  p{pg} starts: {fl.getPlainText()[:70]!r}")
        elif pg not in _seen and isinstance(fl, ListFlowable):
            _seen.add(pg)
            print(f"  p{pg} starts: <list>")
    doc.afterFlowable = _after
doc.build(story, canvasmaker=NumberedCanvas)
print("wrote", OUT)
