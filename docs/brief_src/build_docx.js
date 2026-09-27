// Render the client acquisition brief to DOCX from brief_content.json.
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, ShadingType, BorderStyle,
  LevelFormat, Footer, PageNumber, TabStopType,
} = require("docx");

const OUT = process.argv[2] || "ACQUISITION_BRIEF.docx";
const C = JSON.parse(fs.readFileSync(path.join(__dirname, "brief_content.json"), "utf8"));

const NAVY = "1F3A5F", ACCENT = "2E6B8F", GREY = "404040", LIGHT = "EEF2F6";
const RULE = "9DB2C6", MUTED = "8A8A8A", FONT = "Calibri";
const CONTENT_W = 9648; // US Letter 12240 minus 2 x 1296 (0.9in) margins

// "**bold**" inline markup -> TextRuns
function runs(text, o = {}) {
  return String(text).split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map((part) => {
    const bold = part.startsWith("**") && part.endsWith("**");
    return new TextRun({
      text: bold ? part.slice(2, -2) : part,
      bold: bold || !!o.bold, color: o.color || GREY, size: o.size || 21, font: FONT,
    });
  });
}

const para = (text, before = 0) => new Paragraph({
  spacing: { before, after: 140, line: 288 }, children: runs(text),
});

const heading = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_1,
  keepNext: true,
  spacing: { before: 300, after: 120 },
  children: [new TextRun({ text, bold: true, color: NAVY, size: 28, font: FONT })],
});

const listItem = (text, ref) => new Paragraph({
  numbering: { reference: ref, level: 0 },
  spacing: { after: 100, line: 288 },
  children: runs(text),
});

const rule = (color, size, before, after) => new Paragraph({
  spacing: { before, after },
  border: { bottom: { color, space: 1, style: BorderStyle.SINGLE, size } },
  children: [],
});

const cellMargins = { top: 70, bottom: 70, left: 130, right: 130 };

function table({ header, rows, w1 = 2600 }, withHeader = true) {
  const w2 = CONTENT_W - w1;
  const cell = (children, width, fill) => new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: fill ? { type: ShadingType.CLEAR, color: "auto", fill } : undefined,
    margins: cellMargins,
    children: [new Paragraph({ spacing: { after: 0, line: 264 }, children })],
  });
  const out = [];
  if (withHeader) {
    out.push(new TableRow({
      tableHeader: true,
      children: header.map((h, i) => cell(
        [new TextRun({ text: h, bold: true, color: "FFFFFF", size: 20, font: FONT })],
        i === 0 ? w1 : w2, NAVY)),
    }));
  }
  rows.forEach((r, i) => {
    const fill = i % 2 ? "FFFFFF" : LIGHT;
    out.push(new TableRow({
      cantSplit: true,
      children: [
        cell([new TextRun({ text: r[0], bold: true, color: NAVY, size: 20, font: FONT })], w1, fill),
        cell(runs(r[1], { size: 20 }), w2, fill),
      ],
    }));
  });
  const line = { style: BorderStyle.SINGLE, size: 2, color: RULE };
  const inner = { style: BorderStyle.SINGLE, size: 1, color: "D2DBE6" };
  return new Table({
    columnWidths: [w1, w2],
    width: { size: CONTENT_W, type: WidthType.DXA },
    borders: { top: line, bottom: line, left: line, right: line, insideHorizontal: inner, insideVertical: inner },
    rows: out,
  });
}

// ---- build body ----------------------------------------------------------
const children = [];
const numberingRefs = [];

children.push(new Paragraph({ spacing: { after: 0 },
  children: [new TextRun({ text: C.title, bold: true, color: NAVY, size: 52, font: FONT })] }));
children.push(new Paragraph({ spacing: { after: 60 },
  children: [new TextRun({ text: C.subtitle, color: ACCENT, size: 30, font: FONT })] }));
children.push(rule(NAVY, 10, 0, 180));
children.push(table({ header: ["", ""], rows: C.meta, w1: 2200 }, false));

let listCounter = 0;
for (const section of C.sections) {
  children.push(heading(section.h));
  for (const b of section.blocks) {
    if (b.p) children.push(para(b.p, b.before || 0));
    else if (b.table) {
      children.push(table(b.table, b.table.header.some(Boolean)));
      children.push(new Paragraph({ spacing: { after: 60 }, children: [] }));
    } else if (b.bullets) b.bullets.forEach((t) => children.push(listItem(t, "bullets")));
    else if (b.numbers) {
      const ref = `num${++listCounter}`; // own reference so each list restarts at 1
      numberingRefs.push(ref);
      b.numbers.forEach((t) => children.push(listItem(t, ref)));
    }
  }
}

children.push(rule(RULE, 6, 240, 100));
children.push(new Paragraph({ spacing: { after: 0, line: 264 },
  children: [new TextRun({ text: C.disclaimer, italics: true, color: MUTED, size: 17, font: FONT })] }));

const level = (format, text) => [{
  level: 0, format, text, alignment: AlignmentType.LEFT,
  style: {
    paragraph: { indent: { left: 480, hanging: 280 } },
    run: format === LevelFormat.DECIMAL ? { bold: true, color: NAVY } : { color: ACCENT },
  },
}];

const doc = new Document({
  creator: "Takeover Hunter",
  title: "Takeover Hunter Acquisition Brief",
  numbering: {
    config: [
      { reference: "bullets", levels: level(LevelFormat.BULLET, "•") },
      ...numberingRefs.map((ref) => ({ reference: ref, levels: level(LevelFormat.DECIMAL, "%1.") })),
    ],
  },
  sections: [{
    properties: { page: {
      size: { width: 12240, height: 15840 },
      margin: { top: 1296, bottom: 1296, left: 1296, right: 1296 },
    } },
    footers: { default: new Footer({ children: [new Paragraph({
      border: { top: { color: RULE, space: 6, style: BorderStyle.SINGLE, size: 4 } },
      tabStops: [{ type: TabStopType.RIGHT, position: CONTENT_W }],
      children: [
        new TextRun({ text: C.footer, color: MUTED, size: 16, font: FONT }),
        new TextRun({ text: "\t", size: 16 }),
        new TextRun({ children: ["Page ", PageNumber.CURRENT, " of ", PageNumber.TOTAL_PAGES], color: MUTED, size: 16, font: FONT }),
      ],
    })] }) },
    children,
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(OUT, buf);
  console.log("wrote", OUT, buf.length, "bytes");
});
