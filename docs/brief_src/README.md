# Acquisition brief sources

`brief_content.json` is the single source for the client-facing brief. Both
builders render from it, so the DOCX and PDF cannot drift apart.

```bash
cd docs/brief_src
npm install docx          # once
pip install reportlab     # once
node build_docx.js ../ACQUISITION_BRIEF.docx
python3 build_pdf.py ../ACQUISITION_BRIEF.pdf
```

Set `PAGEMAP=1` when running `build_pdf.py` to print which content opens each
page, useful for checking page breaks after editing the copy.

Keep seller-internal pricing (floor, expected clearing range) out of
`brief_content.json`; it belongs only in `../ACQUISITION_BRIEF.md`.
