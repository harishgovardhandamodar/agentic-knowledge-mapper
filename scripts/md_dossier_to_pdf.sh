#!/usr/bin/env bash
# Dossier Markdown -> PDF via pandoc + LaTeX (A4, TOC, long tables).
#
# Usage:  scripts/md_dossier_to_pdf.sh dossier.md out.pdf
#
# This is the CLI twin of app/dossier_pdf.py: it does NOT render mermaid to
# images (the app does that through its headless-Chromium cache before calling
# pandoc). If the markdown still contains ```mermaid fences, pandoc prints them
# as source code — run the app export for rendered figures.
set -euo pipefail

IN="${1:?usage: md_dossier_to_pdf.sh <dossier.md> <out.pdf>}"
OUT="${2:?usage: md_dossier_to_pdf.sh <dossier.md> <out.pdf>}"
ENGINE="${AKM_PDF_ENGINE:-pdflatex}"

command -v pandoc >/dev/null 2>&1 || { echo "pandoc not found (apt-get install pandoc)" >&2; exit 2; }
command -v "$ENGINE" >/dev/null 2>&1 || { echo "LaTeX engine '$ENGINE' not found (apt-get install texlive-latex-base texlive-latex-recommended texlive-fonts-recommended)" >&2; exit 2; }

HDR="$(mktemp -t dossier-hdr-XXXX.tex)"
cat > "$HDR" <<'TEX'
\usepackage{longtable}
\usepackage{booktabs}
\usepackage{graphicx}
\usepackage{url}
\setkeys{Gin}{width=\linewidth,keepaspectratio}
\setlength{\parskip}{0.4em}
TEX

pandoc "$IN" -o "$OUT" \
  --pdf-engine="$ENGINE" \
  --toc --toc-depth=2 \
  -V geometry:a4paper,margin=25mm \
  -V fontsize=11pt \
  -V colorlinks=true \
  --from markdown+pipe_tables+fenced_code_blocks+raw_html \
  --highlight-style=tango \
  --resource-path="$(dirname "$IN")" \
  -H "$HDR"
rm -f "$HDR"

echo "wrote $OUT"
