#!/usr/bin/env bash
# Build the evidence-backed expanded draft; preserve the original PAPER.pdf.
set -euo pipefail
PROJECT=$(cd "$(dirname "$0")/.." && pwd)
cd "$PROJECT"
python3 scripts/render_research_tex.py --simulation results/research_simulation_v2 \
  --mitigation results/mitigation_analysis_v3 \
  --scale-smoke results/scale_200source_smoke_v4/summary.json --out report_ieee/generated
cd report_ieee
pdflatex -interaction=nonstopmode -halt-on-error main.tex > build_pass1.txt
bibtex main > build_bibtex.txt
pdflatex -interaction=nonstopmode -halt-on-error main.tex > build_pass2.txt
pdflatex -interaction=nonstopmode -halt-on-error main.tex > build_pass3.txt
cp main.pdf "$PROJECT/../REVISED_PAPER.pdf"
echo "Built $PROJECT/../REVISED_PAPER.pdf (expanded research draft, not venue-length submission)"
