# Fluid UI build: the parallel Next.js GUI (fluid/) is statically exported and
# served by FastAPI at /fluid. Built in a node stage so the runtime image stays
# slim and python-only.
FROM node:22-slim AS fluid-build
WORKDIR /build
COPY fluid/package.json fluid/package-lock.json* ./fluid/
RUN cd fluid && (npm ci --no-audit --no-fund || npm install --no-audit --no-fund)
COPY fluid/ ./fluid/
# `next build` exports to fluid/out, then scripts/export-to-static.mjs copies it
# to ../static/fluid, i.e. /build/static/fluid.
RUN cd fluid && npm run build

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Headless Chromium draws arbitrary mermaid figures (flowcharts, sequence
# diagrams, mindmaps) to PNG so the PDF shows pictures, not source text.
# pandoc + a LaTeX engine print the full dossier Markdown as an A4 report with
# a table of contents (matching the sample dossier PDF).
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium fonts-dejavu-core \
    pandoc \
    texlive-latex-base texlive-latex-recommended texlive-latex-extra \
    texlive-fonts-recommended texlive-fonts-extra lmodern \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Fluid UI assets from the node stage (overrides anything checked in).
COPY --from=fluid-build /build/static/fluid /app/static/fluid

# Pinned mermaid renderer, vendored so PDF export needs no network.
ADD https://cdn.jsdelivr.net/npm/mermaid@10.9.4/dist/mermaid.min.js \
    /app/static/vendor/mermaid.min.js

EXPOSE 8204

RUN mkdir -p /app/data

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8204"]
