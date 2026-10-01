FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Headless Chromium draws arbitrary mermaid figures (flowcharts, sequence
# diagrams, mindmaps) to PNG so the PDF shows pictures, not source text.
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Pinned mermaid renderer, vendored so PDF export needs no network.
ADD https://cdn.jsdelivr.net/npm/mermaid@10.9.4/dist/mermaid.min.js \
    /app/static/vendor/mermaid.min.js

EXPOSE 8204

RUN mkdir -p /app/data

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8204"]
