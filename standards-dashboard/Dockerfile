# Dashboard image: build static TSX bundle, serve via nginx.
# Base images are pinned by digest (frozen 2026-09-20); refresh with:
#   docker buildx imagetools inspect node:20-alpine --format '{{json .Manifest}}'
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY index.html vite.config.ts tsconfig.json ./
COPY src/ ./src/
COPY data/ ./data/
COPY scripts/ ./scripts/
COPY public/ ./public/
# Optional build-time override for the Benchmark tab's backend API (see README).
# Default "" = same origin: nginx proxies /api/benchmark to benchmark-api.
ARG VITE_BENCH_API=
ENV VITE_BENCH_API=$VITE_BENCH_API
RUN node scripts/ingest.mjs && npm run build

FROM nginx@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist/ /usr/share/nginx/html/
EXPOSE 80
