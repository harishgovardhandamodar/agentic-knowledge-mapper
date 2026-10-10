/** @type {import('next').NextConfig} */

// The FastAPI app serves this build from static/fluid/ at the URL prefix
// /fluid (see app/main.py::serve_fluid). A static export plus matching
// basePath keeps every asset and client route under that prefix, and the
// postbuild step (scripts/export-to-static.mjs) drops `out/` into
// ../static/fluid so the Docker build stage and the dev backend both find it.
const isDev = process.env.NODE_ENV !== 'production';

const nextConfig = {
  output: 'export',
  basePath: '/fluid',
  assetPrefix: '/fluid/',
  // Every route becomes a real directory with index.html, so the FastAPI
  // catch-all can serve a deep link directly instead of falling back to the
  // root shell.
  trailingSlash: true,
  reactStrictMode: true,
  images: { unoptimized: true },
  eslint: { ignoreDuringBuilds: true },
  // Rewrites are not applied to a static export, so they exist only for the
  // dev server, proxying /api to the running FastAPI backend.
  ...(isDev
    ? {
        async rewrites() {
          return [
            {
              source: '/api/:path*',
              destination: 'http://localhost:8204/api/:path*',
            },
          ];
        },
      }
    : {}),
};

export default nextConfig;
