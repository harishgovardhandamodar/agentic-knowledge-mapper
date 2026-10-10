// Copies the Next.js static export into ../static/fluid, where the FastAPI
// app serves it (app/main.py mounts static/ at /static and serve_fluid reads
// static/fluid). Portable Node rather than `cp -r` so it behaves the same on
// Linux, macOS and Windows.
import { cp, mkdir, rm, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(here, '..', 'out');
const destDir = resolve(here, '..', '..', 'static', 'fluid');

async function main() {
  try {
    await access(outDir);
  } catch {
    console.error(
      `[export-to-static] no export at ${outDir} — did "next build" run?`,
    );
    process.exit(1);
  }
  await mkdir(dirname(destDir), { recursive: true });
  await rm(destDir, { recursive: true, force: true });
  await cp(outDir, destDir, { recursive: true });
  console.log(`[export-to-static] ${outDir} -> ${destDir}`);
}

main().catch((err) => {
  console.error('[export-to-static] failed:', err);
  process.exit(1);
});
