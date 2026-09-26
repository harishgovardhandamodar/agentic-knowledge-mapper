/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_BENCH_API?: string;
  readonly VITE_BENCH_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}