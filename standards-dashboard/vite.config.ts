import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    proxy: {
      // Same-origin path the Benchmark tab uses (see src/lib/config.ts).
      '/api/benchmark': {
        target: 'http://localhost:5250',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://localhost:5250',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./test/setup.ts'],
  },
});