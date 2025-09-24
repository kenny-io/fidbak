import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    format: ['esm'],
    dts: true,
    sourcemap: true,
    minify: true,
    clean: true,
    target: 'es2018',
  },
  {
    entry: { 'fidbak.fab.min': 'src/umd.ts' },
    format: ['iife'],
    globalName: 'FidbakUMD',
    dts: false,
    sourcemap: false,
    minify: true,
    clean: false,
    target: 'es2018',
  },
]);
