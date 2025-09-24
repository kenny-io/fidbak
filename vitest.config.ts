import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['packages/**/src/**/*.{test,spec}.ts?(x)', 'apps/**/src/**/*.{test,spec}.ts?(x)'],
    coverage: {
      reporter: ['text', 'html'],
    },
  },
});
