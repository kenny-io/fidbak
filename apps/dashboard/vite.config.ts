import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      '/v1': {
        target: 'http://localhost:8787',
        changeOrigin: true,
      },
    },
  },
});
