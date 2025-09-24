import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 5181,
    fs: {
      // allow serving files from monorepo root for /@fs absolute paths
      strict: false,
    },
  },
});
