import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      'vis-network/standalone': path.resolve(__dirname, 'node_modules/vis-network/standalone/umd/vis-network.min.js'),
      'vis-network': path.resolve(__dirname, 'node_modules/vis-network/standalone/umd/vis-network.min.js'),
    },
  },
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://localhost:8000', changeOrigin: true } },
  },
});
