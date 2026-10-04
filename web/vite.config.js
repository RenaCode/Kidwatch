import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Ten sam uklad co w Trader-AI: front wola /api/... bez znajomosci hosta.
// Lokalnie proxy idzie do `python -m kidwatch run` z panel.enabled=true.
// Jeden obiekt dla `server` i `preview` - powod opisany w Trader-AI/web.
const proxy = {
  '/api': { target: process.env.API_URL || 'http://127.0.0.1:8080', changeOrigin: true },
};

export default defineConfig({
  plugins: [react()],
  server: { port: 5175, proxy },
  preview: { port: 4174, proxy },
});
