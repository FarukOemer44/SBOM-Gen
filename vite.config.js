import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,               // im ganzen Netz erreichbar, nicht nur auf diesem Rechner
    port: 5200,
    strictPort: true,         // lieber Fehler als stiller Wechsel auf 5201 — die geteilte Adresse bleibt gueltig
    allowedHosts: ['.local'], // Zugriff ueber MacBook-Pro-von-Omer.local zulassen
    proxy: { '/api': 'http://127.0.0.1:5178' },
  },
})
