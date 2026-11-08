import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  resolve: { tsconfigPaths: true },
  server: {
    host: true,
    proxy: { '/api': process.env.LABWARDEN_API ?? 'http://localhost:8080' },
  },
  build: { chunkSizeWarningLimit: 600 },
})
