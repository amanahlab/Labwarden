import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  resolve: { tsconfigPaths: true },
  server: {
    host: true,
    proxy: { '/api': process.env.LABWARDEN_API ?? 'http://localhost:8080' },
  },
  build: {
    chunkSizeWarningLimit: 600,
    // The CSP has no font-src, so default-src 'self' blocks data: fonts:
    // always emit fonts as files. Other small assets keep the default.
    assetsInlineLimit: (file) => (file.endsWith('.woff2') || file.endsWith('.woff') ? false : undefined),
  },
})
