import { defineConfig, loadEnv } from 'vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const backend = env.VITE_DEV_BACKEND_TARGET || 'http://127.0.0.1:8001'
  const proxy = {
    '/api': { target: backend, changeOrigin: true, ws: true },
    '/health': { target: backend, changeOrigin: true },
  }

  return {
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy,
    },
    preview: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy,
    },
  }
})
