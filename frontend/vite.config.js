import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '127.0.0.1',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout: 1_800_000,
        proxyTimeout: 1_800_000,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Charting and animation are heavy and only needed on a few screens.
        // Splitting them out keeps the login and dashboard payload small and
        // lets the browser cache vendor code across application deploys.
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          charts: ['chart.js', 'react-chartjs-2'],
          motion: ['framer-motion'],
          forms: ['formik', 'yup'],
        },
      },
    },
  },
})
