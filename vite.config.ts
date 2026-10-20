import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({ plugins: [react()], server: { proxy: { '/api': 'http://127.0.0.1:3001', '/mock': 'http://127.0.0.1:3001', '/hooks': 'http://127.0.0.1:3001' } } });
