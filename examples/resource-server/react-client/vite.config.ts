import react from '@vitejs/plugin-react-swc';
import { defineConfig } from 'vite';

// The seeded app allows only the origin http://localhost:5173, so a silent move
// to another port would fail as a CORS error. strictPort makes it a startup error.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, strictPort: true },
  preview: { port: 5173, strictPort: true },
});
