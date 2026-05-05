import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    lib: {
      entry: 'src/index.ts',
      formats: ['es'],
      fileName: () => 'index.js',
    },
    rollupOptions: {
      external: ['libsodium-wrappers-sumo', 'shamir-secret-sharing'],
    },
    sourcemap: true,
  },
})
