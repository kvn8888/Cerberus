import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { execSync } from 'child_process'

// Get the short git commit hash at build time (falls back to "dev")
const commitHash = (() => {
  try {
    return execSync('git rev-parse --short HEAD').toString().trim()
  } catch {
    return 'dev'
  }
})()

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  define: {
    // Inject the commit hash as a global constant available at runtime
    __COMMIT_HASH__: JSON.stringify(commitHash),
  },
})
