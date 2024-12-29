import { resolve } from 'path'
import { defineConfig } from 'vite'
import dts from 'vite-plugin-dts'

// https://vitejs.dev/guide/build.html#library-mode
export default defineConfig({
    build: {
        lib: {
            entry: resolve(__dirname, 'dist/index.d.ts'),
            name: 'safe-deposit-core',
            fileName: 'safe-deposit-core',
        },
    },
    plugins: [dts(
        {
            tsconfigPath: './tsconfig.json'
        }
    )]
})