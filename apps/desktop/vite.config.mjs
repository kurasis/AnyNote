import {defineConfig} from 'vite';
import {fileURLToPath} from 'node:url';
export default defineConfig({base:'./',build:{target:'es2022',rollupOptions:{input:{main:fileURLToPath(new URL('./index.html',import.meta.url)),preview:fileURLToPath(new URL('./auth/preview.html',import.meta.url))}},sourcemap:false,chunkSizeWarningLimit:1500},server:{strictPort:true,port:1420},clearScreen:false});
