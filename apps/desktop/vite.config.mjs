import {defineConfig} from 'vite';
export default defineConfig({base:'./',build:{target:'es2022',sourcemap:false,chunkSizeWarningLimit:1500},server:{strictPort:true,port:1420},clearScreen:false});
