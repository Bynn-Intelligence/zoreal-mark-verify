import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  // Everything the verifier needs is a WHATWG or Web Crypto API, so the same
  // build runs in a browser, a service worker, a Safari extension and Node 22.
  platform: 'neutral',
  target: 'es2022',
});
