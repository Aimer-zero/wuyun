# Wuyun JS Deobfuscation Prompt

```text
Use $wuyun, $wuyun-js-reverse, and $wuyun-js-deobfuscation.
Mode: js-deobfuscation.
Artifact: ./dist/app.bundle.js or ./chunks/.

Please triage obfuscation, signing logic, WebCrypto/CryptoJS, WASM glue, sourcemaps, and bundler module structure.
Do not execute unknown JavaScript.

Output:
- obfuscation class
- AST transform plan
- signing/protocol hypotheses
- WASM or sourcemap follow-up
- evidence locations and confidence
- safe Web/API validation handoff
```
