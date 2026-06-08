# AST Deobfuscation Workflow

Use deterministic transforms when possible. Keep the original artifact and transformation notes.

## Preferred Order

1. Identify bundler/module loader: webpack, vite, rollup, parcel, systemjs.
2. Recover sourcemaps before transforms.
3. Beautify only for readability; do not treat beautified code as recovered semantics.
4. Decode string arrays and literal encodings.
5. Constant fold deterministic expressions.
6. Simplify dead branches only when the condition is proven constant.
7. Identify control-flow flattening and dispatcher variables.
8. Rename symbols by role only after call graph evidence.
9. Extract request wrappers, signing functions, crypto helpers, and protocol schemas.

## Signals

- string arrays with numeric/hex indexers,
- `eval`, `Function`, timer-string execution,
- self-defending checks and debugger loops,
- `while(true)` plus `switch` dispatcher,
- large hex/unicode escaped literals,
- module loader wrappers,
- WebAssembly glue,
- CryptoJS/WebCrypto calls.

## False-Positive Reducers

- Minification is not obfuscation.
- Dead-looking code can be feature-flagged or lazy-loaded.
- A decoded string is a lead; server behavior still requires validation.
- Public API keys and publishable client IDs may be intended.

## Evidence Tracking

For every transform:

- source file and hash if available,
- line/offset before transform,
- transform rule,
- output path,
- semantic claim,
- confidence and contradiction.
