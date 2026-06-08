# WASM Triage

Use this when JavaScript references `WebAssembly`, `.wasm`, Emscripten, wasm-bindgen, or binary modules.

## Static Signals

- `WebAssembly.instantiate`, `instantiateStreaming`, `compile`,
- `.wasm` paths,
- Emscripten glue: `Module`, `HEAPU8`, `ccall`, `cwrap`,
- wasm-bindgen glue: `__wbg_`, `wasm_bindgen`,
- imports/exports related to crypto, sign, hash, encode, verify.

## Safe Analysis

- Extract imports/exports and strings from local artifacts.
- Link JS glue functions to request signing or protocol code.
- Prefer local lab execution only when explicitly authorized.
- Do not patch production controls or distribute bypassed binaries.

## Follow-Up

- Identify JS caller and arguments.
- Determine whether WASM protects a client-exposed secret or only implements public logic.
- Feed recovered request behavior into Web/API validation.
