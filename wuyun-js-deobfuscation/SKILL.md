---
name: wuyun-js-deobfuscation
description: JavaScript AST deobfuscation and web-signature analysis companion for Wuyun. Use for obfuscated JS bundles, AST-based triage, string-array and control-flow-flattening detection, eval/Function unpacking leads, webpack/vite module recovery, sourcemap correlation, WebCrypto/CryptoJS/WASM signing logic discovery, replay-window analysis, and safe transformation planning without executing unknown code.
---

# Wuyun JS Deobfuscation

Use this companion with `$wuyun-js-reverse` when JavaScript is obfuscated, packed, split across chunks, or hides protocol/signature logic.

## Safety Boundary

- Prefer static AST/text analysis and local lab fixtures. Do not execute unknown bundles by default.
- Do not produce credential theft, stealth bypass, CAPTCHA automation, or production control-evasion instructions.
- Treat deobfuscated output as sensitive evidence if it reveals secrets, internal APIs, or proprietary logic.
- Keep transformations reversible and evidence-linked: original file, rule, line/offset, output artifact, and confidence.

## Workflow

1. **Triage**:
   - Run `scripts/deobfuscation_triage.py <path>` to classify obfuscation, packing, crypto/signature, sourcemap, and WASM signals.
2. **Select pipeline**:
   - Load `references/ast-deobfuscation.md` for Babel/Acorn/SWC transform planning.
   - Load `references/signature-protocol.md` for request signing, nonce/timestamp, replay-window, and client-secret analysis.
   - Load `references/wasm-analysis.md` when WASM glue or `WebAssembly.*` appears.
3. **Recover structure**:
   - Identify module loaders, request wrappers, signing helpers, API constants, string arrays, and state machines.
   - Use source maps when available before manual deobfuscation.
4. **Validate meaning**:
   - Confirm whether recovered logic affects a server-side trust boundary.
   - Feed endpoints/protocols to `$wuyun-web-api-audit` and runtime questions to `$wuyun-browser-runtime`.
5. **Report**:
   - Separate deobfuscation leads from confirmed vulnerabilities.
   - Include transformation plan, evidence locations, confidence, and safe validation.

## References

- `references/ast-deobfuscation.md`: AST workflow, transform ordering, false-positive reducers, and evidence tracking.
- `references/signature-protocol.md`: web request signing and protocol analysis.
- `references/wasm-analysis.md`: WASM/glue-code triage and safe static analysis.

## Output Shape

```markdown
## JS Deobfuscation Outcome
- Status: triaged | transform-plan | recovered-logic | needs-runtime | ruled-out
- Artifact:
- Obfuscation class:
- Security-relevant logic:

## Evidence
- File/path/line:
- Signal:
- Confidence:

## Transform Plan
- Step:
- Tool:
- Expected proof:
- Rollback:

## Security Follow-Up
- Server trust boundary:
- Replay/signature hypothesis:
- Runtime observation needed:
```
