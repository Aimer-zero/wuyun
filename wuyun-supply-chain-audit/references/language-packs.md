# Language Pack Selection

Use language/framework signals to choose deeper review patterns:

- Node/Next.js: SSR/CSR boundaries, server actions, prototype pollution, template injection, package lifecycle scripts
- Python/Django/FastAPI/Flask: SQL/ORM boundaries, deserialization, template rendering, subprocess, async background tasks
- Java/Spring: Spring Security, Actuator exposure, SpEL, unsafe deserialization, path traversal, SSRF clients
- Go: `net/http`, template escaping, goroutine/context leaks, command execution, archive/path extraction
- Rust: `unsafe`, FFI, panic boundaries, crypto misuse, path/canonicalization, serde formats
- C/C++: memory safety, integer overflow, lifetime, parser surfaces, unsafe string APIs
- Mobile: APK/iOS secrets, WebView bridges, certificate pinning, storage, deep links
- Smart contracts: ownership, reentrancy, price oracle trust, upgradeability, arithmetic, signature replay
