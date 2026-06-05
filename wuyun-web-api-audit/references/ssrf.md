# Web/API SSRF Review

Use for URL fetchers that may reach internal services or cloud metadata.

## Sources

- `url`, `callback`, `webhook`, `avatar_url`, `image`, `import`, `feed`, `redirect`, `target`.
- XML/HTML/PDF parsers that load external resources.
- Server-side browsers/screenshots and link preview services.

## Controls to Check

- Scheme allowlist; host allowlist; final resolved IP private-range deny.
- Revalidation after redirects.
- DNS pinning or resolve/connect mismatch.
- Timeouts, response-size caps, and egress restrictions.

## Safe Validation

- Controlled callback server proof is preferred.
- Do not target metadata endpoints in production-like scope.
- For cloud metadata/STS tasks, load `$wuyun-cloud-vuln`.
