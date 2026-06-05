# OpenAPI / Swagger Review

Use the spec as an attack-surface map, not proof that runtime behavior matches.

## Checks

- Operations missing `security` while neighboring endpoints require it.
- Sensitive methods: DELETE/PATCH/PUT/POST exports/imports/admin actions.
- Path/query/body parameters named `id`, `userId`, `tenantId`, `role`, `status`, `price`, `redirect`, `url`, `file`, `path`.
- Schemas exposing writable `role`, `isAdmin`, `ownerId`, `tenantId`, `balance`, or `status`.
- Deprecated or undocumented endpoints still present in runtime.

## Safe Use

Run:

```bash
python3 wuyun-web-api-audit/scripts/analyze_openapi.py openapi.yaml
```

Then validate high-risk leads against code or controlled requests.
