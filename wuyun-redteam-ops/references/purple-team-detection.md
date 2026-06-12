# Purple-Team Detection and Remediation Mapping

Use this reference after `redteam_plan.py` or `attack_path_matrix.py` identifies attack paths. The objective is to convert each path into owner-reviewed telemetry, safe emulation, remediation tests, and retest criteria.

## Mapping workflow

1. **Start from local artifacts**: attack matrix, redteam plan, HAR, OpenAPI, JS surface, auth, cloud, or AI audit outputs.
2. **Assign a category**: web, cloud, identity, protocol, AI, WAF/CDN, internal, or CTF/lab.
3. **Define telemetry**: logs and decision points that should prove whether the safe emulation was seen and handled correctly.
4. **Define detection objective**: one observable behavior for owner-approved synthetic activity; avoid stealth or bypass goals.
5. **Define safe emulation**: smallest canary/synthetic action that exercises the boundary without touching unrelated data.
6. **Define remediation tests**: code/config/control tests that would break the attack path.
7. **Record evidence ledger**: path id, source, controlled input, expected log/decision, observed result, redaction status, owner confirmation, retest status.

## Safe defaults by category

| Category | Safe emulation focus | Telemetry focus |
|---|---|---|
| Web/API | synthetic account/object authorization checks | route, principal, tenant/object id, allow/deny reason |
| Cloud | metadata-safe canaries and synthetic storage access | control-plane audit, egress, object access logs |
| Identity | offline token/flow structure and test-tenant validation | IdP, token validation, session lifecycle, auth middleware |
| Protocol | request-shape and replay-window validation in test scope | WebSocket/RPC/GraphQL operation and decision logs |
| AI | benign canary prompts/documents | prompt, retrieval, tool-call, output-sink policy logs |
| WAF/CDN | Ray IDs and owner-assisted challenge attribution | CDN/WAF rule id, action, origin correlation |
| Internal | low-privilege synthetic admin/CI checks | admin, CI/CD, config, and dependency change logs |
| CTF/lab | replayable lab transcript and lesson capture | challenge-scoped logs, artifact hashes, offsets |

## Blocked actions

Do not turn detection mapping into stealth, persistence, malware, credential theft, data dumping, WAF bypass payload packs, CAPTCHA automation, proxy rotation, or request fingerprint spoofing. If a detection objective would require those actions, document the gap and request owner-assisted validation instead.
