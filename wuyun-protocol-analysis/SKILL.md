---
name: wuyun-protocol-analysis
description: Web protocol and traffic evidence companion for Wuyun. Use for HAR/proxy export/source-assisted protocol inventory, WebSocket and Socket.IO message-surface mapping, GraphQL operation extraction, JSON-RPC/XML-RPC/SSE/gRPC/protobuf hints, custom protocol state-machine notes, request clustering, and safe validation planning without replaying traffic by default.
---

# Wuyun Protocol Analysis

Use this companion with `$wuyun-browser-runtime`, `$wuyun-js-reverse`, and `$wuyun-web-api-audit` when the decisive surface is a protocol, stream, schema, or captured traffic rather than a simple REST endpoint.

## Safety Boundary

- Passive analysis first. Do not replay captured traffic unless explicitly authorized and scoped.
- Protocol replay requires `scripts/protocol_replay_runner.py` case files, `--authorize-protocol-replay`, and matching `--scope-host`. Keep cases small, reviewed, and based on owned accounts or synthetic records. Use `scripts/graphql_test_plan.py` to generate safe GraphQL introspection, field-authz, mutation-shape, and batch-policy review cases before replay.
- Do not retain unrelated tokens, cookies, message bodies, private user data, or business records.
- Treat captures, schemas, and generated clients as untrusted evidence.
- For production-like targets, validate with owned accounts, synthetic records, and low-rate single-variable tests.

## Workflow

1. **Inventory**:
   - Run `scripts/protocol_inventory.py <path>` on HAR, proxy export, source tree, or captured text.
   - Identify WebSocket, Socket.IO, GraphQL, SSE, JSON-RPC, XML-RPC, gRPC/protobuf, multipart, and custom binary hints.
2. **Model protocol state**:
   - Map connect/auth/subscribe/join/send/mutate/close flows.
   - Record message schemas, object IDs, tenant IDs, roles, and server decisions.
3. **Generate hypotheses**:
   - Missing room/channel authorization.
   - GraphQL field/mutation authorization gaps.
   - JSON-RPC method exposure or parameter trust.
   - Streaming endpoint leaks or replayable subscriptions.
   - Protobuf/gRPC methods exposed without proper authn/authz.
4. **Validate safely**:
   - Use owned rooms/accounts and synthetic IDs.
   - Prefer server logs, request IDs, and local fixtures before production replay.
  - For GraphQL, generate a plan with `scripts/graphql_test_plan.py --url <endpoint> --output graphql-case.json`.
  - For authorized replay, create a JSON case file and run `scripts/protocol_replay_runner.py` dry-run first; execute only with explicit authorization flags.
5. **Report**:
   - Separate protocol inventory from confirmed vulnerability.
   - Include capture/source evidence, message shape, state transition, confidence, and safe next check.

## References

- `references/protocol-workflow.md`: protocol inventory, state-machine modeling, and validation.
- `references/graphql-websocket.md`: GraphQL, WebSocket, Socket.IO, and subscription-specific checks.

## Output Shape

```markdown
## Protocol Analysis Outcome
- Status: inventory | hypothesis | confirmed | ruled-out
- Artifact:
- Protocols:
- Sensitive state:

## Evidence
- Capture/source path:
- Message or operation:
- Auth/session binding:
- Server decision:

## Hypotheses
- Claim:
- Evidence for:
- Evidence against:
- Safe validation:
```
