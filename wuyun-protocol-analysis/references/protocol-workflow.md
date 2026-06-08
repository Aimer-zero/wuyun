# Protocol Analysis Workflow

Use this for HAR/proxy exports, source-assisted traffic analysis, WebSocket captures, streaming APIs, RPC schemas, and custom message protocols.

## Inventory Fields

- protocol,
- host/path,
- method or message type,
- auth/session source,
- object/tenant/channel identifiers,
- state transition,
- server response/decision,
- sensitivity,
- confidence.

## State Machine Template

```markdown
## Protocol State Machine
- Connect:
- Authenticate:
- Subscribe/join:
- Send/mutate:
- Receive:
- Error/deny:
- Close:
```

## Replay Case Template

Use reviewed case files with `scripts/protocol_replay_runner.py`. Keep them small and scoped.

```json
{
  "type": "graphql",
  "url": "https://app.example.com/graphql",
  "headers": {
    "content-type": "application/json"
  },
  "baseline": {
    "operationName": "Viewer",
    "query": "query Viewer($id: ID!) { viewer(id: $id) { id } }",
    "variables": {
      "id": "owned-user-1"
    }
  },
  "probes": [
    {
      "label": "synthetic-other-id",
      "variables": {
        "id": "synthetic-user-2"
      }
    }
  ]
}
```

Execute only with `--authorize-protocol-replay` and matching `--scope-host`.

## Common Risks

- channel/room ID trusted from client,
- subscription continues after privilege change,
- GraphQL mutation lacks object ownership check,
- JSON-RPC exposes admin methods,
- SSE stream leaks cross-tenant events,
- protobuf/gRPC service allows method discovery or unauthenticated calls,
- message replay lacks nonce/session binding.

## False-Positive Reducers

- Seeing a method name does not prove it is callable.
- WebSocket connection success does not prove room authorization.
- GraphQL operation presence does not prove field access.
- Protobuf names in a bundle may be generated dead code.
