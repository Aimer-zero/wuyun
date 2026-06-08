# GraphQL And WebSocket Review

## GraphQL

Check:

- query/mutation/subscription inventory,
- variables containing IDs, tenant IDs, role IDs, pricing, or workflow state,
- field-level authorization,
- mutation-side ownership checks,
- introspection exposure in production,
- batching and aliasing behavior,
- error messages that expose schema or authorization details.

## WebSocket / Socket.IO

Check:

- auth token source during connect,
- namespace/path,
- join/subscribe message,
- room/channel/user ID fields,
- server-side authorization on join and send,
- reconnect behavior,
- message replay,
- cross-account delivery.

## Safe Validation

- Use two owned accounts with clearly synthetic rooms/objects.
- Confirm deny behavior and log request IDs.
- Do not subscribe to unrelated user channels or dump event history.
