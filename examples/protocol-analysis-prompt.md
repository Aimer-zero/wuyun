# Wuyun Protocol Analysis Prompt

```text
Use $wuyun, $wuyun-protocol-analysis, and $wuyun-web-api-audit.
Mode: protocol-analysis.
Artifact: ./capture.har, proxy export, GraphQL schema, protobuf files, or frontend source tree.

Please passively inventory WebSocket, Socket.IO, GraphQL, SSE, JSON-RPC, gRPC/protobuf, multipart, and streaming surfaces.
Do not replay captured traffic by default.

Output:
- protocol inventory
- state-machine notes
- auth/session binding observations
- object/tenant/channel ID trust boundaries
- prioritized safe validation hypotheses
- evidence and confidence levels
```
