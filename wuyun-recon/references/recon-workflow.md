# Scoped Recon Workflow

## Passive / Local First

- local repository route extraction,
- JS bundle endpoint extraction,
- OpenAPI/Swagger parsing,
- known owned domains and org names,
- certificate transparency query URLs,
- GitHub/GitLab search query generation.

## Active Recon Guardrails

- written domain/org scope,
- rate limits,
- one tool at a time,
- no credential or secret collection,
- no third-party tenant enumeration,
- stop on instability or owner concern.

## Asset State

- candidate,
- in-scope confirmed,
- out-of-scope,
- duplicate,
- parked/dead,
- needs owner confirmation.
