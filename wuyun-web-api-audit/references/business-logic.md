# Business Logic Review

Business logic bugs violate application invariants rather than parser rules.

## Common Invariants

- Price, discount, quantity, quota, balance, reward, ownership, role, workflow state.
- One-time actions: redemption, password reset, invitation, coupon, trial activation.
- State transitions: pending → approved → paid → shipped; draft → published.
- Idempotency, retries, race conditions, and duplicate webhook delivery.

## Hypotheses

- Client controls server-authoritative fields.
- Later workflow endpoints can be called directly.
- Concurrent requests double-spend or duplicate state transitions.
- Replay of signed callbacks succeeds after expiration or status changes.

## Safe Validation

- Use synthetic test records.
- Prefer local/unit tests for race and state-machine proof.
- Avoid financial, billing, or production data impact.
