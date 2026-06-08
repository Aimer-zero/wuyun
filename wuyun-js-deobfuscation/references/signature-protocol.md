# Web Signature And Protocol Analysis

Use this reference when JS contains signing, nonce, timestamp, device token, or request canonicalization logic.

## Map Inputs

- method, path, query, body hash,
- timestamp and clock tolerance,
- nonce/random source,
- device/session/user identifiers,
- app key/client ID/public key,
- secret source,
- token refresh flow,
- canonical header list,
- encoding and sorting rules.

## Hypotheses

- Replay window is too long or nonce is not enforced server-side.
- Client-exposed secret is treated as server secret.
- Signature omits security-critical fields such as body, method, tenant, or path.
- Device/risk token is checked only client-side.
- Canonicalization differs between client and server.
- Token refresh endpoint trusts stale or low-privilege context.

## Safe Validation

- Prefer local reproduction with synthetic requests.
- Compare owned accounts and synthetic records.
- Do not brute force signatures or attack unrelated accounts.
- Do not dump secrets or production data.

## Reporting

State what is proven:

- signature construction recovered,
- replay accepted,
- field omission confirmed,
- server-side trust boundary violated,
- or validation blocked by missing owner support.
