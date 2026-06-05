# Wuyun Safe Validation Guide

Use this reference for production-safe reviews and any situation where business impact matters.

## Validation Ladder

Start at the lowest level that can answer the question.

1. **Code/config proof**: show flawed branch, missing check, unsafe sink, or insecure default.
2. **Synthetic local proof**: reproduce in local tests, fixtures, containers, or mocks.
3. **Metadata-only runtime proof**: confirm status code, timing, error class, role boundary, or non-sensitive marker.
4. **Controlled state proof**: create or modify only records explicitly provided for testing.
5. **Exploit proof**: use only when necessary for a lab/CTF task or clearly defined validation need.

## Evidence That Is Usually Enough

- A route handler accepts an object ID and updates it before checking owner/tenant.
- A query concatenates request input without parameter binding.
- A file extraction path joins user-controlled names without canonicalization.
- A response differs across roles in a way that proves authorization boundary failure without exposing data.
- A timing delta confirms a blind injection condition using a harmless sleep in a lab or controlled validation.

## Evidence to Avoid in Production-Like Contexts

- Dumping database tables or user records.
- Reading secrets, tokens, private files, or cloud credentials.
- Uploading webshells or persistent payloads.
- Brute forcing credentials or tokens.
- High-volume crawling, fuzzing, scanning, or denial-of-service style tests.
- Privilege escalation on production systems.

## Redaction Rules

- Replace secret values with `<redacted>`.
- Truncate tokens to at most a short prefix/suffix only when needed for correlation.
- Replace user/customer identifiers with stable pseudonyms.
- Store only non-sensitive evidence pointers in memory.

## Confidence Impact

- **High**: code path plus safe runtime proof or deterministic local reproduction.
- **Medium**: decisive code path but no runtime validation, or runtime signal without root-cause trace.
- **Low**: pattern match only, scanner alert only, or incomplete reachability.
