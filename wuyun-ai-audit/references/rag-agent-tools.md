# RAG And Agent Tool Review

## RAG Checks

- writable sources and ingestion approval.
- chunking/metadata trust.
- source ranking and stale content.
- tenant/source isolation.
- prompt construction and retrieved text delimiters.
- citation and provenance display.

## Agent Tool Checks

- file path allowlists and canonicalization.
- HTTP fetch allowlists and private-range blocking.
- shell command allowlists and argument escaping.
- database/query tools and row/tenant filters.
- browser automation scope.
- memory writes and long-term persistence.

## Safe Validation

- temporary synthetic document with a canary marker.
- dry-run tool policies when available.
- harmless local paths/URLs.
- owned account and isolated workspace.
