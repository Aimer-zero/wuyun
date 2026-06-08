# Canonicalization And Parser Mismatch

Use benign markers to understand how each layer transforms input:

- browser URL construction
- proxy and CDN normalization
- WAF decoding
- framework routing
- application parsing
- logging and alerting

Safe review questions:

- Which layer decodes URL encoding, Unicode escapes, path separators, and duplicate parameters?
- Does the application authorize before or after canonicalization?
- Are logs and alerts recording the same value that the application uses?
- Can validation be performed with a harmless marker and synthetic object?

Do not combine canonicalization variants with exploit payloads unless an explicitly authorized lab scope requires it.
