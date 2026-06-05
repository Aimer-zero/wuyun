# File Upload, Path, and Parser Review

## Surfaces

- Multipart uploads, import-by-URL, archive extraction, image transformations, document parsing.
- Download endpoints that accept `path`, `file`, `key`, `name`, or `template` parameters.
- User-controlled filenames stored in object storage or local paths.

## Bug Classes

- Path traversal and unsafe path join.
- Zip Slip / archive entry traversal.
- Content-type confusion and extension-only validation.
- Parser exploits through image/PDF/XML libraries.
- Public object overwrite or predictable storage keys.

## Safe Validation

- Use benign text/image fixtures.
- Do not upload executable payloads or webshells.
- Prove canonicalization with local tests or synthetic filenames.
