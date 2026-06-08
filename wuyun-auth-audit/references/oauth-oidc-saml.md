# OAuth / OIDC / SAML Review

## OAuth / OIDC Checks

- redirect URI exact matching and scheme/host/path controls.
- state presence, unpredictability, and binding to the browser session.
- nonce usage for OIDC ID token replay protection.
- PKCE use for public clients.
- token audience, issuer, expiration, and key selection.
- open redirect chains that can receive codes or tokens.
- jku/jwks_uri/x5u/kid trust boundaries.

## SAML Checks

- signed assertion vs signed response.
- signature wrapping risk when XML parsing selects unsigned nodes.
- audience, recipient, destination, NotBefore, NotOnOrAfter.
- NameID and attribute mapping.
- replay and session binding.

## False-Positive Reducers

- Missing nonce is not always exploitable outside OIDC implicit/hybrid or replayable flows.
- Public JWKS URLs can be normal; risk depends on who controls the URL and key selection.
- SAML XSW requires parser/signature validation mismatch, not just SAML usage.
