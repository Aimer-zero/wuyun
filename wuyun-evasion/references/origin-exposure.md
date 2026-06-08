# Origin Exposure Plan

Origin review should prefer owner-provided data and passive evidence:

- DNS records and historical DNS supplied by the owner
- certificate SANs and transparency records
- SPF/MX/DMARC includes
- CDN-specific response headers
- deployment inventory and load balancer records
- application allowlists and expected ingress paths

Validation must not brute force origin IPs. If a candidate origin is supplied by the owner, use a single low-impact metadata request and preserve request IDs rather than probing content broadly.
