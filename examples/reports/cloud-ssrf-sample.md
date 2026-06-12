# Sample Report: Cloud SSRF Lead

## Summary
- Status: likely
- Affected component: server-side URL previewer
- Vulnerability class: SSRF to cloud metadata exposure lead

## Technical Analysis
- Source/input: user-provided preview URL.
- Boundary/control: URL validation checks scheme but not resolved address ranges.
- Sink/decision/state change: backend HTTP client performs outbound fetch.

## Supporting Evidence
- Controlled callback received one request from the application egress IP.
- Code/config indicates redirects are followed.
- No metadata credential request was performed in this sample.

## Root Cause
The URL fetcher validates string shape but does not enforce destination allowlists, private-range deny rules, redirect controls, or cloud metadata protections.

## Confidence Level
- Level: medium.
- Rationale: outbound fetch is demonstrated with a harmless callback, but metadata reachability and credential exposure were not tested.

## Validation Suggestions
- In owner-approved staging, verify private-range and metadata egress blocking with harmless metadata path checks.
- Prefer cloud logs, egress firewall logs, or local reproduction before production validation.

## Remediation Guidance
- Use strict allowlists for preview destinations.
- Resolve and pin DNS before connect.
- Block private, loopback, link-local, and metadata ranges after every redirect.
- Enforce IMDSv2 or provider-equivalent metadata hardening and least-privileged instance roles.

## Lessons Learned
- Callback proof confirms server-side fetch; it does not by itself prove metadata compromise.
