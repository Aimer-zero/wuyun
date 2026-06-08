# Tool Integrations

## Burp / Caido

Generate reviewed request collections from known endpoints. Do not include unrelated cookies or bearer tokens in shared artifacts.

## ffuf

Build wordlists from local routes and JS endpoints. Keep rate low and host scope explicit.

## nuclei

Prefer custom low-impact templates for known owned fingerprints. Avoid broad public template packs as proof.

## sqlmap

Use only for confirmed injection candidates. Set low risk/level/thread count, avoid dumping data, and manually verify parser influence.

## jwt_tool

Use for offline JWT structure checks and lab-only authorized tests. Do not brute force production tokens.
