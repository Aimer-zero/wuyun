# Wuyun Tool Matrix

Use this reference when choosing tools, explaining missing capabilities, or downgrading validation.

## Decision Rule

Pick the tool that gives the strongest evidence with the least risk. If the right tool is unavailable, state the gap and use a bounded fallback only when it still preserves validation integrity.

## Capability Matrix

| Task | Preferred tools | Safe fallback | Evidence to collect |
|---|---|---|---|
| Local source search | `rg`, `git grep`, language server, `passive_repo_audit.py` | Python file walker | File path, line, source → boundary → sink trace |
| Route discovery | framework router inspection, OpenAPI/spec parsing, `passive_repo_audit.py` | manual manifest/source review | Route, method, auth middleware, handler |
| Dependency inventory | package manager lockfiles, SBOM tools, package manager audit | manifest parsing | Package name, version, source file, reachability |
| HTTP request replay | Burp MCP/repeater, captured HAR replay, `curl`, Python `requests`/`httpx` | user-provided request/response analysis | Request, response code, response field, timing |
| Cloudflare/WAF interference | captured HAR/headers, `cloudflare_triage.py`, browser/runtime tools, owner Security Events by Ray ID | source/OpenAPI review and owner-assisted replay | Ray ID, status, block/challenge marker, request shape, origin-validation gap |
| Browser/runtime JS | js-reverse MCP, jshook, browser/Chrome automation, runtime hooks | static JS review | Executed function, runtime value, network call |
| Directory/parameter discovery | `ffuf`, `gobuster`, `dirsearch` with rate limits | route/source extraction | Discovered path/parameter and status behavior |
| SQL injection | SQLMap MCP/`sqlmap` plus manual proof | code-level query review | Bound parameter evidence or controlled error/timing |
| Network enumeration | `nmap` with scoped targets | service config/source review | Host, port, service, version, scope proof |
| Binary analysis | IDA/Ghidra MCP, `checksec`, debugger, `pwntools` | `file`, `strings`, static triage | Protections, symbol/path, offset, crash proof |
| Mobile runtime | Frida MCP/Frida CLI, `adb`, objection | APK static analysis | Hook target, method trace, controlled value |
| PCAP/DFIR | `tshark`, Zeek, Volatility | metadata extraction scripts | Timeline, artifact path, hash, minimal decoded content |

## MCP / Plugin Expectations

Host-level MCP tools are not visible to `check_tools.py`; discover them through the agent's tool-discovery mechanism when available.

| Need | First-choice MCP/plugin | If unavailable |
|---|---|---|
| Browser interaction, runtime JavaScript, WebSocket/API tracing | js-reverse MCP or jshook | browser/Chrome automation, static JS review, HAR/manual hooks |
| HTTP proxy, interception, replay, active scanning | Burp MCP | captured requests + `curl`/Python replay; avoid claiming scanner-equivalent coverage |
| SQLi enumeration and tamper chains | SQLMap MCP | manual sink tracing and small controlled tests |
| Binary reversing | IDA MCP or Ghidra MCP | `file`, `strings`, `objdump`, debugger if available |
| Metasploit module workflows | Metasploit MCP | manual CVE validation only within scope |
| Android/iOS dynamic hooks | Frida MCP | Frida CLI if installed, otherwise static APK/IPA review |

## Missing Tool Language

Use precise wording:

```text
Validation gap: `sqlmap` is unavailable, so I could not automate SQLi enumeration. I reviewed the query construction path instead. Confidence remains medium until parameter binding behavior is tested in a scoped environment.
```

Do not say:

```text
No SQL injection exists because sqlmap is unavailable.
```

## Safe Defaults

- Use passive local analysis before active target interaction.
- Rate-limit active tests and change one variable at a time.
- Prefer synthetic markers over data extraction.
- Stop if tests produce instability, errors at scale, or unexpected sensitive data.
- Record which tool proved which fact; do not let scanner output replace root-cause validation.

## Cloudflare/WAF Validation Gap Language

```text
Cloudflare WAF blocks validation for this request shape. WAF behavior is confirmed by status/header/body indicators, but origin behavior remains unproven. Use Ray ID lookup or a scoped owner-approved WAF skip/staging replay to validate the application layer.
```
