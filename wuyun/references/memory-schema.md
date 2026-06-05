# Wuyun Long-Term Knowledge Base Format

Use this reference to create or update a model-agnostic vulnerability research memory. The memory may live wherever the host agent framework stores persistent knowledge; if no location is provided, propose a project-local `.wuyun/memory.md` file or an agent-managed private memory store.

## Memory Principles

- Keep memory evidence-driven, scoped, and reusable.
- Do not store secrets, tokens, private personal data, or unrelated third-party information.
- Mark confidence and freshness explicitly.
- Separate general vulnerability knowledge from target-specific notes.
- Preserve false positives; they are valuable for reducing future noise.

## Recommended File Structure

```text
.wuyun/
  memory.md          # curated long-term knowledge using this schema
  findings/          # optional per-investigation summaries
  evidence-index.md  # optional pointers to non-sensitive evidence
```

If the agent platform already provides memory, store entries using the schema below rather than requiring these files.

## Entry Schema

```markdown
### <entry-id>: <short title>

- Type: pattern | technique | false-positive | framework-behavior | workflow | remediation
- Status: established | observed | hypothesis | deprecated
- Confidence: high | medium | low
- Scope: general | framework:<name>@<version> | language:<name> | target:<project/challenge>
- First observed: YYYY-MM-DD
- Last updated: YYYY-MM-DD
- Tags: [<tag>, <tag>]

#### Summary
<One or two sentences describing the reusable knowledge.>

#### Context
<Where this applies: architecture, framework, data flow, trust boundary, privilege model.>

#### Signals
- Positive indicators:
  - <signal>
- Contradictory indicators:
  - <signal>
- Fast validation:
  - <minimal check or experiment>

#### Root Cause or Mechanism
<The failed assumption, framework behavior, parser differential, or control weakness.>

#### Reuse Guidance
<When to look for this again and how to validate quickly.>

#### Remediation or Prevention
<Design rule, code fix, test, configuration, or monitoring pattern.>

#### Evidence Pointers
- <non-sensitive path, commit, report section, request ID, or reproduction note>

#### Revision Notes
- YYYY-MM-DD: <what changed and why>
```

## ID Convention

Use stable IDs:

```text
PAT-<area>-<slug>       # vulnerability pattern
TEC-<area>-<slug>       # validation/exploitation technique
FP-<area>-<slug>        # false-positive reducer
FW-<framework>-<slug>   # framework behavior
WF-<workflow>-<slug>    # workflow improvement
REM-<area>-<slug>       # remediation pattern
```

Examples:

- `PAT-authz-idor-tenant-field`
- `FP-xss-react-escaped-interpolation`
- `FW-express-bodyparser-duplicate-keys`
- `TEC-race-concurrent-idempotency-check`

## Search and Reuse Protocol

At the start of an investigation:

1. Search memory by framework, language, route type, trust boundary, and vulnerability class.
2. Import only relevant entries into working context.
3. Treat memory as a guide, not proof.
4. Validate against current runtime or source before reporting.

At the end of an investigation:

1. Add new entries only when they are reusable.
2. Update existing entries instead of duplicating.
3. Add false-positive reducers for misleading signals.
4. Mark stale entries as `deprecated` rather than silently deleting when historical context is useful.

## Minimal Memory Update Template

```markdown
### <ID>: <Title>
- Type: <type>
- Status: observed
- Confidence: medium
- Scope: <scope>
- First observed: <date>
- Last updated: <date>
- Tags: []

#### Summary

#### Signals
- Positive indicators:
- Contradictory indicators:
- Fast validation:

#### Reuse Guidance

#### Evidence Pointers
```
