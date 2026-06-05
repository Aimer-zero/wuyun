# Wuyun Learning Mechanism

Use this reference when an investigation produces new knowledge, a false positive, a failed path, or a confirmed vulnerability pattern. The goal is cumulative improvement without confusing speculation with reusable fact.

## Learning Loop

1. **Observe**: capture decisive evidence, not just conclusions.
2. **Normalize**: convert the event into a reusable pattern, anti-pattern, validation method, or false-positive indicator.
3. **Classify**: label the knowledge type and confidence.
4. **Store**: write it using the long-term memory schema in `memory-schema.md`.
5. **Reuse**: during future investigations, search for matching context, framework, sink, source, or trust boundary.
6. **Revise**: update or downgrade knowledge when later evidence contradicts it.

## What to Learn From

- **Confirmed findings**: root cause, exploit path, impacted invariant, validation method, remediation.
- **Likely findings**: promising signals and missing validation requirements.
- **False positives**: which control, configuration, or runtime behavior invalidated the hypothesis.
- **Failed attempts**: why a path was architecturally implausible or blocked by evidence.
- **Tool outcomes**: commands, queries, hooks, payloads, or traces that reduced uncertainty.
- **Framework behaviors**: sanitizer semantics, auth middleware order, parser quirks, ORM defaults, cache rules.

## Learning Entry Types

Use one of these labels:

- `pattern`: recurring vulnerability pattern.
- `technique`: reusable validation or exploitation technique for scoped tasks.
- `false-positive`: signal that looked risky but was neutralized.
- `framework-behavior`: language, library, framework, or platform behavior that affected security.
- `workflow`: investigation sequence that improved coverage or speed.
- `remediation`: durable fix pattern or test strategy.

## Confidence Levels for Knowledge

- **Established**: confirmed across multiple investigations or backed by documentation/runtime evidence.
- **Observed**: confirmed once with clear evidence.
- **Hypothesis**: plausible but not fully validated; use as a lead only.
- **Deprecated**: contradicted or no longer reliable; keep reason and replacement if known.

## Extraction Checklist

After each investigation, ask:

- What assumption failed?
- What trust boundary mattered?
- What input source and sink formed the decisive path?
- What evidence increased confidence?
- What evidence reduced confidence?
- What should be tried earlier next time?
- What should be avoided next time?
- Which test would have caught this bug?
- Which remediation would prevent the class, not just this instance?

## Update Discipline

- Store minimal, reusable knowledge; avoid copying full reports into memory.
- Separate project-specific facts from general patterns.
- Never store secrets, private customer data, or unrelated personal data in long-term memory.
- Prefer exact framework/version context when behavior is version-dependent.
- Link to evidence by path, commit, request ID, or report section when available.
- Downgrade or delete stale entries when contradicted by runtime behavior.

## Learning Output Block

Use this compact block at the end of substantial investigations:

```markdown
## Lessons Learned
- Pattern: <reusable pattern or root cause>
- Useful signal: <evidence that raised confidence>
- False-positive reducer: <evidence/control that should be checked next time>
- Reusable validation: <smallest proof method>
- Memory update: <entry type and title to add/update, or "none">
```
