# Prompt Injection Review

## Channels

- direct chat input,
- document/PDF/HTML/Markdown ingestion,
- URLs and web pages,
- code comments and repository files,
- images with visible text,
- audio transcripts,
- email/ticket/CRM content.

## Safe Test Pattern

Use a unique marker such as `WUYUN_CANARY_123` and ask the model to include or ignore it in a harmless way. Do not ask for secrets, system prompts, credentials, private data, or policy bypass.

## Leakage Triage

- transformation tasks that preserve hidden instructions,
- summarizers that follow embedded instructions,
- agents that treat retrieved text as developer instructions,
- tools that run based on model output without policy checks.

## False-Positive Reducers

- A model repeating a marker is not a vulnerability unless it crosses a trust boundary or triggers a sensitive action.
- Prompt injection impact depends on tool access, data access, memory, retrieval, or output sink.
