# Injection Review

Focus on reachability from user input to interpreter/query/template/command sinks.

## Patterns

| Class | Sources | Sinks | Reducers |
|---|---|---|---|
| SQL | search/filter/sort/id | raw query, string concat | parameter binding, allowlisted columns |
| NoSQL | JSON filters/operators | `$where`, unfiltered Mongo query | operator allowlist, schema validation |
| LDAP/XPath | login/search filters | string-built filters | escaping, prepared APIs |
| Command | filenames, URLs, flags | shell exec/spawn | argv array, no shell, allowlist |
| SSTI | template/theme/content | dynamic template compile | sandbox, context escaping |

## Safe Validation

- Prefer code-level trace and local unit tests.
- Use harmless syntax errors, boolean differences, or timing in labs or scoped validation contexts.
- Never dump tables or secrets as proof.
