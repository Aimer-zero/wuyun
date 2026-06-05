# XSS and SSTI Review

## XSS Contexts

- HTML body, attribute, JavaScript string, URL, CSS, Markdown/rich-text, DOM sinks.
- React/Vue escape by default, but check `dangerouslySetInnerHTML`, `v-html`, custom renderers, and post-sanitization transforms.

## SSTI Contexts

- User-provided templates, themes, email bodies, document generators, notification formats.
- Jinja, Twig, Freemarker, Velocity, Handlebars, EJS, and custom expression engines.

## Safe Validation

- Start with inert markers and context reflection.
- Use non-exfiltrating payloads only when necessary for a lab or scoped validation.
- Do not steal cookies or access user data.
