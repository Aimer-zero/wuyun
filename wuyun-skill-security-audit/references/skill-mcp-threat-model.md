# Skill and MCP Threat Model

## Assets

- Agent system/developer/user context
- Local files, shell, browser state, tokens, SSH keys, cloud credentials, package manager auth
- MCP server transport and tool schemas
- Evidence, reports, memory, screenshots, HAR files, and audit outputs

## High-Risk Behaviors

- Reading sensitive files outside the target workspace without explicit user scope
- Remote script execution during install or first use
- Hidden instructions to ignore safety, approvals, scope, or user intent
- Network exfiltration of findings, prompts, credentials, or local paths
- Persistence through cron, launch agents, login items, shell profile mutation, or global hooks
- MCP servers exposing shell, filesystem, browser, or network tools without allowlists
- Package lifecycle scripts that download or execute opaque payloads

## Review Pattern

1. Identify all instruction files that can steer the agent.
2. Identify all executable files and package lifecycle hooks.
3. Identify all outbound network paths.
4. Identify all filesystem paths referenced by instructions or scripts.
5. Decide whether each capability is necessary, bounded, documented, and reversible.
