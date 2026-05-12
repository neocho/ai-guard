# ai-guard

A local guardrail proxy for AI coding agents. `aig` sits between your agent
(Claude Code, Cursor, etc.) and the model API, terminating TLS via a
per-process local CA so it can see, parse, and gate every outbound request —
flagging secrets and PII before they leave your machine. Early stage, work
in progress.

## Supported agents

| Agent | Coverage |
|---|---|
| Claude Code CLI (`claude`) | ✅ Full |
| Codex CLI (`codex`) | ✅ Full |
| `aider`, `opencode`, other Node CLIs | ✅ Full |
| Cursor (Electron) | ✅ Full |
| Codex Desktop (Electron) | ✅ Full |
| Claude Desktop (Electron) | ❌ Not supported — application-level cert pinning. Use the Claude Code CLI for Anthropic traffic. |

## License

MIT — see [LICENSE](LICENSE).
