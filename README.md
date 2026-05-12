# ai-guard

A local guardrail proxy for AI coding agents. `aig` sits between your agent
(Claude Code, Cursor, etc.) and the model API, terminating TLS via a
per-process local CA so it can see, parse, and gate every outbound request —
flagging secrets and PII before they leave your machine. Early stage, work
in progress.

## Install (macOS, Apple Silicon or Intel)

```sh
curl -fsSL https://raw.githubusercontent.com/neocho/ai-guard/main/install.sh | bash
```

Then install the local CA into your keychain (one Touch ID prompt, no admin
password):

```sh
aig install-cert
```

Wrap your AI agent:

```sh
aig run claude          # or codex, opencode, aider…
aig run /Applications/Cursor.app
```

Captures land in `~/.aig/captures.db`. Run `aig serve` to expose a local
JSON API, or install the [AIGuard Mac app](https://github.com/neocho/ai-guard-mac/releases)
for the UI.

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
