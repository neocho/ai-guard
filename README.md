# ai-guard

A local guardrail proxy for AI coding agents. `aig` sits between your agent
(Claude Code, Cursor, etc.) and the model API, terminating TLS via a
per-process local CA so it can see, parse, and gate every outbound request —
flagging secrets and PII before they leave your machine. Early stage, work
in progress.

## License

MIT — see [LICENSE](LICENSE).
