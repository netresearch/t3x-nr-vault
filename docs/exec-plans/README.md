# Execution Plans

Working directory for multi-step agent execution plans (design docs, task breakdowns, migration plans) that are too large for a PR description but not durable enough for `Documentation/`.

- `active/` — plans currently being executed. One Markdown file per plan, named `YYYY-MM-DD-<slug>.md`.
- `completed/` — plans whose work has merged; keep for archaeology, prune freely.

Rules:

- A plan is a scratchpad, not documentation — the merged PR and `Documentation/` (ADRs included) are the durable record. Never cite an exec plan from code or docs.
- Directories are created on first use; do not commit empty placeholder files.
