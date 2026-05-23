# Review notes

Engineering artifacts from periodic multi-axis reviews of the extension. Each
file is a point-in-time analysis written by a single agent or reviewer — they
are *not* end-user documentation (that lives under `Documentation/`).

Notes here:

- Identify gaps, risks, or technical debt the codebase doesn't surface on its
  own (e.g. missing test coverage, accessibility findings, UX regressions).
- Reference specific files / line numbers as evidence — claims that no longer
  match the code should be treated as stale, not authoritative.
- Are committed so follow-up PRs can cite them and so the next review can
  start from "what changed since last time" instead of redoing the analysis.

Each note carries the date and the scope at the top. When the underlying
finding is addressed in a PR, link the PR from the note rather than deleting
the entry — the audit trail of "what was raised, what was done" stays useful.
