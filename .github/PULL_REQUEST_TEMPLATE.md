## Summary

<!-- Brief description of changes -->

## Related Issues

<!-- Link to related issues: Fixes #123, Relates to #456 -->

## Changes

<!-- List the main changes -->

-

## Checklist

- [ ] Tests pass locally (`composer test`)
- [ ] PHPStan passes (`composer ci:test:php:phpstan`)
- [ ] Code style is correct (`composer ci:test:php:cgl`)
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated

## Threat-Model Delta

<!--
REQUIRED when this PR touches Classes/Crypto, Classes/Security, Classes/Audit,
Classes/Http, the security gates, the release-evidence pipeline, or SECURITY.md
— and whenever it changes how a secret, key, or audit record is produced,
stored, transported or compared. Otherwise delete this section.

"No change" is a valid answer; leaving it blank is not — see CONTRIBUTING.md.
Security-critical PRs also need TWO approvals, one from a code owner.
-->

- **Trust boundaries**: <!-- new boundary crossed (process, host, network, DB, log sink, external provider), or "none" -->
- **Attacker capability**: <!-- what an attacker would now need, and whether that got cheaper -->
- **Invariants**: <!-- invariant added/changed/removed, and the test that pins it -->

<details>
<summary>How to answer these three (click to expand)</summary>

**Trust boundaries.** Does data cross a boundary it did not cross before — a
process, host, network hop, database, log sink, cache, or external provider? A
new `error_log()` call on a code path that handles plaintext is a new boundary.
Answer "none" when nothing moved.

**Attacker capability.** What would an attacker need in order to exploit this,
and did that get cheaper? Call out explicitly anything that:

- replaces a `hash_equals()` comparison with `===` or `==`,
- widens a permission grant or adds an admin override,
- lengthens how long a plaintext secret, DEK, or master key stays in memory,
- removes or defers a `sodium_memzero()`,
- adds a code path that can reach a secret without writing an audit entry.

**Invariants.** Name the security invariant this adds, changes, or removes, and
the test that pins it. Removing an invariant needs its own justification — say
why it was not load-bearing, or what replaced it.

Worked example of a "nothing new" answer:

```markdown
- **Trust boundaries**: none — the DEK never leaves EncryptionService.
- **Attacker capability**: none; no comparison, grant, or zeroisation changed.
- **Invariants**: adds "a wrapped DEK is rejected when its identifier does not
  match" (pinned by MasterKeyRotationAbortTest).
```

</details>

## Test Plan

<!-- How can reviewers test this? -->
