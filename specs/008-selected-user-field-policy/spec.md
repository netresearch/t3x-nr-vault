# Evaluate field TSconfig for the selected backend user

Status: proposed repair of an existing argument. Architecture: ADR-049.
The decision depends on the exact published FieldPermission oracle PR #441
head `57a83d637a4a6aa323cf354811466bb3dd9ebe07`; publish the implementation as
a real child of this decision. No public signature change.

## Existing defect and supported-major evidence

All three public wrappers accept an optional `BackendUserAuthentication`.
The supplied object already selects administrator bypass and permission-cache
identity, but its TSconfig read uses the ambient global backend account.
Two real authenticated SQL-user controls fail by assertions. No production
caller in this repository currently passes the optional argument, so this is
not evidence of a currently exercised caller exploit.

Passing only the selected user's materialized `UserTsConfig` to Core's
`PageTsConfigFactory` is insufficient. Its managed condition visitor uses the
ambient singleton Context. Real extension `page.tsconfig` UID, group and
administrator conditions add three genuine failures. The same original
20-test/117-assertion probe has five assertion failures and no errors under
native TYPO3 13.4.36/PHP 8.4 and TYPO3 14.3.8/PHP 8.5.

An identical isolated Core-coordination prototype passes four tests/112
assertions on both majors. It checks actual conditions, independent IncludeTree
nodes, fresh matcher/AST visitor/AST/context objects, immutable earlier
verdicts/output, real runtime-cache hash and cached-object identities, native
extension defaults and an explicit user without global `BE_USER`. Native13's
legacy global Page TSconfig remains; native14's own removal is preserved.
The final AST-visitor version uses Core's configured `shared:false` service.
Production remains unchanged for these architecture probes.

The physical13 dependencies came from an existing13 test tree into a private
copy, without a Composer update, advisory exception or platform override.
Only the duplicate installed Vault self-package metadata was removed from that
copy before regenerating its root autoload; other installed versions stayed
identical. Failed initial Composer/path probes are not native test evidence.

## Decision

1. Thread the selected object through the existing private field-policy path.
   `isAllowed()`, `getPermissions()` and `isReadOnly()` must consistently use
   that account's policy. Omitted user arguments keep current behavior.
2. If the selected object is the actual global `BE_USER` object, retain
   `BackendUtility::getPagesTSconfig(0)` exactly, including Core's existing
   page-zero runtime cache. Do not overlay ambient policy into another user's
   result.
3. For a distinct selected object, coordinate Core's page-zero include tree,
   tokenizer, condition-aware traverser and configured fresh AST visitor in a
   narrow private helper. Reuse Core's parser and include/cache/event handling;
   do not introduce a second TypoScript parser or new dependency.
4. Clone the current `Context`, replacing only its `backend.user` aspect with a
   `UserAspect` of the selected account. Construct a new condition visitor
   against that clone and the real `PageLayoutResolver`. Keep the other request
   aspects and native page-zero `NullSite`/rootline variables.
5. Respect the actual supported-major constructor difference: Core13's visitor
   implements `LoggerAwareInterface`, takes Context and PageLayoutResolver,
   then receives its logger with `setLogger()`; Core14 takes the logger as a
   third constructor argument. Both paths use a fresh visitor. Obtain neither
   an ambient/global managed condition visitor nor a reused stateful one.
6. Append the selected account's already materialized `page.*` User TSconfig
   overrides using Core's flatten/strip-prefix procedure. That object comes
   from the existing Core account setup; this repair does not rematerialize an
   entire alternate login session or change the execution identity.
7. Every resolution gets a fresh IncludeTree and AST visitor. Core mutates
   condition verdicts and the visitor's AST; previous resolutions must remain
   unchanged. Preserve configured Core AST-builder services instead of
   replacing them with an independent parser implementation.
8. Never replace global `BE_USER`, alter the singleton Context/aspects, or write
   selected policy into Core's ambient page-UID runtime cache. A selected user
   remains usable when global `BE_USER` is absent.

## Existing boundaries

Keep administrator bypass and the administrator's `readOnly=false` behavior,
no-user refusal, field→table-default→global-default→built-in precedence,
boolean conversion and action separation. Keep the existing service cache per
table/field/action/user UID until `clearCache()`, including independent selected
user entries and invalidation controls. Do not convert the read-only flag into
an authorization grant. Underlying Vault operation and secret ACL gates still
apply and are outside this TSconfig selector repair.

Native13 supports deprecated global `defaultPageTSconfig`; native14 removed it.
Use each Core's native include-tree behavior, retaining extension/event
defaults in both. This repair does not restore the removed14 global input.
Page-zero resolution adds no site lookup, schema, public method, required
constructor argument or request impersonation API.

## Acceptance and falsification

- Exercise all public wrappers using actual opposing selected/ambient SQL
  backend accounts and materialized Core user/group TSconfig; assert allowed,
  full permission map and read-only result outside callbacks/catches.
- Exercise UID, administrator and group Page TSconfig conditions with opposing
  accounts on both supported majors, plus ordinary ambient controls.
- Preserve extension/default inheritance, selected overrides, omitted user
  behavior, explicit-without-global behavior and no ambient-policy overlay.
- Assert actual selected→ambient→selected output and condition verdicts,
  disjoint IncludeTree node identities, fresh configured AST visitor/AST,
  unchanged earlier trees and output, and the real Core page-zero cache hash
  and cached `PageTsConfig` object identities. Global object assertions alone
  are insufficient.
- Keep existing cache/invalidation, precedence, action and admin tests green;
  execute affected real SQLite and MariaDB cases.
- Challenge selected-user propagation, local-context replacement, ambient
  overlay, visitor-state reuse and Core runtime-cache contamination on the
  final production snapshot. Require genuine assertion failures and exact
  restoration, with no parser/framework failures counted as useful kills.
- Complete canonical CI/Rector, native13/14 checks, documentation baseline
  comparison and a complete independent source/test/spec review.

The successful coordination prototype does not establish that the production
repair exists. The whole ACL, TSconfig, Hook and mutation adequacy audit remains
open until its separate feature-family work is complete.
