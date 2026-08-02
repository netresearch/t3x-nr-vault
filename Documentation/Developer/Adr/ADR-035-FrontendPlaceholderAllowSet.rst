.. include:: /Includes.rst.txt

.. _adr-035-frontend-placeholder-allow-set:

=================================================================
ADR-035: Per-request allow-set of frontend-resolvable identifiers
=================================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted (amended 2026-08-02 — the CLI is strict too)

Date
====

2026-07-30, amended 2026-08-02

Amendment 2026-08-02 — the CLI carve-out is gone
================================================

The original decision exempted the CLI unconditionally: ``Environment::isCli()``
put every command-line render into LEGACY, on the reasoning that the CLI is not
an unauthenticated surface. That reasoning does not survive contact with
``scheduler:run``.

A scheduled task authenticates the ``_cli_`` administrator, and an administrator
holds the admin bypass, so the read is granted whatever the per-secret tiers say.
The plain unauthenticated CLI is fail-closed for a different reason
(``allowCliAccess`` defaults to ``0``), so it was never the exposure — the
*authenticated* one is. A newsletter or export job that renders editor-authored
``tt_content`` through ``stdWrap`` is a resolution site with no gate left on it
at all, which is exactly the shape this ADR set out to close on the frontend.

The allow-set therefore applies on the CLI as it does in a frontend request. An
installation whose internal render jobs genuinely need the old behaviour opts
back into it with the extension-configuration key
``frontendPlaceholderLegacyCli`` (default ``0``), which restores the removed
branch byte for byte. The narrower remedy — publishing the identifiers through
A1/A3 or one ``allowIdentifier()`` call — stays the recommended one.

Two details of the original design carry over unchanged and are worth stating,
because both look like oversights otherwise:

*  **The question is asked of the SAPI, not of the request.** A CLI process
   usually carries a CLI-typed request, and ``ApplicationType::isFrontend()``
   reports ``false`` for it — so the "positively not a frontend request" rule
   alone would classify every scheduled render as LEGACY and close nothing.
   ``isCli()`` stays in the rule; only its answer changed from "legacy" to "the
   opt-in decides".
*  **The log latch still never engages on the CLI**, whatever the opt-in says.
   A long-running ``scheduler:run`` or Messenger consumer handles many renders
   under one request object, so a latch keyed on that object is effectively
   process-wide, and one planted placeholder would black out every later warning
   of the run — the attacker-triggered blackout this ADR rejects elsewhere.
   Unlatched CLI logging is the pre-ADR-035 volume, so making resolution strict
   there adds no capability on the logging side.

The rest of this document describes the decision as amended.

Context
=======

``TypoScriptVaultListener`` subscribes to
``AfterStdWrapFunctionsExecutedEvent``, which core dispatches at the end of
*every* ``stdWrap()`` call. Any string that passes through ``stdWrap`` is
therefore a resolution site for :typoscript:`%vault(identifier)%`, including
strings the integrator never authored:

-  an editor-written ``tt_content`` field rendered with
   :typoscript:`stdWrap.field = bodytext`,
-  a request parameter rendered with :typoscript:`data = GP:q`,
-  anything an extension puts through ``stdWrap`` on the way to the page.

An editor — or an anonymous visitor able to get a reflected parameter rendered —
could name any secret flagged ``frontend_accessible`` and have its plaintext
written into output that is shared through the page cache. ``frontend_accessible``
was the only gate, and it is a property of the secret, not a statement about
where in a page a secret is allowed to surface.

Authorising the *content* is not possible: by the time the listener runs, the
provenance of a byte is gone. What can be authorised is the *identifier*.

Decision
========

In a frontend request, on the command line, and in any web request whose type
cannot be established — resolve an identifier only if the integrator published
it through a source an editor cannot write. ``FrontendPlaceholderPolicy`` builds
that allow-set per request, lazily, in memory.

The gate
--------

.. code-block:: text

   resolve(id)  <=>  (everything that was already required)
                     AND ( mode === LEGACY  OR  id in AllowSet )

A pure conjunction, so ``resolves_after`` is a subset of ``resolves_before``: no
string becomes a resolution site that was not one, no secret becomes reachable
that was not, and no new call reaches the vault. The gate runs **before**
``VaultServiceInterface::retrieveForFrontend()``, so a rejected identifier
touches neither the vault nor the audit log. A rejected placeholder is left
byte-identical, which is the contract the class already documented.

Context rule — fail-closed
--------------------------

.. code-block:: text

   LEGACY (pre-ADR-035 behaviour, byte for byte) iff
           Environment::isCli() === true AND frontendPlaceholderLegacyCli === true
        or Environment::isCli() === false
           AND a request is obtainable
           AND ApplicationType::fromRequest($r)->isFrontend() === false

   STRICT (allow-set enforced) in every other case

Both questions the rule asks — "which mode" and "whose state" — are answered
from one and the same request: the one ``ContentObjectRenderer::getRequest()``
returns, with :php:`$GLOBALS['TYPO3_REQUEST']` removed for the duration of that
call (see :ref:`adr-035-request-scoping`). A renderer that carries no request of
its own answers neither question, and is strict.

An earlier revision split the two, letting the **mode** fall back to
:php:`$GLOBALS['TYPO3_REQUEST']` on the argument that a stale read there "can
only move a render between legacy and strict, never make one request's state
addressable from another". Moving a render into legacy *is* the vulnerability.
``cms-backend``'s ``RequestHandler`` assigns that same global, and core unsets it
nowhere, so in a worker SAPI a finished backend request leaves a backend-typed
object behind; the next anonymous frontend render through a requestless renderer
read it, concluded "not a frontend request", and resolved every
frontend-accessible identifier an editor could name. The mode is therefore read
from the scope request or from nothing at all.

Detecting context through :php:`$GLOBALS['TYPO3_REQUEST']` **alone would leave
the headline unauthenticated path ungated**. That global is assigned in exactly
one place in the frontend stack — ``cms-frontend``'s ``RequestHandler``, the
innermost handler — and ``EidHandler::process()`` dispatches directly without
ever calling ``$handler->handle()``. In an eID request the global does not
exist, so a "no request means legacy" rule would resolve *everything* there.
Core states the constraint itself in ``ApplicationType``'s class docblock.

``Environment::isCli()`` is therefore asked separately from the request, but it
is no longer a carve-out: at the shipped default the CLI — the scheduler,
Symfony Messenger, console commands, PHPUnit — enforces the allow-set exactly as
a frontend request does, and everything else that is not positively non-frontend
fails closed. The SAPI has to be asked separately precisely *because* a CLI
process usually carries a CLI-typed request that ``isFrontend()`` reports as
``false``: routing that answer through the request rule would put every
scheduled render back into LEGACY.

Only the extension-configuration key ``frontendPlaceholderLegacyCli`` (default
``0``) restores the removed branch, and it restores it byte for byte. It is
CLI-scoped: setting it changes nothing about a web request.

Allow-set sources (union)
-------------------------

A1
   The ``frontend.typoscript`` setup array, walked recursively; every string
   leaf is matched against the shared ``VAULT_PATTERN``. ``sys_template`` is
   ``ctrl.adminOnly`` on both supported majors, and site TypoScript lives on
   disk. Page and ``tt_content`` data reach TypoScript only as
   condition-matcher variables that *select* authored blocks; they never become
   setup leaves.

A2
   The ``site`` request attribute: ``getConfiguration()`` (which already merges
   ``settings``) and ``getSettings()->getAllFlat()``. Both are on-disk YAML
   edited through an admin-only backend module.

A3
   The setup-array path ``plugin.tx_nrvault.frontendResolvableIdentifiers``, a
   comma-separated identifier list. Same source and same trust domain as A1,
   for identifiers that appear nowhere else in TypoScript.

A4
   ``FrontendPlaceholderPolicyInterface::allowIdentifier($identifier, $request)``,
   callable from integrator PHP — a ``userFunc``, a DataProcessor, or an eID
   handler. The grant is bound to the request passed in; see
   :ref:`adr-035-request-scoping`.

In eID neither A1 nor A2 exists (the eID middleware runs before the site and
TypoScript middlewares), so the allow-set there is A4 only. That is the intended
shape: eID is the unauthenticated surface, and the remedy is one
``allowIdentifier()`` call in the integrator's own handler.

On a **fully cached page hit that contains no** ``USER_INT`` **or** ``COA_INT``
**object**, core's frontend TypoScript factory returns before it populates the
setup array, so A1 and A3 are empty for that request too and only A2 and A4
apply. No documented example depends on A1 in that state, and the direction is
fail-closed, but it is third-party reachable and is recorded as a residual.

.. _adr-035-request-scoping:

Request scoping — why every mutable field is a WeakMap
-------------------------------------------------------

``FrontendPlaceholderPolicy`` is registered without ``shared: false`` and is
consumed by an event listener that is itself a singleton, so **one instance
serves the whole PHP process**. "Per-request state" on such an object is not a
property that documentation can assert; it has to be built.

Two fields would otherwise leak across a request boundary:

*  the **A4 grant**. In a worker SAPI (FrankenPHP, RoadRunner) an eID handler
   that publishes ``stripe_secret`` for request 1 would still be authorising
   request 2 — an anonymous frontend render, possibly on a different site in the
   same worker — whose output goes into the shared page cache. That is the very
   hole this ADR closes, re-opened through the remedy for it.
*  the **log latch**. A single boolean would make the pre-existing "Failed to
   resolve vault reference" warning a one-shot for the *process*. In any
   long-lived process — ``scheduler:run``, a Messenger consumer, a CLI crawler —
   one placeholder planted in an early-rendered ``tt_content`` field would
   silence every later warning, the attacker's own and any genuine
   misconfiguration. That is an attacker-triggered log blackout, and a new
   capability rather than a reduction.

Both fields are therefore ``\WeakMap``\ s, and both request-scoped methods take
their scope with them:
``allowIdentifier(string $identifier, ServerRequestInterface $request)`` and
``claimLogSlot(ContentObjectRenderer $contentObjectRenderer)``.

**A** ``\WeakMap`` **is not by itself the property.** A first revision made both
fields weak maps and still leaked, because the *key* was
:php:`$GLOBALS['TYPO3_REQUEST']` whenever that global was set. Core assigns it in
``cms-frontend``'s ``RequestHandler`` and **never unsets it** — a whole-tree grep
of the core tree finds four assignments and no unset — so in a worker SAPI
(FrankenPHP, RoadRunner) it survives the end of the request that set it. Every
subsequent request in that worker then keyed on the same stale object: a grant
published by request N was readable by request N+1, and a log slot claimed by N
silenced N+1. That is an identity bug, not a freshness bug, and no obligation on
a caller can close it.

The key is therefore the request the **caller** carries, and only that:

*  ``allowIdentifier()`` keys on the request it is handed, unchanged.
*  ``isResolvable()`` and ``claimLogSlot()`` key on
   ``ContentObjectRenderer::getRequest()``.

``getRequest()`` has its own deprecated fallback to the same global, which would
smuggle the stale object back in whenever a renderer carries no request. The
global is therefore removed for the duration of that call: the renderer either
answers with the request it was given, or ``getRequest()`` throws
``ContentRenderingException`` 1607172972 and the policy fails closed. Removing it
also means the v14 deprecation branch is never entered, so no
``E_USER_DEPRECATED`` escapes into ``stdWrap()``.

A later request holds a different request object, so it cannot address the
earlier entry, and the entry is collected with its request. Nothing has to be
reset, because there is no key a later request can reach.

The matching obligation on an A4 caller is an *identity* one, not a lifetime
one: pass the request you are handling **and** ``setRequest()`` the same object
on the renderer you render with. A renderer carrying a different request sees no
grant — fail-closed, and pinned by a test that runs the eID sequence with the
stale global deliberately left in place.

Two consequences follow from the choice:

*  **A4 now requires a request.** In strict context with no request obtainable
   anywhere, nothing is resolvable at all — previously A4 answered there. This
   is the fail-closed direction, and it is what makes the grant un-shareable.
*  **The latch never engages on the CLI, or in legacy context.**
   ``claimLogSlot()`` always returns ``true`` on the command line — whatever
   ``frontendPlaceholderLegacyCli`` says — and in a positively backend-typed
   request, so logging in both is byte-for-byte what it was before this ADR. On
   the CLI that is a security property, not a compatibility one: a long-running
   ``scheduler:run`` handles many renders under one request object, so a latch
   keyed on that object would be a process-wide log blackout an attacker
   triggers with a single planted placeholder.

Regex parity and hardening
--------------------------

``VAULT_PATTERN`` is one constant consumed by both the listener and the
harvester, and both apply the same ``trim()``. A harvester laxer than the
listener would be bypassable; a stricter one would over-block. Membership is
exact byte equality — no case folding, no normalisation.

The walk is depth-capped at 32, caps harvested identifiers at 1000, and wraps
each source in ``try/catch (\Throwable)``. Every failure mode yields a *smaller*
set, never an exception escaping ``stdWrap()`` and never an open gate.

Memoisation of A1/A3 and A2 uses two ``\WeakMap``\ s keyed on the
``FrontendTypoScript`` and ``Site`` instances. Weak, per-object keys mean a
long-running SAPI (FrankenPHP, RoadRunner) cannot serve one request's set to the
next, and keying on those objects rather than on the request survives the
distinct request instances that Extbase and ``USER_INT`` sub-renders carry. The
A4 grant and the log latch are ``\WeakMap``\ s too, keyed on the request — see
:ref:`adr-035-request-scoping`.

Logging
-------

Outside :guilabel:`Development` the skip path writes **no** record — the only
volume unauthenticated input provably cannot raise. In :guilabel:`Development` a
single ``notice`` per request is emitted behind a latch, so N rejections yield
at most one record for any N.

The pre-existing ``warning`` in the resolution catch shares that latch **in
strict context only**, and the latch is per request, not per process. That
matters in both directions:

*  100 injected placeholders naming a withheld secret used to produce 100
   warnings and 100 ``AccessDenied`` audit rows; they now produce at most one
   record and no rows;
*  but a rejection in one request cannot consume the next request's slot, and in
   legacy context (CLI, backend) nothing is latched at all. A process-wide latch
   would have handed an attacker a log blackout — see
   :ref:`adr-035-request-scoping`.

The identifier is echoed only when ``IdentifierValidator::isValid()`` passes,
otherwise the literal ``[invalid]`` — no newline injection, no length blow-up,
never a secret value.

Consequences
============

-  No documented configuration changes behaviour. Every shipped example
   publishes its own identifier through A1 or A2.
-  A bare ``%vault(id)%`` typed into a Fluid template file, on a site whose
   integrator adds neither A3 nor A4, stops resolving. It fails loud, and the
   remedy is one TypoScript line.
-  A scheduled job that renders editor-authored content and relied on the CLI
   carve-out stops resolving unpublished identifiers. It fails loud, and the
   remedy is one ``frontendResolvableIdentifiers`` line, one
   ``allowIdentifier()`` call, or — for a deployment that genuinely cannot do
   either — ``frontendPlaceholderLegacyCli = 1``.
-  No schema change, no TCA change, no new dependency, no database access added,
   zero new writes. One extension-configuration key
   (``frontendPlaceholderLegacyCli``, default ``0``), added by the 2026-08-02
   amendment; the original decision added none. A half-migrated install cannot
   fatal: a rejected identifier never touches the database, an accepted one
   takes exactly today's path, and an absent key reads as its secure default.

Rejected alternatives
=====================

**Detecting context only through** :php:`$GLOBALS['TYPO3_REQUEST']`, treating
"no request" as legacy. That global is absent in eID, so this leaves the
unauthenticated path open while appearing to close it.

**Harvesting the cObj configuration** (``$event->getConfiguration()``) as an
allow-set source. A third-party ``$cObj->stdWrap($x, ['wrap' => $userInput])``
puts attacker-influenced bytes into that array. In frontend scope it is also
redundant: every cObj configuration is a slice of the setup array, already
covered by A1.

**A per-call blanket opt-in** such as ``nrVaultResolve = 1`` in the cObj
configuration. Unforgeable (``stdWrap()`` only writes back into keys present in
``STD_WRAP_ORDER``), but it authorises *any* frontend-accessible identifier
inside that blob — wider than an identifier-scoped invariant — and its natural
placement (``page.10.stdWrap.``, ``FLUIDTEMPLATE.stdWrap.``) is exactly where
editor content is aggregated. A3 keeps the unforgeability and makes the grant
identifier-scoped.

**An extension-configuration key** instead of A3's TypoScript path. Same trust
domain, but per-installation instead of per-site, and it needs an Install Tool
round-trip plus new ``ext_conf_template.txt`` surface. (Still rejected as an
*allow-set source*. ``frontendPlaceholderLegacyCli`` is not one: it selects a
context rule, and it publishes no identifier.)

**A per-request resolution cap.** An arbitrary constant that degrades a
legitimate page in production. Memoising resolved values inside the listener is
likewise rejected: ``VaultService`` holds no plaintext cache (the request-scoped
one was removed on 2026-08-01), and one audit ``Read`` row per resolution is the
deliberate contract, not an artefact the listener may optimise away.

**A** ``legacy`` **opt-out switch for the whole policy.** One config key that
restores the vulnerable behaviour everywhere is one edit away from being set
everywhere and never removed. The fix already fails loud with a one-line
per-site remedy.

The 2026-08-02 amendment adds ``frontendPlaceholderLegacyCli``, and this
rejection is the reason it is shaped the way it is rather than a reversal of it.
It is not that switch: it is scoped to the CLI, so no web request — the surface
this ADR is about — can be weakened with it; it defaults to ``0``; it honours the
``$TYPO3_CONF_VARS[SYS][nrVault]`` pin, so an operator can put the weakening out
of reach of a compromised admin; and it exists because removing the CLI carve-out
is a *behaviour change to working installations*, which the original decision
never had to offer a migration path for. A blanket opt-out remains rejected.

Residual risk
=============

-  **Identifier-scoped, not location-scoped.** An editor can still re-emit an
   identifier this site's own TypoScript or site configuration already
   publishes, at a different location. Incremental disclosure is nil — that
   value is already on that site for the same anonymous audience — and what is
   closed is enumeration of *arbitrary* frontend-accessible secrets, which is
   the finding. Location scoping would need an unconditional walk or a mutation
   of the setup array on every request.
-  **A bare placeholder in a Fluid template file** stops resolving without A3 or
   A4. Such a placeholder was already inconsistent: a ``FLUIDTEMPLATE`` without a
   ``stdWrap.`` sub-array never reached the listener at all.
-  **Repeat resolution of an allow-listed identifier** writes one audit
   ``Read`` row per occurrence, unconditionally — there is no plaintext cache
   to absorb the repeats. Pre-existing, and strictly narrower afterwards.
-  **A2 trusts a core ACL** that v13.4 still marks ``@todo implement
   access=user`` on the site-settings module. If core opens site settings to
   non-admins, A2 must be dropped. Pinned as a comment at the A2 collector.
-  **A4 is a trust primitive.** An integrator who passes request-derived data to
   ``allowIdentifier()`` re-opens the hole in their own installation.
-  **The CLI opt-in restores the exposure it was added to close.**
   ``frontendPlaceholderLegacyCli = 1`` puts every command-line render back into
   LEGACY, and what that re-opens is not academic: ``scheduler:run``
   authenticates the ``_cli_`` administrator, so the admin bypass grants the
   read regardless of the per-secret tiers, and a scheduled newsletter or export
   job that renders editor-authored ``tt_content`` through ``stdWrap`` then
   substitutes any frontend-accessible secret an editor can name. Whether the
   result is *disclosure* depends on where that job's output goes — a mail to a
   subscriber list, a file on disk, an HTTP callback — which is outside this
   extension's knowledge, so the flag has to be read as re-opening the hole, not
   as narrowing it to a safe context. Three things keep it from being the
   blanket opt-out this ADR rejects: it is CLI-scoped and cannot weaken a web
   request, it defaults to ``0``, and it honours the
   ``$TYPO3_CONF_VARS[SYS][nrVault][frontendPlaceholderLegacyCli]`` pin, so an
   operator can put the weakening out of reach of the backend Settings module —
   which matters here, because the flag's only effect is to open a gate.
   ``vault:doctor`` does not report it; an operator who sets it has to remember
   it themselves.
-  **A CLI render that carries no request of its own resolves nothing**, because
   A4 needs a request to be keyed on and the console application's own request
   is not automatically the renderer's. This is the fail-closed direction and
   the same state a bare renderer is in on the web (see the entry below), but on
   the CLI it is newly reachable: before the amendment every CLI render was
   LEGACY, so the question never arose. An integrator's render job publishes
   through A1/A3 on the request it renders with, or calls ``allowIdentifier()``
   with the request it then passes to ``setRequest()``.
-  **The Development notice is unbounded on the CLI.** The latch deliberately
   never engages there (a per-run latch would be an attacker-triggered log
   blackout — see :ref:`adr-035-request-scoping`), so a planted placeholder can
   drive one ``notice`` per occurrence in a :guilabel:`Development` context.
   That is the pre-ADR-035 warning volume rather than a new capability, and
   production writes nothing on this path.
-  **Rejection is silent, so probing leaves no trace.** This is the cost of the
   "0 audit rows, 0 log records" property, and it is a real loss, not only a
   win. Before this ADR, a placeholder naming a withheld secret reached
   ``retrieveForFrontend()`` and produced one ``AccessDenied`` audit row per
   occurrence. Now, in strict context outside :guilabel:`Development`, a
   rejected identifier reaches neither the vault nor any log record, so an
   attacker can enumerate which identifiers a site publishes — by observing
   whether the literal survives in the output — with nothing written anywhere.
   The alternative is worse: any per-rejection record is a write an anonymous
   visitor can drive at will, which is the amplification the old behaviour had
   and which this ADR set out to remove. Detection therefore moves to the
   output side (``%vault(`` appearing in a rendered page) and to running
   :guilabel:`Development` while investigating. A bounded per-request signal in
   production was considered and rejected: at one record per request it is still
   attacker-paced, and it re-adds a log line to a path that is on every page.
-  **An unknown web SAPI** — non-CLI, no request obtainable anywhere, e.g. a
   hand-rolled entry point outside core's application objects — is strict, so
   placeholders stay literal, **including A4 grants**, which now need a request
   to be keyed on. This is the fail-closed direction. Because there is no
   request to latch on either, the :guilabel:`Development` notice is unbounded
   in that context; it is Development-only and this entry point is outside
   core's own request handling.
-  **A content object renderer that carries no request of its own** is in that
   same fail-closed state even in a live frontend request, because
   :php:`$GLOBALS['TYPO3_REQUEST']` is deliberately not accepted as a substitute.
   Core sets the request on every renderer it builds, and v14 deprecates leaving
   it unset, so this is third-party reachable only. The alternative — accepting
   the global — is the leak this ADR closes.
-  **A fully cached page hit with no** ``USER_INT``/``COA_INT`` **object** leaves
   the setup array unbuilt, so A1 and A3 contribute nothing for that request and
   only A2 and A4 apply. Fail-closed, no documented example affected, but
   third-party reachable: an extension that renders through ``stdWrap`` on such
   a hit sees a narrower allow-set than on an uncached hit.
-  **Backend-scope rendering stays legacy where the renderer carries the
   backend-typed request** — which is every renderer core builds for a rendering
   path — so a backend preview can still substitute a frontend-accessible secret
   found in editor content. The viewer is an authenticated backend user and the
   output does not enter the frontend page cache. A renderer built *without* a
   request is strict wherever it runs, backend scope included (core has such a
   call site: ``BackendConfigurationManager`` builds a bare renderer for a
   ``storagePid`` ``stdWrap``), because "backend" can no longer be inferred from
   a leftover global. That narrowing is the fail-closed direction and the price
   of the property above.
