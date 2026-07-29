.. include:: /Includes.rst.txt

.. _adr-031-shared-secret-pattern-catalogue:

=================================================================
ADR-031: One shared catalogue of secret shapes
=================================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-07-29

Context
=======

Knowing what a secret looks like was implemented four times: once here, in
``SecretDetectionService``'s private ``VALUE_PATTERNS`` /
``COLUMN_NAME_PATTERNS`` / ``EXT_CONFIG_KEY_PATTERNS`` constants, and three
times in nr-llm — a guardrail masking secrets in prompts and model responses, a
privacy redactor masking them before they are persisted, and a tool that lists
the process environment to a language model.

The four copies had drifted apart, in both directions:

-  This scanner knew Stripe, SendGrid, Twilio, Mailchimp and PayPal shapes.
   None of the redactors did.
-  The redactors knew OpenAI project keys (``sk-proj-…``), fine-grained GitHub
   PATs (``github_pat_…``), the ``ghs_`` token prefix and bare JWTs. The
   scanner did not.
-  Within nr-llm the copies disagreed with each other: measured against twelve
   secret shapes, the guardrail masked eleven while the privacy redactor missed
   seven of them — so a secret that was correctly masked on its way to a
   provider was still written to the database in cleartext.

Every copy was individually defensible and collectively wrong. Nothing made
the copies converge, and each new shape had to be added in four places by
someone who knew all four existed.

Decision
========

Extract one catalogue into ``Netresearch\NrVault\Secret`` and have every
consumer — this extension's scanner included — read from it.

Two forms per shape
-------------------

:php:`SecretPattern` carries both forms a shape needs:

-  an **anchored** pattern (:regexp:`^…$`) for whole-value classification, which
   is what a scanner asks of a column value;
-  an **inline** pattern for finding the shape embedded in free text, which is
   what a redactor asks of a prompt or a log line.

They differ in strictness deliberately, and that is the reason to keep them on
one object rather than in two lists: a scanner that over-matches invents
findings, while a redactor that under-matches leaks. Keeping the two forms
adjacent is what stops them drifting, which is the failure this ADR responds to.

Either form may be absent:

-  **No inline form** where the shape is too generic to hunt for inside prose.
   A bare 32-character hex string is a Twilio auth token, but it is also every
   MD5 digest; masking it inline would corrupt far more legitimate text than it
   would protect. Twilio and PayPal are anchored-only for this reason.
-  **No anchored form** where the shape only ever appears embedded: a
   ``Bearer …`` header, or credentials inside a URL.

Existing patterns are frozen
----------------------------

The anchored patterns and their **names** are carried over byte-identically.
A finding is labelled with the pattern name and its severity is derived from
whether a pattern matched at all, so renaming or loosening one would silently
change findings in every installation. ``SecretPatternLibraryTest`` pins all
eighteen pre-extraction patterns against a verbatim copy of the old constant,
so the extraction cannot regress them and a future edit has to be deliberate.

New shapes were only added. Three of them (OpenAI, ``ghs_``, fine-grained
PATs) now also classify **values**, which means a cleartext OpenAI key in a
database column is reported as ``Critical`` where it was previously unlabelled.
That is a deliberate improvement in scan output, not a side effect.

Three identifier namespaces, not one
------------------------------------

Judging a *name* secret-bearing needs different rules per namespace, so
:php:`SecretIdentifierKind` keeps them apart rather than offering one union.
Database columns and configuration keys are suffix-anchored
(``/secret$/`` matches ``clientSecret`` but not ``secretPrefix``), while a
process environment needs a broad substring rule because its names are terse
and inconsistent (``PGPASSWORD``, ``DATABASE_URL``, ``TYPO3_ENCRYPTION_KEY``).
Applying the environment rule to a database column would flag ``keyword``
because it contains ``KEY`` — a union would have imported exactly that bug.

E-mail masking is opt-in
------------------------

:php:`SecretRedactorInterface::redact()` takes ``$includeEmails``, defaulting to
off. An address is personal data rather than a secret, and the two callers want
opposite things: a privacy redactor writing to storage should mask it, while a
guardrail rewriting a prompt should not — silently removing an address from a
prompt changes what the user asked.

Query-parameter and userinfo patterns are bounded
-------------------------------------------------

The URL patterns inherited from nr-llm bounded their value only at ``&`` or
whitespace, which let them run off the end of the URL. Masking
``{"url":"…?token=abc","next":"keepme"}`` swallowed the closing quote, the brace
and the following key; the userinfo pattern turned
``{"url":"https://example.com:8080","contact":"support@example.org"}`` into
``{"url":"https://example.com:***@example.org"}`` — deleting the port and the
contact field, and fabricating a credentialled URL to a host that was never
contacted. Both classes now stop at structural characters, the technique
:php:`OAuthTokenManager` already used.

The parameter-name alternation also accepts an optional vendor prefix, because
without it ``client_secret`` — the name RFC 6749 §2.3.1 defines — matched
nothing, and an OAuth client secret in a query string survived redaction
untouched. ``password`` and the hyphenated ``api-key`` were missing for the same
reason.

Bearer runs first
-----------------

The ``Bearer …`` pattern is applied before the prefix-specific shapes. Run after
them, the OpenAI rule rewrote the key to ``sk-***`` and the Bearer rule then
matched the leftover ``Bearer sk-``, producing ``Bearer ******``.

Failure is not a wipe
---------------------

``preg_replace()`` returns ``null`` when the regex engine gives up, and a bare
``(string)`` cast turns that into ``''``. On a redaction path, wiping the entire
content looks exactly like a successful, very thorough redaction. The redactor
keeps the last good text instead, so one failing pattern is skipped while the
rest still apply.

Consequences
============

-  Four catalogues become one. A new shape is added once, and both the scanner
   and every redactor gain it.
-  One deliberate exception: :php:`OAuthTokenManager` keeps its own patterns,
   because it must also reach credentials inside quoted and JSON-escaped forms
   (``"client_secret":"…"``), which this catalogue does not model. Its
   value-bounding technique was adopted here.
-  The scanner's constructor gains a :php:`SecretRedactorInterface`. Its
   behaviour on the frozen patterns is unchanged; it additionally classifies the
   three added shapes.
-  Scan output changes for installations that hold a cleartext OpenAI key,
   ``ghs_`` token or fine-grained PAT in a scanned column or configuration key:
   such a finding gains a pattern name and is raised to ``Critical``.
-  Redaction is a best-effort net for secrets that have already escaped their
   proper home. It recognises the catalogued shapes and nothing else, and does
   not weaken the rule that secrets belong in the vault.
-  The redactor alias is ``public`` so a consuming extension can resolve it via
   ``GeneralUtility::makeInstance()`` in contexts without constructor injection.

See also
========

-  :ref:`ADR-032 <adr-032-portable-envelope-codec>` — the other API extracted
   for consumers in the same change.
