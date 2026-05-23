.. include:: /Includes.rst.txt

.. _adr-028-phpat-http-client-lock:

==============================================================
ADR-028: PHPat architectural lock for HTTP client construction
==============================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-05-23

Context
=======

The vault enforces multiple layers of outbound HTTP defence:

-  ``SecureHttpClientFactory::create()`` configures the
   ``isHostAllowed`` allowlist, the DNS-rebinding middleware
   (:ref:`adr-026-dns-rebinding-defence`), retry policy, and timeouts.
-  ``OAuthTokenManager`` (:ref:`adr-027-oauth-client-unification`)
   routes through the same factory so token endpoints inherit the
   same protections.

These defences are only worth what the construction site is worth.
Any code that calls ``new \GuzzleHttp\Client(...)`` directly bypasses
every middleware the factory installs — and that's exactly the kind
of regression that *looks* fine in code review ("just adding a
small HTTP call") but silently undoes the SSRF guard.

History shows this isn't theoretical: PR #145 review found one such
site in adapter code that escaped earlier review cycles. We need a
mechanical fence, not just convention.

Decision
========

Add a PHPat architectural rule to ``Tests/Architecture/ArchitectureTest.php``
(verbatim from ``testOnlySecureHttpClientFactoryInstantiatesGuzzleClient``):

.. code-block:: php

    public function testOnlySecureHttpClientFactoryInstantiatesGuzzleClient(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\\NrVault'))
            ->excluding(
                Selector::classname(SecureHttpClientFactory::class),
                Selector::inNamespace('Netresearch\\NrVault\\Tests'),
            )
            ->shouldNot()
            ->dependOn()
            ->classes(Selector::classname(Client::class))
            ->because(
                'all outbound HTTP must flow through SecureHttpClientFactory; '
                . 'instantiating GuzzleHttp\\Client directly bypasses SSRF + '
                . 'DNS-rebinding + no-redirect defences (PR #145)',
            );
    }

The rule uses ``shouldNot()->dependOn()`` rather than a hypothetical
``shouldNotConstruct``. ``dependOn`` is intentionally broader: it forbids
any reference to ``GuzzleHttp\\Client`` (``new``, ``use``, type-hint,
static call) outside the allowed namespaces. That's the strictest
fence PHPat offers and matches the intent — production code shouldn't
even *name* the class.

Allowed namespaces (an explicit allowlist, not a regex):

-  ``SecureHttpClientFactory`` — the single legitimate constructor.
-  ``Netresearch\\NrVault\\Tests`` — test doubles and fixtures need
   to construct ``GuzzleHttp\\Client`` instances directly to wire
   ``MockHandler``-driven flows. Tests don't ship in the distributed
   extension, so they can't widen the production attack surface.

The rule runs in the standard PHPat suite (``composer ci`` and the
CI ``architecture`` job), so violations fail the build with a
deterministic message naming the offending class.

Consequences
============

Positive
--------

-  Future regressions get a hard "cannot instantiate" failure at
   PHPat time, not at a security-audit time three months later.
-  Code review for new HTTP-using classes becomes mechanical:
   either the diff calls ``$factory->create(...)`` or PHPat fails.
-  Documents the rule alongside the rest of the architectural
   contract — anyone surveying ``Tests/Architecture/`` sees the
   constraint without hunting for tribal knowledge.

Negative
--------

-  Genuine edge cases (e.g., a one-off testing-only HTTP client
   that intentionally skips the middleware) need explicit allowlist
   additions with PR-level justification. This is intentional
   friction — the friction *is* the value.
-  PHPat takes ~1 s to evaluate the rule. Negligible.

Verified
========

-  Rule passes on the current codebase (post-#146 cleanup).
-  Manually verified: inserting ``new Client()`` into any adapter
   fails ``composer ci`` with a PHPat error pointing at the file.

References
==========

-  Pull request: `#146 <https://github.com/netresearch/t3x-nr-vault/pull/146>`__
-  Related: :ref:`adr-010-secure-outbound`,
   :ref:`adr-026-dns-rebinding-defence`,
   :ref:`adr-027-oauth-client-unification`
-  PHPat docs: https://github.com/carlosas/phpat
