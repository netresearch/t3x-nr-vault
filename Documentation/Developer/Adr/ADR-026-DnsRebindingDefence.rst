.. include:: /Includes.rst.txt

.. _adr-026-dns-rebinding-defence:

==================================================
ADR-026: DNS-rebinding defence via CURLOPT_RESOLVE
==================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-05-22

Context
=======

The SSRF defence in ``SecureHttpClientFactory`` (see
:ref:`adr-010-secure-outbound`) rejects requests whose host
resolves into private / loopback / link-local / multicast /
cloud-metadata ranges. The host is resolved once via
``dns_get_record()``, every record is checked, and the request is
rejected if any answer falls in a dangerous range.

This defence has a documented but unaddressed gap that the comment
on ``isDangerousIpLiteral`` flagged from the start:

    Caveat: this defence is bypassable by DNS rebinding when the
    upstream HTTP client (Guzzle/curl) re-resolves at connect-time.
    For full protection, callers must pin to the resolved IP via curl
    ``CURLOPT_RESOLVE``; that is a follow-up.

The TOCTOU race:

1.  Code: ``gethostbyname('evil.attacker.com')`` → ``93.184.216.34``
    (harmless).
2.  Code: ``isDangerousIpLiteral('93.184.216.34')`` → false. OK to
    send.
3.  Code: ``$guzzle->post('https://evil.attacker.com/token', ...)``
4.  Guzzle/curl: ``gethostbyname('evil.attacker.com')`` →
    ``192.168.1.1`` (rebound; TTL = 1s).
5.  HTTP request goes to ``192.168.1.1``.

The defence checks the result of lookup #1; curl uses the result of
lookup #2 a second later.

Decision
========

Push a Guzzle middleware (``ssrf-dns-pin``) onto the
``HandlerStack`` inside ``SecureHttpClientFactory::create()``. The
middleware runs per outgoing request:

1.  Read URI host + port (normalised via the existing
    ``normaliseHost()`` so IPv6 brackets ``[::1]`` are stripped
    before validation).
2.  Resolve via ``DnsResolverInterface::resolve()``
    (``DefaultDnsResolver`` wraps ``dns_get_record(A | AAAA)``;
    in-memory test double exists for deterministic tests).
3.  Validate EACH returned record against the existing
    ``isDangerousIpLiteral()`` defence.
4.  If **any** answer is dangerous, reject the request with
    ``RequestException`` **before the socket opens**. (Defends
    split-horizon rebinding: a malicious resolver returning one
    safe + one internal IP can't trick curl into picking the
    internal one.)
5.  If all answers are safe, pin them via curl's ``CURLOPT_RESOLVE``
    option (``host:port:ip`` for IPv4, ``host:port:[ipv6]`` for
    IPv6 — colons in v6 require brackets in CURLOPT_RESOLVE's
    field-delimiter format).
6.  IP literals (already validated by ``isHostAllowed``) and
    unresolvable hosts pass through without a pin.

curl then skips its own DNS step and connects to the IP we just
validated. No second resolution, no rebinding window.

ext-curl absence
----------------

``HandlerStack::create()`` falls back to ``StreamHandler`` when
ext-curl is missing — StreamHandler **ignores** the ``curl`` option.
The factory logs a warning when ``curl_init`` is unavailable so
operators notice the gap. The pre-request validation
(``buildResolveEntries()`` rejecting dangerous IPs) still fires on
StreamHandler — only the race-free pinning is lost.

Consequences
============

Positive
--------

-  TOCTOU race closed: curl uses the IP we validated, not a
   newly-resolved one.
-  Split-horizon rebinding handled (any dangerous answer kills the
   request).
-  PSR-7 ``getHost()`` IPv6 bracket normalisation closes a separate
   security regression flagged by Gemini (``[::1]`` would have
   bypassed the literal-IP guard otherwise).

Negative
--------

-  curl-specific. Stream handler users get the original (pre-pin)
   defence only.
-  Dual-stack hosts where the v4 and v6 records have different
   trust levels (uncommon) get both pinned; curl's per-family
   interface selection picks one — current behaviour is "pin both,
   trust both".

Verified
========

-  Unit tests cover the four resolution outcomes (safe IPs → pin,
   any-dangerous → reject, IP literal → no pin, unresolvable → no
   pin).
-  Integration tests assert the ``ssrf-dns-pin`` middleware is
   registered on every factory-built ``HandlerStack``.
-  Regression test for the IPv6-bracket normalisation.

References
==========

-  Pull request: `#144 <https://github.com/netresearch/t3x-nr-vault/pull/144>`__
-  Related: :ref:`adr-010-secure-outbound`,
   :ref:`adr-008-http-client`
