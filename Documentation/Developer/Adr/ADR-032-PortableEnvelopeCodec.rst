.. include:: /Includes.rst.txt

.. _adr-032-portable-envelope-codec:

=================================================================
ADR-032: A portable envelope codec for consumer-owned payloads
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

:php:`EncryptionServiceInterface` mirrors this extension's own storage: its
:php:`decrypt()` takes seven arguments — ciphertext, wrapped DEK, two nonces,
the AAD identifier, and the version and algorithm markers — because those are
seven columns of ``tx_nrvault_secret``.

A consuming extension that wants to protect its own payload rarely has seven
columns to spare. It has one, and so it has to invent framing: pack the
:php:`EncryptedData` into something, unpack it again, validate every field,
decide what a corrupt value means, and version the format for later.

nr-llm did exactly that. Its ``AgentStateCodec`` (ADR-114 there, shipped in
nr-llm 0.24.0) is 154 lines, of which roughly a hundred are a version prefix, a
base64/JSON pack, a field-by-field type check and a corruption exception —
nothing specific to agent state, all of it re-derivable by the next consumer,
and each consumer arriving at a slightly different format.

Decision
========

Provide the framing here, once, as :php:`EnvelopeCodecInterface`: one string
in, one string out, with parsing and validation on this side of the boundary.

A new interface, not four more methods
--------------------------------------

The codec is a NEW interface rather than additional methods on
:php:`EncryptionServiceInterface`. Adding methods to a published interface breaks
every implementor of it, and the two interfaces answer different questions:
"encrypt these fields" versus "protect this payload". :php:`EncryptionService`
remains the crypto boundary; :php:`EnvelopeCodec` is framing on top of it and
holds no key material or cipher logic of its own.

Wire format
-----------

.. code-block:: text

   nrv1: + base64( JSON of EncryptedData::toArray() )

The marker makes a stored value self-identifying, so a column can hold sealed
and not-yet-sealed values during a migration and :php:`isSealed()` tells them
apart without the caller knowing the format.

The JSON body is deliberately **exactly** what a consumer that hand-rolled this
would already have written — ``EncryptedData::toArray()`` — so an existing
consumer can adopt the codec by mapping its own marker onto ``nrv1:``, with no
data migration and no re-encryption. ``EnvelopeCodecTest`` pins this by building
a body the way nr-llm's codec builds one and opening it here.

Parsing reads only the six fields it needs and ignores any others, so a body
written by an older or newer vault still opens. The change-detection checksum is
carried through re-wrapping but not required to open, and not verified —
integrity is the AEAD tag's job, and the checksum is an audit token.

Corruption is not tampering
---------------------------

:php:`EnvelopeFormatException` is a **sibling** of :php:`EncryptionException`, not
a subclass. "This string is not an envelope" and "this envelope failed
authentication" want different handling: the first is a truncated column, a
value that was never sealed, or garbage; the second means the ciphertext was
altered, moved to a different AAD context, or written under a key this host does
not hold. A consumer catching only :php:`EncryptionException` must not silently
absorb malformed input as if it were a failed MAC check.

Rotation is a caller obligation
-------------------------------

:php:`seal()` wraps the payload's DEK with the CURRENT master key, and that
wrapped DEK is stored in the CONSUMER's table, where this extension's rotation
cannot reach it. A consumer that seals therefore **must** also register a
:php:`ForeignEnvelopeRotatorInterface` (:ref:`ADR-033 <adr-033-foreign-envelope-rotation>`).
Sealing without one produces data that becomes permanently unreadable the moment
an operator rotates. Both the interface docblock and the rotation ADR say so,
because the failure is silent and only shows up long after the mistake.

Consequences
============

-  A consumer stores one string and writes no framing code. nr-llm's codec
   collapses to a marker-compat branch plus two delegating calls.
-  One format instead of one per consumer, so a future format change is a
   vault-side migration rather than an archaeology exercise across extensions.
-  :php:`rewrap()` re-wraps the DEK layer without decrypting the payload, so
   rotation never materialises plaintext.
-  The codec alias is ``public`` so a consuming extension can resolve it via
   ``GeneralUtility::makeInstance()`` outside a DI-constructed service.
-  The ``nrv1`` marker is a commitment: changing the body format requires a new
   marker and a read path for the old one.

See also
========

-  :ref:`ADR-002 <adr-002-envelope-encryption>` — the envelope encryption scheme
   itself.
-  :ref:`ADR-033 <adr-033-foreign-envelope-rotation>` — the rotation obligation
   that comes with sealing.
