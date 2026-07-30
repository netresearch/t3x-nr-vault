.. include:: /Includes.rst.txt

.. _adr-033-foreign-envelope-rotation:

=================================================================
ADR-033: Master-key rotation reaches consumer-owned envelopes
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

``vault:rotate-master-key`` re-wrapped every DEK it could find by iterating
``SecretRepositoryInterface::findIdentifiers()`` — that is, the rows of
``tx_nrvault_secret``, and nothing else.

That was complete for as long as this extension was the only thing storing
envelopes. It stopped being complete once consumers began encrypting their own
payloads with the same managed key: :php:`EncryptionService::encrypt()` wraps each
DEK with the current master key, but a consumer's wrapped DEK sits in the
consumer's own table. Rotating therefore left those envelopes wrapped under a key
the operator was told to archive or destroy, and they became permanently
undecryptable — with no error at rotation time, because the rotation genuinely
succeeded at everything it knew about.

nr-llm hit this concretely. Its ADR-114 claimed "key rotation is the vault's …
rotating the master key re-wraps the DEKs without touching the row ciphertext",
and cited :php:`MasterKeyRotatedEvent` as the mechanism. Neither half held:
rotation never looked outside ``tx_nrvault_secret``, and the event — declared in
``Classes/Event/``, documented in :file:`Api.rst`, and listed as step 3 of the
rotation procedure in :ref:`ADR-003 <adr-003-master-key-management>` — was never
dispatched from anywhere in ``Classes/``. A consumer could not even have
subscribed to learn that a rotation had happened.

Decision
========

Make consumer-owned envelopes a first-class part of the rotation, and dispatch
the event that was already promised.

The seam
--------

A consumer implements :php:`ForeignEnvelopeRotatorInterface` and tags it:

.. code-block:: yaml

   Vendor\Extension\Crypto\MyEnvelopeRotator:
     tags: ['nrvault.foreign_envelope_rotator']

The command collects the tagged services and calls each one's
:php:`rewrapAll()` with an :php:`EnvelopeRotationContext`.

Keys stay inside the context
----------------------------

Re-wrapping needs both the old and the new master key, but a consumer has no
business holding either. :php:`EnvelopeRotationContext` closes over both and
exposes only :php:`rewrap(string $sealed, string $identifier): string`, so a
consumer moves an envelope between keys without ever seeing key material. Both
constructor parameters carry ``#[\SensitiveParameter]``, so a stack trace
unwinding through it shows them redacted, and a unit test asserts the class
exposes no property or method through which a key could be read back.

Inside the transaction, before the audit re-key
-----------------------------------------------

This is the crux of the design. A listener notified *after* the commit can no
longer obtain the old master key, so it could not re-wrap anything — which is
why an "announce it afterwards" event was never going to be sufficient, and why
the seam is a collected interface call rather than an event listener.

:php:`rewrapAll()` therefore runs inside the command's existing transaction:

1. the vault's own secrets are re-encrypted;
2. **every registered consumer re-wraps its envelopes**;
3. the audit chain is re-keyed, which takes the audit advisory lock and holds it
   for the remainder of the transaction — so anything that still needs to write
   must have written by then;
4. commit;
5. :php:`MasterKeyRotatedEvent` is dispatched, carrying both counts.

Fail closed, everywhere
-----------------------

-  A consumer that throws rolls back the **entire** rotation — this extension's
   secrets, the audit-chain re-key, and every other consumer. A partially
   rotated installation is worse than an unrotated one: some data is wrapped
   under a key the operator has been told to destroy.
-  A consumer that cannot be **inventoried** (``countEnvelopes()`` throws) aborts
   before anything is touched. Not knowing what a rotation is about to change is
   a reason to refuse it.
-  A consumer whose tables are mapped to a **different database connection** is
   refused, mirroring the existing precondition on ``tx_nrvault_audit_log``:
   across two connections "one transaction" is a fiction and half a rotation
   could commit.
-  A vault holding **no secrets of its own** no longer short-circuits to
   "nothing to do" — it may be the key authority for thousands of consumer
   envelopes. In that case the old key cannot be smoke-tested against a real
   secret up front, and the operator is told so explicitly rather than left to
   assume it was checked; a wrong key then surfaces as a consumer failure, which
   rolls back.

Consequences
============

-  Sealing a payload as a consumer now has a stated obligation: register a
   rotator, or the data dies at the next rotation. Both this ADR and
   :php:`EnvelopeCodecInterface` say so, because the failure is silent and
   surfaces long after the mistake.
-  ``vault:rotate-master-key`` reports each participant and its envelope count,
   in both dry-run and live mode, so an operator can see the blast radius before
   confirming.
-  :php:`MasterKeyRotatedEvent` is dispatched for the first time, after the
   commit, so a listener never observes a rotation that was rolled back. It
   gained a ``foreignEnvelopesReEncrypted`` field with a default of 0, which
   keeps existing constructor calls working.
-  Rotation wall-clock now includes every consumer's pass, in one transaction.
   Consumers are required to work in batches for this reason.
-  The command's constructor gained the codec, the access-control service (for
   the event's actor), the event dispatcher, and the tagged-rotator iterable.

See also
========

-  :ref:`ADR-003 <adr-003-master-key-management>` — the rotation procedure this
   completes.
-  :ref:`ADR-032 <adr-032-portable-envelope-codec>` — the codec whose
   :php:`seal()` creates the obligation.
