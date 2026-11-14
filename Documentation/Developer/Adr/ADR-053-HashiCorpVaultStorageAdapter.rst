.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-053-hashicorp-storage-adapter:

=================================================
ADR-053: HashiCorp Vault storage adapter
=================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-11-13

Context
=======

The ``storageAdapter`` setting listed ``hashicorp`` and ``aws`` while only
``local`` existed, and the ``hashicorp.*`` auth settings offered ``approle`` and
``kubernetes`` that nothing accepted. Operators who already run HashiCorp Vault
want the encrypted envelope of a secret to live there, under Vault's policies
and Vault's own audit device, instead of in the TYPO3 database.

The storage contract, :php:`VaultAdapterInterface`, is not a plain key-value
store. It addresses secrets by UID for the availability flag and the read
counter, returns :php:`Secret` entities that carry the owner, the two group
tiers, the metadata and the counters, and every one of those is read by the
backend module, the list commands, the access-control service and the audit
trail. Master-key rotation and the rotation-gap repair read the envelope from
the database row directly.

Decision
========

Keep the database row as the registry of a secret and move only the encryption
envelope to Vault.

*   **What is stored where.** The row keeps identifier, owner, group tiers,
    metadata, version, counters and timestamps, plus ``adapter = hashicorp``
    and ``external_reference`` (the KV path). Its envelope columns are empty,
    which :php:`Secret` already accepts as a consistent state. Vault KV v2
    holds the envelope: encrypted value, wrapped data key, both nonces,
    checksum, envelope version and algorithm marker, base64-encoded where
    binary. The value is still encrypted by nr-vault before it leaves the
    process, so Vault stores ciphertext it cannot read, and a stolen database
    holds no envelope at all.
*   **Selection.** ``StorageAdapterFactory`` binds
    :php:`VaultAdapterInterface` by the ``storageAdapter`` setting. An unknown
    value is refused instead of treated as ``local``. A consuming extension that
    binds the interface itself still replaces the factory's result.
*   **Per-row routing.** Each row routes by its own ``adapter`` column. A secret
    stored locally before the switch stays local and keeps working; a new
    secret, and a row that exists without a value (the FormEngine creation
    path), goes to Vault. Nothing migrates existing secrets.
*   **Order of writes.** On store, Vault is written first, then the row. A
    failed first insert removes the Vault key it just wrote. On delete, Vault is
    emptied first, then the row, so a half-finished delete can be repeated. KV
    v2 keeps versions; delete removes the key through the metadata path, so no
    version survives.
*   **A path that is not ours.** A KV path may hold somebody else's data. A new
    secret claims its path with a create-only write (KV v2 check-and-set with
    ``cas=0``), in one request: a key that exists is read, and only an nr-vault
    write of this installation for the same identifier (an unreferenced leftover
    of a crash; the write carries an HMAC of the master key, so a key written by
    another installation is not taken over) is taken
    over; anything else is refused with code ``1794400012`` and left untouched,
    including by the compensation, which destroys only a key this call created
    and puts a taken-over one back. There is no window between the check and the
    write for a store that offers the create-only write. Every write of such a
    store reports the KV version it created, and the rollback is a check-and-set
    against exactly that version (``cas``): Vault applies it only if nobody wrote
    since, so a concurrent writer is neither overwritten nor deleted, and no
    payload is compared. The one exception is the delete that takes back a
    create: KV v2 has no conditional delete, so the version is read immediately
    before the delete and a write landing in that gap is not detected. A failed
    audit write is compensated by :php:`VaultService`. An adapter that
    implements :php:`CreateCompensatingAdapterInterface` undoes exactly what the
    create did: it destroys a key the call created and puts back one it took
    over (a plain ``delete()`` would destroy the leftover that was adopted); the
    row is removed in both cases. A rollback that is skipped because the key is
    no longer at the version this call wrote is logged as a warning, and the
    version read is retried a few times so a read that has not caught up with
    the write is not mistaken for a concurrent writer. The interface for it is
    :php:`AtomicKvStoreInterface`, which the shipped store implements. A store
    that implements only :php:`KvStoreInterface` is deprecated: the adapter
    reads, then writes, which leaves that window open, and reports a
    deprecation once; version 2.0 will require the atomic interface. A row
    already bound to Vault owns its key, but only at the location it recorded:
    when the row's stored reference differs from the key the current
    ``hashicorp.path`` resolves to, store, delete and read are refused (code
    ``1794400015``) instead of touching an unrelated key, and the key's payload
    must carry the row's identifier, and no other installation's marker, before
    it is overwritten or destroyed. A payload without a marker (written by 1.6.x)
    is accepted for a row bound to it, because such a row holds no envelope to
    compare, and the next write stamps the marker. The marker is derived from the
    master key, so a master-key rotation that supports external secrets must
    re-stamp it on every payload; until then rotation refuses while any exist.
*   **Authentication.** One authenticator for ``token``, ``approle`` and
    ``kubernetes``. The token comes from an environment variable (stored
    fallback for ``token`` only), the AppRole secret id from the environment
    only, the Kubernetes JWT from the projected service account file. A login
    token is memoised for the life of the object and refreshed when 80 percent
    of its lease has passed; a request rejected with 403 under a login method is
    retried once after a fresh login. Nothing is persisted.
*   **Transport.** All requests go through the client
    :php:`SecureHttpClientFactory` builds: SSRF range check, DNS pin, no
    redirects, no request logging, a 10 second bound. A private or loopback Vault
    address needs a literal ``allowed_hosts`` entry, the existing opt-in. The
    address must be ``https`` unless ``hashicorp.allowInsecureHttp`` is set; it
    must be a bare origin without credentials, path, query or fragment. Mount,
    prefix and identifier are validated per path segment before they reach a
    URL.
*   **Errors.** :php:`HashiCorpException` names the operation and the HTTP
    status. No token, login credential, response body or secret value appears in
    a message.
*   **Audit.** Unchanged. :php:`VaultService` audits every operation at its own
    boundary, whichever adapter stores the envelope.
*   **Master-key rotation refuses.** Rotation is one database transaction;
    an envelope in Vault cannot join it. ``vault:rotate-master-key`` therefore
    stops with a named secret while any secret is stored outside the local
    database, before changing anything. Re-wrapping data keys held in Vault is
    not part of this decision.

HTTP client libraries and SDKs
------------------------------

No Vault client library is added. The three operations the adapter needs are
KV v2 read, write and delete plus a login call; they go through the existing
PSR-18 client. A third-party client would bring its own transport and bypass the
SSRF and DNS-pin middleware the extension relies on.

Consequences
============

Positive
--------

-  Vault policies and Vault's audit device apply to every envelope.
-  Listing, access control, expiry, analytics and the audit trail work unchanged,
   because the registry row stays.
-  Switching the setting is safe: existing secrets keep working.

Negative
--------

-  A secret now has two stores. A crash between the two writes leaves an
   unreferenced Vault key (overwritten by the next store of that identifier) or,
   after a failed update of the row, a row whose metadata is one write behind the
   envelope. Neither loses a value.
-  When the audit write fails after a Vault change, the existing compensation
   restores the previous envelope as a new KV version; a compensated delete
   recreates the key with its latest value only, so older KV versions are not
   restored. Nothing here is crash-atomic (:ref:`adr-036-mutation-audit-atomicity`).
-  A Vault outage makes secrets stored there unreadable; secrets stored locally
   are unaffected.
-  Master-key rotation is unavailable while Vault-backed secrets exist.
-  The registry rows are still in the database: names, owners, groups and
   metadata remain visible to anyone who can read it.

Alternatives considered
=======================

Store the whole secret, including ownership and counters, in Vault
------------------------------------------------------------------

**Rejected.** UID-addressed operations, the group tiers in MM tables and the
audit references would need a second implementation on top of Vault, and the
read counter would become a write to Vault on every read.

Store the plaintext in Vault and skip the envelope
--------------------------------------------------

**Rejected.** It breaks "no plaintext storage outside envelope encryption" and
the contract with :php:`VaultService`, which decrypts what the adapter returns.

Use a Vault client library
--------------------------

**Rejected**, see above.

Related decisions
=================

-  :ref:`adr-002-envelope-encryption` - The envelope that moves to Vault
-  :ref:`adr-026-dns-rebinding-defence` - The transport defences the adapter reuses
-  :ref:`adr-036-mutation-audit-atomicity` - Why a non-local adapter takes the compensation path
-  :ref:`adr-003-master-key-management` - Transit custody; token auth only
