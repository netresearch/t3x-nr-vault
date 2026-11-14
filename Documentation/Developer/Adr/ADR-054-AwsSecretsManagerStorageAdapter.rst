.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-054-aws-secrets-manager-storage-adapter:

=====================================================
ADR-054: AWS Secrets Manager storage adapter
=====================================================

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

The ``storageAdapter`` setting listed ``aws`` while the value behaved like
``local``. :ref:`adr-053-hashicorp-storage-adapter` settled how an external store
fits the storage contract: the database row stays the registry of a secret, and
only the encryption envelope moves. Operators who run on AWS want that envelope
in AWS Secrets Manager, under IAM and CloudTrail, with the same guarantees.

Three things differ from the HashiCorp case. AWS has no plain HTTP API that is
cheap to call by hand: every request is signed with Signature Version 4, and the
usual way to produce that signature is the AWS SDK for PHP. The SDK's default
credential lookup asks the instance metadata service at ``169.254.169.254``,
which the extension's SSRF defence refuses. And with two external adapters, a
row can now be bound to an adapter other than the configured one.

Decision
========

Apply the design of ADR-053 to a second store, and decide the three differences.

Same as ADR-053
---------------

*   **What is stored where.** The row keeps identifier, owner, group tiers,
    metadata, version, counters and timestamps, plus ``adapter = aws`` and
    ``external_reference``. Its envelope columns are empty. Secrets Manager holds
    one JSON document per secret with the encrypted value, wrapped data key, both
    nonces, checksum, envelope version and algorithm marker, base64-encoded where
    binary. The value is still encrypted by nr-vault before it leaves the
    process.
*   **Per-row routing.** Each row routes by its own ``adapter`` column. A secret
    stored locally before the switch stays local; a new secret, and a row that
    exists without a value, goes to AWS. Nothing migrates existing secrets.
*   **Order of writes.** AWS is written first, then the row. A failed first
    insert removes the AWS secret it just created, unless a row for the
    identifier exists by now. A failed row update puts the previous envelope back
    as a new version. On delete, AWS is emptied first, then the row, so a
    half-finished delete can be repeated.
*   **Audit.** Unchanged. :php:`VaultService` audits every operation at its own
    boundary. When the audit write fails after an AWS change, the existing
    compensation restores the previous envelope for create, rotate and delete.
*   **Gate classification and master-key rotation.** Both already test for "not
    stored locally" and not for a named adapter, so they hold for ``aws`` without
    change: a row that points at AWS but has no loadable envelope is an existing
    secret and keeps the rotate and policy gates, and ``vault:rotate-master-key``
    refuses while any secret lives outside the local database.

The SDK is a suggestion, not a requirement
------------------------------------------

``aws/aws-sdk-php`` is listed in ``suggest`` and ``require-dev``, never in
``require``. A TYPO3 installation that does not select ``aws`` does not install
it and boots without it: no class outside :php:`AwsClientFactory` and
:php:`AwsSecretsManagerStore` names an SDK type, no autowired constructor takes
one, and the factory builds the client on first use.

Selecting ``aws`` without the SDK fails with a :php:`ConfigurationException`
(code ``1794500002``) that names the Composer command. It does not fall back to
local storage. The failure comes on the first operation that needs AWS, not when
the setting is read, so secrets stored locally stay readable on an installation
whose SDK went missing.

ADR-053 declined a client library because it would bring its own transport and
bypass the SSRF and DNS-pin middleware. The SDK is used here for what is not worth
rewriting, Signature Version 4 signing, request building and response parsing,
and its transport is replaced: the AWS client is given the client that
:php:`SecureHttpClientFactory` builds, through the SDK's ``http_handler`` option.
Every request therefore passes the SSRF range check and the DNS pin, follows no
redirect, logs nothing and is bounded to ten seconds. A functional test pins this
with the same refusal ADR-053 has: an unlisted loopback endpoint is refused.

That client is built with ``http_errors`` off, so that the vault HTTP client can
audit error statuses. Handed to the SDK as it is, a 403 or 500 arrives as an
ordinary response and is parsed as an empty successful result: a rejected write
would read as stored. The AWS client therefore sets ``http_errors`` back on for
its own requests, and a unit test builds the client the production way to pin it.

Credentials are explicit
------------------------

The SDK is given one credentials object. That means its default provider chain,
including the instance metadata call, never runs, and ambient credentials of the
host are not picked up.

*   The access key id is read from an environment variable whose name is
    ``aws.accessKeyIdEnvVar``, with ``aws.accessKeyId`` as a stored fallback (it
    identifies, it does not authenticate).
*   The secret access key is read from the environment only, from the variable
    named in ``aws.secretAccessKeyEnvVar``. No setting stores it.
*   An optional session token, from ``aws.sessionTokenEnvVar``, makes temporary
    credentials usable.
*   The default variable names are ``NR_VAULT_AWS_*``, not the SDK's
    ``AWS_*``, so credentials that belong to something else on the host are not
    taken by accident.
*   Shared config and credentials files are not read, and ``AWS_ENDPOINT_URL``
    variables are ignored. Only ``aws.endpoint`` redirects the adapter.

Assuming a role is not part of this decision. It needs an STS call and a second
endpoint to harden, and temporary credentials can already be supplied through the
session token by whatever assumes the role outside PHP.

Transport and names
-------------------

*   Region is required and validated. An optional ``aws.endpoint`` (a VPC
    endpoint, a compatible service) must be a bare origin and must use ``https``
    unless ``aws.allowInsecureHttp`` is set, the same mechanism as
    ``hashicorp.allowInsecureHttp``. At most one retry, so an unreachable
    endpoint cannot hold a request for minutes.
*   The AWS secret name is :samp:`{prefix}/{identifier}`. AWS allows letters,
    digits and ``/_+=.@-``; an identifier may contain ``:`` (the
    ``site:<namespace>:<name>`` form), which AWS refuses, so the colon is written
    as ``+``. The mapping is injective because ``+`` is not in the identifier
    alphabet. The prefix is normalised, so the default ``typo3/`` yields
    ``typo3/name``, not ``typo3//name``. The registry row stores
    ``<region>:<name>``.
*   Delete uses ``ForceDeleteWithoutRecovery``. A recovery window would keep the
    last envelope alive for up to thirty days and block the name; without it no
    version survives.
*   A write adds a version (``PutSecretValue``) and creates the secret when AWS
    says it does not exist (``CreateSecret``); if a concurrent create wins in
    between, the conflict is raised (code ``1794500012``) and nothing is written
    into that writer's secret. A compensation that cannot apply because the
    secret changed since keeps the row and logs a warning.

Errors
------

:php:`AwsSecretsManagerException` names the operation, the HTTP status and the AWS
error code, a fixed identifier such as ``ResourceNotFoundException``. It is not
chained to the SDK exception, which holds the signed request and the command
parameters, and those include the encrypted envelope. Transport failures carry a
redacted client message.

A secret of somebody else is never overwritten or deleted
---------------------------------------------------------

AWS secret names are shared with everything else in the account. For a new secret
(or a row without a value) the adapter therefore creates the AWS secret with
``CreateSecret``, which fails when the name exists, instead of writing a version.
When it exists, the adapter reads it: only a document that is an nr-vault write
for this very identifier and this installation (format marker, identifier and an
HMAC of the master key stored in the document), an unreferenced leftover of an
earlier crash, is adopted and overwritten; a document of another installation is
not, so each installation needs its own prefix. Anything else is
refused with code ``1794500011`` and left untouched. Compensation follows the
same rule: a failed row write destroys only a secret this call created, and
puts an adopted one back. An existing AWS-bound row owns its secret at the
location it recorded: when the stored reference differs from the one the current
region and prefix resolve to, store, delete and read are refused (code
``1794500014``) instead of touching an unrelated secret; the document must carry
the row's identifier and no other installation's marker before it is overwritten
or destroyed. A document without a marker (an earlier write) is accepted for a
row bound to it, because such a row holds no envelope to compare, and the next
write stamps the marker. A document that is not a JSON object does not make the
row undeletable.

Taking a write back does not compare payloads. ``CreateSecret`` and
``PutSecretValue`` return the ``VersionId`` they created, and the rollback (put
the previous document back, or delete the secret this call created) reads the
``AWSCURRENT`` version id with ``GetSecretValue`` and applies only if it is still
the one the write returned. AWS has no conditional put or delete, so the id is
read immediately before the write or delete and a write that lands in that gap
is not detected; the read is retried a few times so a read that has not caught
up with the write is not mistaken for a concurrent writer, and a rollback that is
skipped is logged as a warning. A failed audit write is compensated by
:php:`VaultService`: an adapter implementing
:php:`CreateCompensatingAdapterInterface` destroys a secret the call created and
puts back one it adopted, then removes the row. The prefix ``typo3/`` stays the default; a
dedicated prefix keeps the names apart from other users of the account.

A row bound to another external adapter is refused
--------------------------------------------------

With two external adapters a row can name one that is not configured.
:php:`HashiCorpAdapter` and :php:`AwsSecretsManagerAdapter` therefore refuse to
store, retrieve or delete a row bound to a different external adapter
(:php:`ConfigurationException`, code ``1794500020``), instead of treating its
empty envelope as "new" and rebinding it, which would write a second copy and
orphan the first. The administrative lookup still returns the row, so it stays
listable. Select the adapter that owns the row to work with it; nothing moves
secrets between adapters.

Test infrastructure
-------------------

Functional tests run against Moto (``motoserver/moto``, an exact tag) through
Testcontainers, not LocalStack, whose current releases need a licence token. Moto
emulates the five Secrets Manager calls the adapter makes (create, put value,
get, describe, delete without recovery) and, with its IAM enforcement on, rejects
an unknown key id and a wrong secret with HTTP 403.

Consequences
============

Positive
--------

-  IAM policies and CloudTrail apply to every envelope.
-  Listing, access control, expiry, analytics and the audit trail work unchanged,
   because the registry row stays.
-  An installation without the SDK is unaffected, and one that selects ``aws``
   without it is told so.
-  The SDK's signing is reused without giving up the extension's transport
   defences.

Negative
--------

-  A secret has two stores and they are not updated atomically. A crash between
   the writes leaves an unreferenced AWS secret (overwritten by the next store of
   that identifier) or a row whose metadata lags the envelope by one write. A
   crash between the AWS delete and the row delete leaves a row whose envelope is
   gone; that value is lost and comes back only from a backup. A compensated
   delete recreates the secret with its latest value only
   (:ref:`adr-036-mutation-audit-atomicity`).
-  AWS stages versions. After a rotation the previous envelope stays in AWS
   labelled ``AWSPREVIOUS`` (measured on Moto 5.2.5; the real service was not
   measured), until the secret is deleted. The previous envelope is ciphertext
   and needs the master key, as does the current one.
-  The AWS SDK and its dependencies are a large package. It is optional, but an
   installation that selects ``aws`` carries it.
-  A secret in AWS makes every read a network call, and AWS bills per secret and
   per API call.
-  Master-key rotation is unavailable while AWS-backed secrets exist.
-  The registry rows are still in the database: names, owners, groups and
   metadata remain visible to anyone who can read it.
-  Assume-role is not supported; supply temporary credentials through the
   session token.

Not verified against real AWS
-----------------------------

The functional suite runs against Moto only. Three things it cannot show:

-  **Resource-scoped IAM.** Moto evaluates a policy's ``Resource`` against ``*``
   for Secrets Manager calls instead of the secret's ARN: a policy scoped to the
   prefix denied every call (measured on 5.2.5). The test policy is therefore
   action-scoped, which proves that the four actions the adapter calls are
   enough and that no other is needed, and says nothing about the ARN pattern on
   the operations page.
-  **Name reuse after a forced delete.** Whether AWS keeps a force-deleted name
   unavailable for a short time was not measured; Moto deletes immediately. A create or a compensating restore inside that
   window is rejected with a request error; it cannot store a wrong value.
-  **Colons in names.** Moto accepts a colon in a secret name and AWS does not.
   The mapping is pinned by unit tests on the name, not by the emulation.

Alternatives considered
=======================

Sign the requests by hand over the PSR-18 client
------------------------------------------------

**Rejected.** It keeps the extension free of the SDK, but Signature Version 4
is exactly the code that is wrong in quiet ways (canonical headers, payload
hash, clock skew, session tokens), the SDK already does it, and the SDK's
transport can be replaced. The cost of the SDK is the package size, which the
decision to make it optional contains.

Make the SDK a requirement
--------------------------

**Rejected** by the repository owner: every installation would carry it for a
feature most do not select.

Use the SDK's default credential chain
--------------------------------------

**Rejected.** It calls the instance metadata service, which the SSRF defence
blocks, and it picks up credentials the operator never meant for nr-vault.

Fail when the setting is read, not on first use
-----------------------------------------------

**Rejected.** The adapter is built whenever the vault service is, so failing
there would make locally stored secrets unreadable on an installation whose SDK
is missing, for a setting that only concerns new secrets.

Move or migrate a row between adapters
--------------------------------------

**Rejected**, as in ADR-053: nothing migrates secrets. The adapters refuse the
foreign row instead of guessing.

Related decisions
=================

-  :ref:`adr-053-hashicorp-storage-adapter` - The design this adapter applies
-  :ref:`adr-002-envelope-encryption` - The envelope that moves to AWS
-  :ref:`adr-026-dns-rebinding-defence` - The transport defences the SDK is routed through
-  :ref:`adr-036-mutation-audit-atomicity` - Why a non-local adapter takes the compensation path
