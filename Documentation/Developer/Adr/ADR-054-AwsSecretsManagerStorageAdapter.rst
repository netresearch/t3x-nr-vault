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
    identifier exists by now. A failed row update moves ``AWSCURRENT`` back to
    the version it replaced when the store implements
    :php:`AwsVersionedSecretStoreInterface` (the shipped store does) and the
    policy grants ``secretsmanager:UpdateSecretVersionStage``; otherwise it puts
    the previous envelope back as a new version (see below). On delete, AWS is
    emptied first, then the row, so a half-finished delete can be repeated.
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
``PutSecretValue`` return the ``VersionId`` they created, and a rollback applies
only while ``AWSCURRENT`` is still that version.

*   **Only the rollback after a failed row write is conditional on AWS**
    (`#567 <https://github.com/netresearch/t3x-nr-vault/issues/567>`__): an
    update or an adoption whose registry row could not be written, when the
    store implements :php:`AwsVersionedSecretStoreInterface` (the shipped
    :php:`AwsSecretsManagerStore` does) and the policy grants
    ``secretsmanager:UpdateSecretVersionStage``. Before it writes, the adapter
    reads the previous document and its ``VersionId`` from one
    ``GetSecretValue`` response. The rollback is ``UpdateSecretVersionStage``
    with ``VersionStage=AWSCURRENT``, ``MoveToVersionId`` that version and
    ``RemoveFromVersionId`` the version the write created. AWS refuses the move
    when ``AWSCURRENT`` is attached to any other version ("If the label is
    attached and you either do not specify this parameter, or the version ID
    does not match, then the operation fails", ``UpdateSecretVersionStage`` API
    reference), so a writer that lands after our write keeps its value. No new
    version is written: the previous version is current again, and AWS moves
    ``AWSPREVIOUS`` to the version the rollback removed ``AWSCURRENT`` from.
*   **A move that fails writes nothing**, unless it was refused for lack of
    the permission (below), and the rollback counts as applied only when a move
    call itself succeeded. The SDK has already retried a throttled or failed
    request once. AWS does not document the error code of a mismatch, so the
    store reads ``AWSCURRENT`` until it sees our version or the version moved
    back to, at most three times with the delay between reads, and reports one
    of four outcomes (:php:`AwsRestoreOutcome`):

    -   Our version: the move is called once more; it is conditional, so that
        is safe. If that call succeeds, the rollback is applied; if it fails,
        no move was acknowledged and nothing is written. Because reads can
        lag, that does not prove our write is still current (a first move that
        applied and lost its answer also ends here), so the warning asks to
        check the secret.
    -   The version moved back to: unconfirmed. An applied move whose answer
        was lost shows it, and so does a read that lags behind our own write;
        no number of reads tells them apart, so this is never counted as
        applied.
    -   Any other version, or none: another writer won, or the secret is gone.

    The adapter logs one warning per skipped rollback, naming the secret and
    the reason. The row failure is the error the caller sees either way. A read
    of the previous document that names no ``VersionId`` does not fail the
    write: the rollback then uses read-then-write.
*   **On that path the rollback falls back to read-then-write** only when the
    move is refused for lack of the permission, and when the store does not
    implement :php:`AwsVersionedSecretStoreInterface`, as before #567. A
    refusal is ``AccessDeniedException`` (the warning names
    ``secretsmanager:UpdateSecretVersionStage`` and the secret) or a ``403``
    without a readable error code (the warning names the status, not a
    permission). The fallback reads the ``AWSCURRENT`` id and, if it is still
    the write's version, puts the previous document back as a new version. A
    write landing between that read and the put is overwritten.
*   **The compensations of a failed audit write are unchanged by #567.**
    Taking back a create whose audit write failed (``compensateCreate()``) and
    the valueless store that compensates the FormEngine completion path still
    read ``AWSCURRENT`` and then put the previous document back as a new
    version, or delete the secret: a writer that lands between that read and
    the write or delete is overwritten or deleted. The update compensation of
    :php:`VaultService` stores the previous row again
    (``adapter->store($existing)``), which writes the previous envelope as a new
    version without any version check. A rollback that fails in these paths is
    logged as a warning, as before.
*   **A writer between the adapter's read and its write is still discarded.**
    The adapter reads the previous document, then writes. A writer whose
    version lands between the two is displaced by our write, and the rollback
    moves back to the version read before it, not to the writer's version: the
    writer's value is overwritten, as it was before this rollback existed.
    Nothing tells the adapter reliably which version its write displaced. The
    ``PutSecretValue`` response holds only the new ``VersionId`` and its
    stages. A ``GetSecretValue`` of ``AWSPREVIOUS`` right after the put names
    the displaced version, but a read that has not caught up names an older
    one, and a writer after ours moves the label again; ``ListSecretVersionIds``
    needs another permission and has the same lag. This window is a known
    limit, next to the stale read above.
*   **Taking back a create is not conditional.** It reads the ``AWSCURRENT`` id
    and deletes the secret only if it is still the version the create returned.
    AWS has no conditional delete, so a write that lands between the read and
    ``DeleteSecret`` is deleted with the secret. This stays a known limit: a
    delete with a recovery window as a barrier would rely on ``PutSecretValue``
    refusing a secret that is pending deletion, which AWS lists only as a
    possible cause of ``InvalidRequestException``.

In both read-before-act paths the read is retried a few times, so a read that
has not caught up with the write is not mistaken for a concurrent writer, and a
rollback that is skipped is logged as a warning. The conditional restore is
verified against the API reference and a unit-test fake of one secret that
models the labels as documented, not against AWS: moto 5.2.5, which the
functional suite runs against, does not move the default version on a stage
move, and its IAM user there has no ``UpdateSecretVersionStage`` permission, so
the functional suite exercises the fallback. Moto answers that denial with an
XML ``403`` from which the SDK reads no error code; the store falls back to
read-then-write on a ``403`` without a code and logs the status.
A failed audit write is compensated by
:php:`VaultService`: an adapter implementing
:php:`CreateCompensatingAdapterInterface` destroys a secret the call created and
puts back one it adopted, then removes the row. The prefix ``typo3/`` stays the default; a
dedicated prefix keeps the names apart from other users of the account.

A value that this call destroyed is put back with ``CreateSecret``, never with a
write (`#539 <https://github.com/netresearch/t3x-nr-vault/issues/539>`__), after
a delete whose row delete failed and after a store without a value whose row
write failed; that restore never writes into an existing name. The compensation
of a delete whose audit write failed, which :php:`VaultService` runs through the
adapter's ``store()``, reaches the same create and keeps the create-or-adopt
rule of a new secret. AWS deletes a force-deleted secret asynchronously and asks
a caller that creates the same name right after to "use appropriate back off and
retry logic" (``DeleteSecret`` API reference). :php:`AwsSecretsManagerStore`
therefore retries ``CreateSecret`` on ``InvalidRequestException`` after 0.25,
0.5, 1 and 2 seconds: five attempts, at most 3.75 seconds of waiting. Every
other error is reported at once, and no put is ever sent again. A write still
tries its create once. If the name exists again, the restore takes it as another
writer's, does not write into it and logs a warning. Which error AWS returns
while the name is still being deleted is not documented;
``InvalidRequestException`` ("The secret is scheduled for deletion") is assumed.
If AWS answers with another code, the restore fails at the first attempt as
before. The cost of the back-off: a create that meets a name another party
scheduled for deletion with a recovery window waits about 3.75 seconds before it
fails as before.

The first restores in production settle the assumption. What each log line
means:

* Notice "CreateSecret succeeded after N InvalidRequestException answer(s)":
  the assumption holds, and the window lasted less than the back-off.
* Warning "restoring an AWS Secrets Manager write failed" naming
  ``InvalidRequestException``: the code is right, but the deletion took longer
  than about 3.75 seconds.
* Warning "was not put back, because a secret of that name exists" right after
  nr-vault's own delete: either another writer created the name, or AWS answers
  the deletion window with ``ResourceExistsException``. ``DescribeSecret``
  on the name tells them apart (a ``DeletedDate`` means AWS was still
  deleting).
* On the audit-failure path, :php:`VaultService` logs "the compensating
  rollback also failed" when the restore failed.

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

The functional suite runs against Moto only. Four things it cannot show:

-  **Resource-scoped IAM.** Moto evaluates a policy's ``Resource`` against ``*``
   for Secrets Manager calls instead of the secret's ARN: a policy scoped to the
   prefix denied every call (measured on 5.2.5). The test policy is therefore
   action-scoped. It holds the four actions every operation needs, which proves
   that no other is needed; the fifth, ``UpdateSecretVersionStage``, is left out
   on purpose, so the suite runs the rollback's fallback instead of Moto's stage
   handling. It says nothing about the ARN pattern on the operations page.
-  **Name reuse after a forced delete.** AWS deletes a force-deleted secret
   asynchronously. How long the name stays unavailable, and which error a
   ``CreateSecret`` gets meanwhile, were not measured; Moto deletes
   immediately. The create back-off assumes ``InvalidRequestException`` and
   waits at most 3.75 seconds. A deletion that takes longer, or another error
   code, makes a compensating restore fail as before, with a warning; it cannot
   store a wrong value.
-  **Colons in names.** Moto accepts a colon in a secret name and AWS does not.
   The mapping is pinned by unit tests on the name, not by the emulation.
-  **The conditional stage move.** Moto 5.2.5 does not move the default version
   on ``UpdateSecretVersionStage``, so the rollback's move is tested against a
   unit-test fake that follows the API reference. Two error codes were not
   measured: the one AWS returns when ``RemoveFromVersionId`` does not match
   (Moto: ``InvalidParameterException``), and the one for a missing
   ``UpdateSecretVersionStage`` permission (``AccessDeniedException`` is
   assumed; Moto answers an XML ``403`` without a readable code, which is
   treated the same). The first does not decide the outcome, because the store
   reads ``AWSCURRENT`` after any failed move. The second does: if AWS denies
   with another code, the move counts as failed at our version, so the
   rollback is skipped and nothing is written, instead of falling back to
   read-then-write.

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
