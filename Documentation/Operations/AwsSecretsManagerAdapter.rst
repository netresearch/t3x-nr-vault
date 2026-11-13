.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _operations-aws-adapter:

================================
AWS Secrets Manager storage
================================

With ``storageAdapter = aws`` the encryption envelope of every new secret lives
in AWS Secrets Manager instead of in the TYPO3 database. The decision and its
trade-offs are in :ref:`adr-054-aws-secrets-manager-storage-adapter`.

.. contents:: Table of contents
   :local:
   :depth: 2

.. _operations-aws-adapter-model:

What lives where
================

..  list-table::
    :header-rows: 1
    :widths: 30 35 35

    *   -   Data
        -   TYPO3 database
        -   AWS Secrets Manager

    *   -   Identifier, description, context, metadata
        -   yes
        -   no

    *   -   Owner, group tiers, expiry, counters, availability
        -   yes
        -   no

    *   -   Pointer to the AWS secret (``external_reference``, written
            :samp:`{region}:{name}`)
        -   yes
        -   no

    *   -   Encrypted value, wrapped data key, nonces, checksum
        -   no (columns are empty)
        -   yes

    *   -   Master key
        -   no
        -   no (see :ref:`operations-key-custody`)

The value is encrypted by nr-vault before it is sent. AWS stores ciphertext it
cannot read, and the master key never reaches AWS.

Existing secrets are not migrated. A secret stored locally stays local and keeps
working after you switch; only new secrets go to AWS. Roll back by switching the
setting back: secrets already in AWS become unreadable until you switch to
``aws`` again, so do not remove them from AWS. A secret stored in HashiCorp Vault
is not usable under ``aws`` and the other way round; nr-vault refuses it with a
message naming the adapter that owns it.

.. _operations-aws-adapter-sdk:

Install the AWS SDK
===================

The SDK is optional. It is not installed with nr-vault; add it where you select
``aws``:

.. code-block:: bash

   composer require aws/aws-sdk-php

Without it, the first operation that needs AWS fails with a configuration error
that names this command. It never falls back to local storage, and secrets that
are stored locally stay readable.

.. _operations-aws-adapter-iam:

Prepare IAM
===========

Give the adapter its own IAM user or role with only the actions it calls. Every
secret is named :samp:`{prefix}/{identifier}`, with ``typo3/`` as the default
prefix:

.. code-block:: json
   :caption: IAM policy for the adapter

   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "secretsmanager:CreateSecret",
         "Resource": "*"
       },
       {
         "Effect": "Allow",
         "Action": [
           "secretsmanager:PutSecretValue",
           "secretsmanager:GetSecretValue",
           "secretsmanager:DeleteSecret"
         ],
         "Resource": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:typo3/*"
       }
     ]
   }

``CreateSecret`` acts on a secret that does not exist yet, so AWS cannot scope it
to the prefix by ARN; look for a condition on the secret name if you need to
narrow it. The adapter calls no other action: it does not list, describe, tag or
rotate secrets. That the four actions are enough is tested; the ARN pattern is
not, because the emulation the tests run against does not evaluate it (see
:ref:`adr-054-aws-secrets-manager-storage-adapter`).

.. _operations-aws-adapter-credentials:

Provide credentials
===================

Credentials are explicit. nr-vault never uses the SDK's default credential
chain: no environment variable named ``AWS_*``, no :file:`~/.aws` file, no
instance metadata service. It reads three variables of its own, whose names are
configurable:

``NR_VAULT_AWS_ACCESS_KEY_ID``
   The access key id. May instead be stored in ``aws.accessKeyId``; it is an
   identifier, not a secret.

``NR_VAULT_AWS_SECRET_ACCESS_KEY``
   The secret access key. Read from the environment only; there is no setting
   that stores it.

``NR_VAULT_AWS_SESSION_TOKEN``
   Optional. Set it when the credentials are temporary, for example from a
   role your deployment assumes outside PHP. nr-vault does not assume roles
   itself.

Export them to the PHP process (the web server's pool or the CLI user), and name
other variables with ``aws.accessKeyIdEnvVar``, ``aws.secretAccessKeyEnvVar`` and
``aws.sessionTokenEnvVar`` if you must. The defaults are not the SDK's, so
credentials that belong to something else on the host are not used by accident.

.. _operations-aws-adapter-config:

Configure TYPO3
===============

.. code-block:: php
   :caption: config/system/additional.php

   $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['storageAdapter'] = 'aws';
   $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['aws'] = [
       'region'       => 'eu-central-1',
       'secretPrefix' => 'typo3/',
   ];

Every setting is described under :ref:`configuration-aws`. The adapter reads its
configuration on each request; nothing is cached across requests.

The secret name is the prefix, a slash and the identifier. AWS does not accept a
colon in a name, so a ``:`` in an identifier (the ``site:<namespace>:<name>``
form) is written as ``+``. Changing ``aws.secretPrefix`` or ``aws.region``
changes where the adapter looks, see below.

.. _operations-aws-adapter-network:

Network and TLS
===============

*   Without ``aws.endpoint`` the adapter talks to the regional AWS endpoint over
    https.
*   A custom ``aws.endpoint`` (a VPC endpoint, a compatible service) must be a
    bare origin: no credentials, path, query or fragment. It must use ``https``
    unless ``aws.allowInsecureHttp`` is set, which is for local development: the
    signed requests and every envelope would cross the network unencrypted.
*   ``AWS_ENDPOINT_URL`` and ``AWS_ENDPOINT_URL_SECRETS_MANAGER`` are ignored.
*   Requests use the same client as every other outbound call of the extension.
    It refuses loopback, private, link-local and metadata addresses, follows no
    redirects and logs no requests. An endpoint on a private network, such as a
    VPC endpoint, therefore needs a literal entry (a wildcard does not count) in
    :php:`$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']`:

    .. code-block:: php
       :caption: config/system/additional.php

       $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'][] = 'secretsmanager.vpce.example.com';

*   A whole transfer is bounded to ten seconds, and a failed request is retried
    once.

.. _operations-aws-adapter-behaviour:

Behaviour you should know
=========================

Failure
   An AWS outage or rejected credentials make the secrets stored in AWS
   unreadable and new secrets unwritable; secrets stored locally are unaffected.
   On store, AWS is written first: a failure leaves no row behind.

Half-finished writes
   A crash between the AWS write and the row write leaves an unreferenced secret
   in AWS, which the next store of that identifier overwrites. A row whose AWS
   secret is missing is reported as an error when the value is read (code
   ``1794500009``), never returned as an empty secret. ``vault:delete`` and
   ``vault:rotate`` still reach the row, so you can remove it or write a new
   value.

Delete
   Deleting removes the AWS secret with ``ForceDeleteWithoutRecovery``, so there
   is no recovery window and no version survives, then the row. Run
   ``vault:delete`` again after an interrupted delete. The flip side: nothing is
   left in AWS to recover a deleted secret from.

Versions
   Every rotation adds a version in AWS. The previous one stays staged as
   ``AWSPREVIOUS`` until the secret is deleted. It is ciphertext and needs the
   master key, like the current one.

Master-key rotation
   ``vault:rotate-master-key`` refuses while any secret is stored outside the
   local database. It names the first one it meets and changes nothing. Data
   keys held in AWS are not re-wrapped by this release.

Audit
   Every operation is written to the nr-vault audit log, and when the audit
   write fails the previous state is restored. Unlike local secrets, the AWS
   write and the database write are not one transaction: a crash after the AWS
   write and before the audit write persists the change without an audit entry.
   CloudTrail records every call to Secrets Manager, so compare writes and
   deletes there with the nr-vault audit log.

Changing ``aws.region`` or ``aws.secretPrefix``
   The secret of a row is looked up under the current setting. Existing
   AWS-backed secrets are not found under a new region or prefix: move them in
   AWS first (or keep the old values) before you change either.

Another external adapter
   A row bound to ``hashicorp`` is refused under ``aws``, and the other way
   round. Store, read and delete all fail with a message naming the adapter that
   owns the row; list and the backend module still show it.

Backup
   The database no longer contains the envelopes. A restore needs the database
   dump, the master key and the Secrets Manager secrets; back all three up, and
   keep them apart (:ref:`operations-backup-and-restore`).

.. _operations-aws-adapter-troubleshooting:

Troubleshooting
===============

..  list-table::
    :header-rows: 1
    :widths: 40 60

    *   -   Message
        -   Likely cause

    *   -   ``the AWS SDK for PHP is not installed``
        -   Run ``composer require aws/aws-sdk-php`` in the project that
            selects ``aws``.

    *   -   ``aws.region is empty`` or ``is not an AWS region name``
        -   Set ``aws.region`` to a region such as ``eu-central-1``.

    *   -   ``AWS credential is missing``
        -   The environment variable named in the message is not visible to the
            PHP process. The SDK's own ``AWS_*`` variables are not read.

    *   -   ``endpoint must use https``
        -   The endpoint is ``http``. Use https, or set
            ``aws.allowInsecureHttp`` on a development machine.

    *   -   ``could not be sent`` with a blocked-host message
        -   The endpoint is private or loopback and not listed in
            ``allowed_hosts``.

    *   -   ``was rejected with HTTP 403``
        -   The key is unknown or revoked, the secret access key is wrong, the
            session token expired, or the policy does not allow the action.
            With the AWS error code in brackets (for example
            ``AccessDeniedException``) the cause is in your IAM policy.

    *   -   ``was rejected with HTTP 400 (ResourceExistsException)`` or
            ``(InvalidRequestException)``
        -   The name is taken, or the secret is scheduled for deletion by
            something other than nr-vault. nr-vault always deletes without a
            recovery window.

    *   -   ``holds no value for it``
        -   The AWS secret was deleted outside nr-vault, or the region or
            prefix changed. Restore the secret, or write a new value with
            ``vault:rotate``.

    *   -   ``is stored in the "hashicorp" adapter``
        -   The row belongs to the other external adapter. Select that adapter
            again to work with it.
