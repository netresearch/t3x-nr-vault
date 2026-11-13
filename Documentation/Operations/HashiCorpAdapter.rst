.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _operations-hashicorp-adapter:

===========================
HashiCorp Vault storage
===========================

With ``storageAdapter = hashicorp`` the encryption envelope of every new secret
lives in HashiCorp Vault (KV version 2) instead of in the TYPO3 database. The
decision and its trade-offs are in :ref:`adr-053-hashicorp-storage-adapter`.

.. contents:: Table of contents
   :local:
   :depth: 2

.. _operations-hashicorp-adapter-model:

What lives where
================

..  list-table::
    :header-rows: 1
    :widths: 30 35 35

    *   -   Data
        -   TYPO3 database
        -   Vault KV v2

    *   -   Identifier, description, context, metadata
        -   yes
        -   no

    *   -   Owner, group tiers, expiry, counters, availability
        -   yes
        -   no

    *   -   Pointer to the Vault key (``external_reference``)
        -   yes
        -   no

    *   -   Encrypted value, wrapped data key, nonces, checksum
        -   no (columns are empty)
        -   yes

    *   -   Master key
        -   no
        -   no (see :ref:`operations-key-custody`)

The value is encrypted by nr-vault before it is sent. Vault stores ciphertext it
cannot read; the master key never reaches Vault, except wrapped, with the
``transit`` provider.

Existing secrets are not migrated. A secret stored locally stays local and keeps
working after you switch; only new secrets go to Vault. Roll back by switching
the setting back: secrets already in Vault become unreadable until you switch to
``hashicorp`` again, so do not remove them from Vault.

.. _operations-hashicorp-adapter-vault:

Prepare Vault
=============

The adapter needs a KV v2 mount (development servers mount one at ``secret/``)
and a policy that is limited to the extension's prefix:

.. code-block:: text
   :caption: Policy typo3

   path "secret/data/typo3/*"     { capabilities = ["create", "read", "update"] }
   path "secret/metadata/typo3/*" { capabilities = ["read", "delete"] }

.. code-block:: bash

   vault policy write typo3 typo3-policy.hcl

``hashicorp.path`` is written as :samp:`{mount}/data/{prefix}`, so the policy
above matches the default ``secret/data/typo3``. A nested mount such as
:samp:`team/kv/data/typo3` is supported: the first path segment named ``data``
separates the mount from the prefix.

.. _operations-hashicorp-adapter-auth:

Choose an authentication method
===============================

Set the method in ``hashicorp.authMethod``. The storage adapter implements all
three. The ``transit`` master key provider still implements ``token`` only.

Token
-----

.. code-block:: bash

   vault token create -policy=typo3 -period=24h

Export the token to the PHP process as ``VAULT_TOKEN`` (or the name set in
``hashicorp.tokenEnvVar``). A token stored in ``hashicorp.token`` also works but
is readable in the Install Tool and lands in configuration exports. A token has
no fallback: when it expires or is revoked, requests fail until you replace it.
Use a periodic token that something renews.

AppRole
-------

.. code-block:: bash

   vault auth enable approle
   vault write auth/approle/role/typo3 token_policies=typo3 token_ttl=1h
   vault read auth/approle/role/typo3/role-id
   vault write -f auth/approle/role/typo3/secret-id

Put the role id in ``hashicorp.roleId``. Export the secret id as
``VAULT_SECRET_ID`` (or the name in ``hashicorp.secretIdEnvVar``). The secret id
is read from the environment only; there is no setting that stores it. The login
token lives for the request or CLI run, is refreshed before its lease ends, and
is replaced once by a new login if Vault rejects it with 403.

Kubernetes
----------

.. code-block:: bash

   vault auth enable kubernetes
   vault write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc
   vault write auth/kubernetes/role/typo3 \
       bound_service_account_names=typo3 \
       bound_service_account_namespaces=web \
       token_policies=typo3 token_ttl=1h

Set ``hashicorp.kubernetesRole`` to ``typo3``. The adapter reads the pod's
service account token from ``hashicorp.kubernetesJwtPath`` (default
:file:`/var/run/secrets/kubernetes.io/serviceaccount/token`) on every login.

.. _operations-hashicorp-adapter-config:

Configure TYPO3
===============

.. code-block:: php
   :caption: config/system/additional.php

   $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['storageAdapter'] = 'hashicorp';
   $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['hashicorp'] = [
       'address'    => 'https://vault.example.com:8200',
       'path'       => 'secret/data/typo3',
       'authMethod' => 'approle',
       'roleId'     => 'b2c1…',
   ];

Every setting is described under :ref:`configuration-extension`. The adapter
reads its configuration on each request; nothing is cached across requests.

.. _operations-hashicorp-adapter-network:

Network and TLS
===============

*   The address must use ``https``. ``hashicorp.allowInsecureHttp`` allows
    ``http`` for local development; with it on, the token and every envelope
    cross the network unencrypted.
*   The address must be a bare origin: no credentials, path, query or fragment.
*   Requests use the same client as every other outbound call of the extension.
    It refuses loopback, private, link-local and metadata addresses, follows no
    redirects and logs no requests. A Vault on a private network therefore needs
    a literal entry (a wildcard does not count) in
    :php:`$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']`:

    .. code-block:: php
       :caption: config/system/additional.php

       $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'][] = 'vault.internal.example.com';

*   A whole transfer is bounded to ten seconds.

.. _operations-hashicorp-adapter-behaviour:

Behaviour you should know
=========================

Failure
   A Vault outage or a rejected token makes the secrets stored in Vault
   unreadable and new secrets unwritable; secrets stored locally are unaffected.
   On store, Vault is written first: a failure leaves no row behind.

Half-finished writes
   A crash between the Vault write and the row write leaves an unreferenced key
   in Vault, which the next store of that identifier overwrites. A row whose
   Vault key is missing is reported as an error when the value is read (code
   ``1794400009``), never returned as an empty secret. ``vault:delete`` and
   ``vault:rotate`` still reach the row, so you can remove it or write a new
   value.

Delete
   Deleting removes the Vault key with all of its versions, then the row. Run
   ``vault:delete`` again after an interrupted delete.

Master-key rotation
   ``vault:rotate-master-key`` refuses while any secret is stored outside the
   local database. It names the first one it meets and changes nothing. Data
   keys held in Vault are not re-wrapped by this release.

Audit
   Every operation is written to the nr-vault audit log, and when the audit
   write fails the previous state is restored. Unlike local secrets, the Vault
   write and the database write are not one transaction: a crash after the
   Vault write and before the audit write persists the change without an audit
   entry. Vault's own audit device records every access to the KV paths, so
   monitor it for writes and deletes that have no matching nr-vault entry.

Changing ``hashicorp.path``
   The Vault key of a secret is derived from the current setting. Existing
   Vault-backed secrets are not found under a new path, so move the keys in
   Vault first (or keep the old path) before you change it.

Backup
   The database no longer contains the envelopes. A restore needs the database
   dump, the master key and a Vault that still holds the KV data; back all three
   up, and keep them apart (:ref:`operations-backup-and-restore`).

.. _operations-hashicorp-adapter-troubleshooting:

Troubleshooting
===============

..  list-table::
    :header-rows: 1
    :widths: 40 60

    *   -   Message
        -   Likely cause

    *   -   ``address must use https``
        -   The address is ``http``. Use https, or set
            ``hashicorp.allowInsecureHttp`` on a development machine.

    *   -   ``could not be sent`` with a blocked-host message
        -   The address is private or loopback and not listed in
            ``allowed_hosts``.

    *   -   ``was rejected with HTTP 403``
        -   The token or the policy does not allow the path. Compare the policy
            with ``hashicorp.path``. Under ``token`` there is no retry.

    *   -   ``login was rejected``
        -   Wrong role id, spent secret id, or a Kubernetes role that does not
            bind the pod's service account.

    *   -   ``login credential is missing``
        -   The environment variable or service account file named in the
            message is not visible to the PHP process.

    *   -   ``holds no value for it``
        -   The Vault key was deleted outside nr-vault, or the row points at
            another Vault. Restore the key from a Vault snapshot.
