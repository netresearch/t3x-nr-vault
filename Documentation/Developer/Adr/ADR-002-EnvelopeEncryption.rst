.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-002-envelope-encryption:

================================
ADR-002: Envelope encryption
================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-01-03

Context
=======

The nr-vault extension needs to encrypt secrets at rest in the database.
The encryption approach must:

-  Protect secrets even if the database is compromised
-  Allow efficient key rotation without re-encrypting all secret values
-  Use well-audited, modern cryptographic primitives
-  Integrate with PHP's native cryptography libraries

Problem statement
=================

How should secrets be encrypted to provide strong security while enabling
efficient operations like key rotation?

Decision drivers
================

-  **Security**: Must use authenticated encryption (AEAD)
-  **Key rotation**: Master key changes should not require re-encrypting values
-  **Performance**: Encryption/decryption must be fast
-  **Simplicity**: Use PHP's built-in libsodium, no external dependencies
-  **Memory safety**: Sensitive data must be cleared from memory

Considered options
==================

Option 1: Direct encryption with master key
-------------------------------------------

Encrypt each secret directly with the master key.

**Pros:**

-  Simple implementation
-  Single key to manage

**Cons:**

-  Master key rotation requires re-encrypting ALL secrets
-  Same key used for all secrets (higher exposure risk)

Option 2: Envelope encryption (DEK/KEK)
---------------------------------------

Two-layer encryption: unique Data Encryption Key (DEK) per secret,
encrypted with Master Key (KEK).

**Pros:**

-  Master key rotation only re-encrypts DEKs (fast)
-  Each secret has unique encryption key
-  Industry-standard pattern (AWS KMS, Google Cloud KMS)

**Cons:**

-  Slightly more complex implementation
-  More data to store (encrypted DEK + nonces)

Decision
========

We chose **envelope encryption** with AES-256-GCM (primary) or
XChaCha20-Poly1305 (fallback) because:

1. **Efficient key rotation**: Only DEKs need re-encryption, not secret values
2. **Defense in depth**: Unique key per secret limits blast radius
3. **Industry standard**: Proven pattern used by major cloud providers
4. **Modern algorithms**: Both are AEAD with strong security properties

Implementation
==============

Encryption flow
---------------

.. code-block:: text
   :caption: Envelope encryption process

   1. Generate unique DEK (32 bytes) for the secret
   2. Generate two random nonces (12 or 24 bytes each)
   3. Encrypt DEK with master key: encryptedDek = AEAD(DEK, masterKey, dekNonce)
   4. Encrypt secret with DEK: encryptedValue = AEAD(secret, DEK, valueNonce)
   5. Calculate SHA-256 checksum for change detection
   6. Clear sensitive data from memory (sodium_memzero)
   7. Store: encryptedValue, encryptedDek, dekNonce, valueNonce, checksum

Decryption flow
---------------

.. code-block:: text
   :caption: Envelope decryption process

   1. Retrieve master key from provider
   2. Decrypt DEK: DEK = AEAD_decrypt(encryptedDek, masterKey, dekNonce)
   3. Decrypt secret: secret = AEAD_decrypt(encryptedValue, DEK, valueNonce)
   4. Clear DEK and master key from memory
   5. Return plaintext secret

Algorithm selection
-------------------

.. code-block:: php
   :caption: Classes/Crypto/EncryptionService.php

   private function useAes256Gcm(): bool
   {
       // Use AES-256-GCM if hardware acceleration available
       // Otherwise fall back to XChaCha20-Poly1305
       if (!sodium_crypto_aead_aes256gcm_is_available()) {
           return false;
       }

       return !$this->configuration->preferXChaCha20();
   }

   private function getNonceLength(): int
   {
       return $this->useAes256Gcm()
           ? SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES      // 12 bytes
           : SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;  // 24 bytes
   }

Memory safety
-------------

.. code-block:: php
   :caption: Secure memory handling

   try {
       $dek = $this->generateDek();
       $encryptedValue = $this->encryptWithKey($plaintext, $dek, $valueNonce);
       // ... store encrypted data
   } finally {
       sodium_memzero($dek);
       sodium_memzero($masterKey);
       sodium_memzero($plaintext);
   }

Master key rotation
-------------------

With envelope encryption, rotating the master key is efficient:

.. code-block:: php
   :caption: Re-encrypting DEKs only

   public function reEncryptDek(
       string $encryptedDek,
       string $dekNonce,
       string $identifier,
       string $oldMasterKey,
       string $newMasterKey,
   ): array {
       // Decrypt DEK with old master key
       $dek = $this->decryptDek($encryptedDek, $dekNonce, $identifier, $oldMasterKey);

       // Re-encrypt DEK with new master key
       $newNonce = random_bytes($this->getNonceLength());
       $newEncryptedDek = $this->encryptWithKey($dek, $newMasterKey, $newNonce);

       sodium_memzero($dek);
       return ['encrypted_dek' => $newEncryptedDek, 'dek_nonce' => $newNonce];
   }

Database storage
----------------

.. code-block:: sql
   :caption: Encrypted data columns

   encrypted_value mediumblob,           -- AEAD ciphertext + auth tag
   encrypted_dek text,                   -- Base64-encoded encrypted DEK
   dek_nonce varchar(24) NOT NULL,       -- Base64-encoded DEK nonce
   value_nonce varchar(24) NOT NULL,     -- Base64-encoded value nonce
   encryption_version int unsigned,      -- For algorithm migrations
   value_checksum char(64) NOT NULL,     -- SHA-256 for change detection

Consequences
============

Positive
--------

-  **Fast key rotation**: Only DEKs re-encrypted, O(n) simple operations
-  **Unique keys per secret**: Compromise of one DEK doesn't expose others
-  **Hardware acceleration**: AES-256-GCM uses AES-NI when available
-  **Authenticated encryption**: Tampering is detected and rejected
-  **Memory safety**: Sensitive data cleared immediately after use

Negative
--------

-  **More storage**: Each secret requires DEK + two nonces
-  **Complexity**: Two-layer encryption requires careful implementation
-  **Algorithm migration**: Changing algorithms requires re-encryption

Risks
-----

-  Master key loss = all secrets unrecoverable (mitigate with secure backups)
-  Memory-based attacks could capture keys during brief window of use

References
==========

-  `libsodium documentation <https://doc.libsodium.org/>`_
-  `AWS KMS Envelope Encryption <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping>`_
-  `NIST SP 800-38D (GCM) <https://csrc.nist.gov/publications/detail/sp/800-38d/final>`_
