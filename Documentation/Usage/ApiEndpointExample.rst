.. include:: /Includes.rst.txt

.. _usage-api-endpoint-example:

==================================
Example: API endpoint management
==================================

A common pattern is storing API endpoints with their credentials in a database
table. This example shows how to combine TCA vault fields with the HTTP client.

.. contents:: Table of contents
   :local:
   :depth: 2

.. _example-tca-definition:

Step 1: Define the TCA table
============================

.. literalinclude:: _tca-apiendpoint.php
   :language: php
   :caption: EXT:my_extension/Configuration/TCA/tx_myext_apiendpoint.php
   :lines: 3-

**Creating an API endpoint record (backend):**

1. Go to :guilabel:`List` module and select your storage folder
2. Click :guilabel:`+ Create new record` and select :guilabel:`API Endpoint`
3. Fill in the form:

   - **Name:** ``Stripe``
   - **API Base URL:** ``https://api.stripe.com/v1``
   - **API Token:** Paste your actual API key (stored securely in vault)

4. Click :guilabel:`Save`

The token field uses ``renderType: 'vaultSecret'`` which:

- Shows a masked password field with a reveal button — and a copy button
  outside the hardened profile, which disables copying because the clipboard
  outlives the dialog
- Automatically stores the secret in the vault on save
- Stores only a UUID v7 reference in the database

**What gets stored in the database:**

.. code-block:: sql
   :caption: Database content (token is UUID, not the secret)

   SELECT uid, name, url, token FROM tx_myext_apiendpoint;
   -- | uid | name   | url                       | token                                |
   -- |-----|--------|---------------------------|--------------------------------------|
   -- | 1   | Stripe | https://api.stripe.com/v1 | 01937b6e-4b6c-7abc-8def-0123456789ab |

.. _example-dto:

Step 2: Create a DTO for type safety
====================================

.. literalinclude:: _ApiEndpoint.php
   :language: php
   :caption: EXT:my_extension/Classes/Domain/Dto/ApiEndpoint.php

.. _example-service:

Step 3: Create a service for authenticated requests
====================================================

.. literalinclude:: _ApiClientService.php
   :language: php
   :caption: EXT:my_extension/Classes/Service/ApiClientService.php

.. _example-usage:

Step 4: Use the service
=======================

.. literalinclude:: _ApiClientUsage.php
   :language: php
   :caption: Example controller or command
   :lines: 3-

.. _example-flow:

What happens under the hood
===========================

1. The ``token`` field contains a UUID v7 like ``01937b6e-4b6c-...``
2. :php:`VaultHttpClient::sendRequest()` retrieves the actual token from vault
3. Token is injected into the ``Authorization: Bearer ...`` header
4. :php:`sodium_memzero()` immediately wipes the token from memory
5. The HTTP call is logged to the audit trail (without the secret)

.. _example-security-benefits:

Security benefits
=================

This pattern provides several security advantages:

**No secret exposure**
   Application code never sees the actual API token. The DTO contains only the
   vault UUID, which is useless without vault access.

**Memory safety**
   Secrets are cleared from memory immediately after injection using
   :php:`sodium_memzero()`.

**Audit trail**
   Every HTTP call is logged with the endpoint name, HTTP method, URL, and
   status code - but never the secret itself.

**Separation of concerns**
   Credential management is handled by the vault. Application code focuses on
   business logic.

**No CLI or file access required**
   Editors and admins can manage API endpoints entirely through the TYPO3
   backend. The vault secret field provides a secure password input with
   reveal — and copy, outside the hardened profile — with no command line
   needed.
