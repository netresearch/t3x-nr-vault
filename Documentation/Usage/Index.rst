.. include:: /Includes.rst.txt

.. _usage:

=====
Usage
=====

.. _usage-backend-module:

Backend module
==============

Access the vault through the TYPO3 backend:

1. Go to :guilabel:`Admin Tools > Vault`.
2. The overview shows statistics and quick-start examples.
3. Navigate to :guilabel:`Secrets` to manage your secrets.

.. figure:: /Images/VaultOverview.png
   :alt: Vault module overview showing statistics and quick start guide
   :class: with-shadow

   The vault overview displays key metrics and provides quick-start code examples

.. _usage-creating-secrets:

Creating secrets
----------------

1. Click :guilabel:`Create Secret` (+ button).
2. Fill in the form:

   Identifier
      Unique identifier for the secret (e.g., ``stripe_api_key``).

   Value
      The secret value to encrypt.

   Description
      Optional description for documentation.

   Context
      Optional context for organization (e.g., ``payment``).

   Allowed groups
      Backend user groups that can access this secret.

   Expiration
      Optional expiration date after which the secret becomes inaccessible.

3. Click :guilabel:`Save`.

.. _usage-viewing-secrets:

Viewing and editing secrets
---------------------------

Secrets are displayed with their metadata but not their values.
Click :guilabel:`Reveal` to temporarily show a secret value.

.. note::

   Revealing a secret creates an audit log entry.

.. figure:: /Images/SecretsList.png
   :alt: Secrets list view showing secret identifiers, contexts, and metadata
   :class: with-shadow

   The secrets list provides filtering, bulk actions, and quick access to secret operations

.. _usage-site-configuration:

Site configuration
==================

Reference secrets in your site configuration files using the
:yaml:`%vault(identifier)%` syntax:

.. code-block:: yaml
   :caption: config/sites/mysite/config.yaml

   settings:
     payment:
       stripePublicKey: 'pk_live_...'
       stripeSecretKey: '%vault(stripe_secret_key)%'
     email:
       mailchimpApiKey: '%vault(mailchimp_api_key)%'
       sendgridToken: '%vault(sendgrid_token)%'

Secrets are resolved at runtime when the site configuration is loaded.
This keeps sensitive values out of your version control while still
allowing you to configure them through the familiar site settings.

.. important::

   Site configuration secrets are resolved on every request. Ensure
   your vault storage is performant (the default local adapter caches
   lookups).

.. _usage-typoscript:

TypoScript integration
======================

Use vault references in TypoScript for frontend-accessible secrets:

.. code-block:: typoscript
   :caption: TypoScript vault reference

   lib.googleMapsKey = TEXT
   lib.googleMapsKey.value = %vault(google_maps_api_key)%

   page.headerData.10 = TEXT
   page.headerData.10.value = <script>var API_KEY = '%vault(public_api_key)%';</script>

.. warning::

   **Security considerations:**

   -  Only secrets marked as ``frontend_accessible`` can be resolved.
   -  Resolved values may be cached - use ``cache.disable = 1`` for
      secrets that should not be cached.
   -  Consider using ``USER_INT`` for content containing secrets.

Example with caching disabled:

.. code-block:: typoscript
   :caption: Disable caching for secrets

   lib.apiKey = TEXT
   lib.apiKey {
     value = %vault(my_api_key)%
     stdWrap.cache.disable = 1
   }

.. _usage-cli-commands:

CLI commands
============

.. _usage-cli-vault-init:

vault:init
----------

Initialize the vault and generate a master key:

.. code-block:: bash
   :caption: Initialize vault

   vendor/bin/typo3 vault:init

   # Output as environment variable format
   vendor/bin/typo3 vault:init --env

   # Specify custom output location
   vendor/bin/typo3 vault:init --output=/secure/path/vault.key

.. _usage-cli-vault-store:

vault:store
-----------

Create or update a secret:

.. code-block:: bash
   :caption: Store a secret

   # Interactive (prompts for value)
   vendor/bin/typo3 vault:store stripe_api_key

   # With options (arbitrary metadata via repeatable --metadata key=value)
   vendor/bin/typo3 vault:store payment_key \
     --value="sk_live_..." \
     --metadata="description=Stripe production key" \
     --metadata="context=payment" \
     --groups="1,2"

.. _usage-cli-vault-retrieve:

vault:retrieve
--------------

Retrieve a secret value:

.. code-block:: bash
   :caption: Retrieve a secret

   vendor/bin/typo3 vault:retrieve stripe_api_key

   # Quiet mode for scripting
   API_KEY=$(vendor/bin/typo3 vault:retrieve -q stripe_api_key)

.. _usage-cli-vault-list:

vault:list
----------

List all accessible secrets:

.. code-block:: bash
   :caption: List secrets

   vendor/bin/typo3 vault:list

   # Filter by pattern
   vendor/bin/typo3 vault:list --pattern="payment_*"

   # JSON output for automation
   vendor/bin/typo3 vault:list --format=json

.. _usage-cli-vault-rotate:

vault:rotate
------------

Rotate a secret with a new value:

.. code-block:: bash
   :caption: Rotate a secret

   vendor/bin/typo3 vault:rotate stripe_api_key \
     --reason="Scheduled quarterly rotation"

.. _usage-cli-vault-delete:

vault:delete
------------

Delete a secret:

.. code-block:: bash
   :caption: Delete a secret

   vendor/bin/typo3 vault:delete old_api_key \
     --reason="Service deprecated" \
     --force

.. _usage-cli-vault-audit:

vault:audit
-----------

View the audit log:

.. code-block:: bash
   :caption: View audit log

   # View entries since a given date
   vendor/bin/typo3 vault:audit --since=2026-05-01

   # Filter by secret
   vendor/bin/typo3 vault:audit --identifier=stripe_api_key

   # Export to JSON
   vendor/bin/typo3 vault:audit --format=json > audit.json

.. figure:: /Images/AuditLog.png
   :alt: Audit log showing secret access history with timestamps, actors, and IP addresses
   :class: with-shadow

   The audit log tracks all secret operations with tamper-evident hash chains

.. _usage-cli-vault-rotate-master-key:

vault:rotate-master-key
-----------------------

Rotate the master encryption key (re-encrypts all DEKs):

.. code-block:: bash
   :caption: Rotate master key

   # Using old key from file, new key from current config
   vendor/bin/typo3 vault:rotate-master-key \
     --old-key=/path/to/old.key \
     --confirm

   # Dry run to simulate
   vendor/bin/typo3 vault:rotate-master-key \
     --old-key=/path/to/old.key \
     --dry-run

.. _usage-cli-vault-scan:

vault:scan
----------

Scan for potential plaintext secrets in database:

.. code-block:: bash
   :caption: Scan for plaintext secrets

   vendor/bin/typo3 vault:scan

   # Only critical issues
   vendor/bin/typo3 vault:scan --severity=critical

   # JSON for CI/CD
   vendor/bin/typo3 vault:scan --format=json

.. _usage-cli-vault-migrate-field:

vault:migrate-field
-------------------

Migrate existing plaintext field values to vault:

.. code-block:: bash
   :caption: Migrate field to vault

   # Preview
   vendor/bin/typo3 vault:migrate-field tx_myext_settings api_key --dry-run

   # Execute
   vendor/bin/typo3 vault:migrate-field tx_myext_settings api_key

.. _usage-cli-vault-cleanup-orphans:

vault:cleanup-orphans
---------------------

Remove orphaned secrets from deleted records:

.. code-block:: bash
   :caption: Clean up orphaned secrets

   vendor/bin/typo3 vault:cleanup-orphans --dry-run
   vendor/bin/typo3 vault:cleanup-orphans --retention-days=30

.. _usage-php-api:

PHP API
=======

.. _usage-php-vault-service:

VaultService
------------

Inject the VaultService to access secrets programmatically:

.. code-block:: php
   :caption: Inject and use VaultService

   use Netresearch\NrVault\Service\VaultServiceInterface;

   final class PaymentService
   {
       public function __construct(
           private readonly VaultServiceInterface $vaultService,
       ) {}

       public function getApiKey(): ?string
       {
           return $this->vaultService->retrieve('stripe_api_key');
       }
   }

.. _usage-php-storing-secrets:

Storing secrets
~~~~~~~~~~~~~~~

.. code-block:: php
   :caption: Store secret with options

   $this->vaultService->store(
       identifier: 'payment_api_key',
       secret: 'sk_live_...',
       options: [
           'description' => 'Stripe production API key',
           'context' => 'payment',
           'groups' => [1, 2], // Backend user group UIDs
           'expiresAt' => time() + (86400 * 90), // 90 days
       ],
   );

.. _usage-php-checking-existence:

Checking existence
~~~~~~~~~~~~~~~~~~

.. code-block:: php
   :caption: Check if secret exists

   if ($this->vaultService->exists('stripe_api_key')) {
       $value = $this->vaultService->retrieve('stripe_api_key');
   }

.. _usage-php-listing-secrets:

Listing secrets
~~~~~~~~~~~~~~~

.. code-block:: php
   :caption: List secrets programmatically

   // Get all accessible secrets
   $secrets = $this->vaultService->list();

   // Filter by pattern
   $paymentSecrets = $this->vaultService->list(pattern: 'payment_*');

.. _usage-php-http-client:

Vault HTTP client
-----------------

Make authenticated API calls without exposing secrets to your code.
The HTTP client is PSR-18 compatible. Configure authentication with
:php:`withAuthentication()`, then use standard :php:`sendRequest()`.

Inject :php:`VaultHttpClientInterface` directly:

.. code-block:: php
   :caption: HTTP client with vault authentication

   use GuzzleHttp\Psr7\Request;
   use Netresearch\NrVault\Http\SecretPlacement;
   use Netresearch\NrVault\Http\VaultHttpClientInterface;

   final class ExternalApiService
   {
       public function __construct(
           private readonly VaultHttpClientInterface $httpClient,
       ) {}

       public function fetchData(): array
       {
           // Configure authentication, then use PSR-18
           $client = $this->httpClient->withAuthentication(
               'api_token',
               SecretPlacement::Bearer,
           );

           $request = new Request('GET', 'https://api.example.com/data');
           $response = $client->sendRequest($request);

           return json_decode($response->getBody()->getContents(), true);
       }
   }

Or access via VaultService:

.. code-block:: php
   :caption: HTTP client via VaultService

   use GuzzleHttp\Psr7\Request;
   use Netresearch\NrVault\Http\SecretPlacement;

   $client = $this->vaultService->http()
       ->withAuthentication('stripe_api_key', SecretPlacement::Bearer);

   $request = new Request(
       'POST',
       'https://api.stripe.com/v1/charges',
       ['Content-Type' => 'application/json'],
       json_encode($payload),
   );

   $response = $client->sendRequest($request);

.. _usage-php-authentication-options:

Authentication options
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: php
   :caption: Authentication placement examples

   use GuzzleHttp\Psr7\Request;
   use Netresearch\NrVault\Http\SecretPlacement;

   // Bearer token
   $client = $vault->http()
       ->withAuthentication('api_token', SecretPlacement::Bearer);
   $response = $client->sendRequest(new Request('GET', $url));

   // API key header (X-API-Key)
   $client = $vault->http()
       ->withAuthentication('api_key', SecretPlacement::ApiKey);
   $response = $client->sendRequest(new Request('GET', $url));

   // Custom header
   $client = $vault->http()
       ->withAuthentication('api_key', SecretPlacement::Header, [
           'headerName' => 'X-Custom-Auth',
       ]);
   $response = $client->sendRequest(new Request('GET', $url));

   // Basic authentication with separate secrets
   $client = $vault->http()
       ->withAuthentication('service_password', SecretPlacement::BasicAuth, [
           'usernameSecret' => 'service_user',
       ]);
   $response = $client->sendRequest(new Request('GET', $url));

   // Query parameter
   $client = $vault->http()
       ->withAuthentication('api_key', SecretPlacement::QueryParam, [
           'queryParam' => 'key',
       ]);
   $response = $client->sendRequest(new Request('GET', $url));

For a complete real-world example combining TCA vault fields with the HTTP
client, see :ref:`usage-api-endpoint-example`.

.. toctree::
   :hidden:

   ApiEndpointExample
   ExtensionSettings
