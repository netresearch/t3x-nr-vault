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

.. _usage-analytics:

Analytics
---------

The :guilabel:`Analytics` submodule gives administrators an at-a-glance view of
secret usage and highlights secrets that may be safe to remove. Choose the
evaluation window with the :guilabel:`30d` / :guilabel:`90d` / :guilabel:`180d`
/ :guilabel:`365d` selector at the top.

.. figure:: /Images/VaultAnalytics.png
   :alt: Vault Analytics module with KPI cards, usage distribution, and a redaction-candidates table
   :class: with-shadow

   The analytics dashboard summarises usage and flags redaction candidates

.. _usage-analytics-metrics:

Key metrics
~~~~~~~~~~~

Total secrets
   Active (non-deleted) secrets in the vault.

Expired
   Secrets whose expiration date has passed but that still exist.

Redaction candidates
   Secrets flagged by at least one staleness rule (see below).

Frontend-accessible
   Secrets marked ``frontend_accessible`` - review these with extra care.

Never rotated
   Secrets that have never been rotated within the configured threshold.

Reads in window (automated / manual)
   Read activity for the selected window, split into automated reads (CLI,
   scheduler, API) and manual reveals performed in the backend.

.. _usage-analytics-redaction:

Redaction candidates
~~~~~~~~~~~~~~~~~~~~~

The table lists every flagged secret together with the rule(s) that flagged it,
its last read of any kind, the automated / manual read split for the window, and
its age in days. :guilabel:`Open` deep-links straight to the secret record so you
can review or delete it.

Secrets are flagged by these rules:

Dead
   Never read and older than the threshold, or not read for a long time - the
   primary deletion candidate.

Expired
   Past its expiration date but still present in the vault.

Never rotated
   Older than the rotation threshold without ever having been rotated.

Automation-stale
   Revealed manually but **never read by automation**. This is a *review*
   signal rather than a deletion signal: the secret may legitimately be used
   only through manual workflows. It is therefore never combined with
   :guilabel:`Dead`.

.. note::

   The automated-versus-manual split is derived from the audit log
   (``actor_type``), so it reflects only reads recorded while audit logging was
   active. Reads in TYPO3 CLI context (console commands, scheduled jobs, queue
   workers) are recorded with actor type ``cli`` and count as automated, even
   though the CLI bootstrap authenticates the ``_cli_`` backend user. The day
   thresholds are configurable - see :ref:`usage-extension-settings`.

.. tip::

   To explore the dashboard with realistic, dated history on a development
   instance, seed demo secrets and audit events with the
   :ref:`vault:seed-demo <command-seed-demo>` command (development context
   only).

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

References are **not** resolved automatically when TYPO3 loads the site
configuration. Resolve them explicitly, at the point of use, with
:php:`SiteConfigurationVaultProcessor`:

.. code-block:: php
   :caption: Resolve site-configuration secrets at read time

   use Netresearch\NrVault\Configuration\SiteConfigurationVaultProcessor;
   use TYPO3\CMS\Core\Utility\GeneralUtility;

   $site = $request->getAttribute('site');
   $processor = GeneralUtility::makeInstance(SiteConfigurationVaultProcessor::class);
   $config = $processor->processConfiguration($site->getConfiguration(), $site);
   $stripeSecret = $config['settings']['payment']['stripeSecretKey'];

This keeps sensitive values out of your version control while still
allowing you to configure them through the familiar site settings.

.. important::

   Resolution is caller-driven, not automatic. TYPO3 persists the loaded
   site configuration into its shared, on-disk ``core`` cache; resolving
   :yaml:`%vault(identifier)%` references eagerly at load time would write the
   decrypted secrets into that cache file in cleartext and would run the
   per-principal access check only once, when the cache is warmed. Resolving
   at read time keeps the plaintext within the current request and re-checks
   access for every reader. Passing the :php:`$site` object also enables
   site-scoped identifiers (``site:<siteIdentifier>:<secret>``).

.. _usage-typoscript:

TypoScript integration
======================

Use vault references in TypoScript for frontend-accessible secrets:

.. code-block:: typoscript
   :caption: TypoScript vault reference

   lib.googleMapsKey = TEXT
   lib.googleMapsKey {
     value = %vault(google_maps_api_key)%
     stdWrap.cache.disable = 1
   }

   page.headerData.10 = TEXT
   page.headerData.10 {
     value = <script>var API_KEY = '%vault(public_api_key)%';</script>
     stdWrap.cache.disable = 1
   }

.. note::

   The ``stdWrap.`` sub-array is required, not decoration. ``TEXT`` removes
   ``value`` from its configuration before rendering, so a ``TEXT`` object whose
   only property is ``value`` never calls ``stdWrap()`` at all — and the
   placeholder is what reaches the page. Earlier releases of this documentation
   showed the property-less form; it never resolved.

.. warning::

   **Security considerations:**

   -  Only secrets marked as ``frontend_accessible`` can be resolved.
   -  Resolved values may be cached - use ``cache.disable = 1`` for
      secrets that should not be cached.
   -  Consider using ``USER_INT`` for content containing secrets.

.. _usage-typoscript-frontend-scope:

Which placeholders resolve in the frontend
------------------------------------------

The listener that expands :typoscript:`%vault(...)%` runs on the output of
*every* ``stdWrap`` call. That includes strings the integrator did not author:
an editor-written ``tt_content`` field rendered with ``stdWrap.field =
bodytext``, or a request parameter rendered with ``data = GP:q``. Without a
restriction, anyone who can type into a content element — or append a query
string — could name any frontend-accessible secret and have it expanded into
the (cacheable) page.

In a frontend request the extension therefore resolves an identifier only when
it was **published** through a source an editor cannot write:

**A1 — frontend TypoScript.** The identifier appears in the setup array, i.e.
somewhere in the site's TypoScript. ``sys_template`` is admin-only and site
TypoScript lives on disk. This covers every documented example on this page:
writing ``lib.apiKey.value = %vault(my_api_key)%`` publishes ``my_api_key``.

**A2 — site configuration and site settings.** An identifier used anywhere in
:file:`config/sites/<site>/config.yaml` or in the site settings is published for
that site. This is what keeps :ref:`site configuration <configuration-site>`
values usable in content.

**A3 — the explicit list.** For an identifier that is used only in a Fluid
template file, a ``userFunc`` or a DataProcessor — that is, nowhere in the setup
array — name it once per site:

.. code-block:: typoscript
   :caption: Publish identifiers that appear nowhere else in TypoScript

   plugin.tx_nrvault.frontendResolvableIdentifiers = my_api_key, public_widget_token

**A4 — integrator PHP.** In an eID handler or any other entry point that has no
TypoScript and no site attribute, publish the identifier for the current request:

.. code-block:: php
   :caption: Publish an identifier from PHP

   use Netresearch\NrVault\Security\FrontendPlaceholderPolicyInterface;
   use TYPO3\CMS\Core\Utility\GeneralUtility;

   // $request is the PSR-7 request your handler received.
   GeneralUtility::makeInstance(FrontendPlaceholderPolicyInterface::class)
       ->allowIdentifier('my_api_key', $request);

The request argument is not decoration, and it is not a freshness hint either:
it *is* the key. The policy is a shared service that lives for the whole PHP
process, so the grant is stored against that request object in a
:php:`\WeakMap`, and a later request — an anonymous frontend render in the same
worker process, possibly on another site — holds a different object and cannot
address it.

.. important::

   Pass the request you are handling, and call :php:`setRequest()` with **the
   same object** on the content object renderer you render with. The grant is
   matched by object identity against the request the renderer carries;
   :php:`$GLOBALS['TYPO3_REQUEST']` is never consulted for it, because TYPO3
   sets that global and never unsets it, so in a worker SAPI it outlives the
   request that set it. A renderer carrying a different request — or none —
   resolves nothing.

.. warning::

   Never pass request-derived data as the *identifier* — that hands the
   allow-set back to the caller and re-opens the hole. Where you can, prefer
   :php:`VaultServiceInterface::retrieveForFrontend()`, which returns the value
   instead of widening the allow-set.

**Failure is loud, but quiet in production.** An unpublished identifier leaves
the literal ``%vault(identifier)%`` in the output. In :guilabel:`Development`
context a single ``notice`` per request names the first rejected identifier; in
every other context the skip path writes nothing, so unauthenticated input
cannot drive log volume.

.. warning::

   The flip side is that a rejected identifier leaves **no trace** outside
   :guilabel:`Development`: no log record and — because the check runs before
   the vault is touched — no ``AccessDenied`` audit row either. Probing for
   which identifiers a site publishes is therefore free and invisible; the only
   signal is whether the literal survives in the page. If you need that signal,
   run the site in :guilabel:`Development` while investigating, or watch for
   ``%vault(`` in rendered output. This is a deliberate trade: emitting a record
   per rejection is exactly the amplification an anonymous visitor could drive.

**Scope of the restriction.** It applies to frontend requests and to any web
request whose type cannot be established (eID among them, where
:php:`$GLOBALS['TYPO3_REQUEST']` does not exist). CLI — scheduler, Symfony
Messenger, console commands — and backend requests are unaffected, a backend
request being recognised by the request the renderer itself carries and never by
what an earlier request left in :php:`$GLOBALS['TYPO3_REQUEST']`. The check is
on the *identifier*, not on where the placeholder sits: an identifier this site
already publishes stays resolvable wherever it appears.

One further case is worth naming: on a **fully cached page hit with no**
``USER_INT`` **or** ``COA_INT`` **object**, core's frontend TypoScript factory
returns before the setup array is built, so A1 and A3 are empty for that request
and only A2 and A4 apply. No documented example is affected, and the direction is
fail-closed. See :ref:`ADR-035 <adr-035-frontend-placeholder-allow-set>`.

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
