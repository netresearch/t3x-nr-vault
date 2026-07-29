.. include:: /Includes.rst.txt

.. _developer-api:

===
API
===

This chapter documents the public API of the nr-vault extension.

.. _api-vault-service:

VaultService
============

The main service for interacting with the vault.

.. php:namespace:: Netresearch\NrVault\Service

.. php:interface:: VaultServiceInterface

   Main interface for vault operations.

   .. note::

      The plaintext parameters ``$secret`` / ``$newSecret`` carry the
      PHP ``#[\SensitiveParameter]`` attribute on the interface, so they
      are redacted from stack traces and ``var_dump()`` output. Mirror
      the attribute on any custom implementation.

   .. php:method:: store(string $identifier, string $secret, array $options = []): void

      Store a secret in the vault. ``$secret`` is a
      ``#[\SensitiveParameter]``.

      :param string $identifier: Unique identifier for the secret.
      :param string $secret: The secret value to store (``#[\SensitiveParameter]``).
      :param array $options: Optional configuration: ``owner`` (int BE-user UID), ``groups`` (int[] BE-group UIDs), ``context`` (string), ``expiresAt`` (int|\DateTimeInterface|null), ``metadata`` (array), ``description`` (string), ``scopePid`` (int).
      :throws ValidationException: If the identifier is invalid.
      :throws EncryptionException: If encryption fails.

   .. php:method:: retrieve(string $identifier)

      Retrieve a secret from the vault.

      :param string $identifier: The secret identifier.
      :returns: The decrypted secret value or null if not found.
      :returntype: string|null
      :throws AccessDeniedException: If user lacks read permission.
      :throws SecretExpiredException: If the secret has expired.

   .. php:method:: exists(string $identifier): bool

      Check if a secret exists.

      :param string $identifier: The secret identifier.
      :returns: True if the secret exists.

   .. php:method:: delete(string $identifier, string $reason = ''): void

      Delete a secret from the vault.

      :param string $identifier: The secret identifier.
      :param string $reason: Optional reason for deletion (logged).
      :throws SecretNotFoundException: If secret doesn't exist.
      :throws AccessDeniedException: If user lacks delete permission.

   .. php:method:: rotate(string $identifier, string $newSecret, string $reason = ''): void

      Rotate a secret with a new value. ``$newSecret`` is a
      ``#[\SensitiveParameter]``.

      :param string $identifier: The secret identifier.
      :param string $newSecret: The new secret value (``#[\SensitiveParameter]``).
      :param string $reason: Optional reason for rotation (logged).

   .. php:method:: list(?string $pattern = null): array

      List accessible secrets.

      :param string|null $pattern: Optional pattern to filter identifiers (supports the ``*`` wildcard).
      :returns: A ``list<SecretMetadata>`` of secret metadata DTOs (``Netresearch\NrVault\Domain\Dto\SecretMetadata``).

   .. php:method:: getMetadata(string $identifier): SecretDetails

      Get metadata for a secret without retrieving its value.

      :param string $identifier: The secret identifier.
      :returns: A ``SecretDetails`` DTO (``Netresearch\NrVault\Domain\Dto\SecretDetails``) with identifier, description, owner, groups, version, etc.
      :throws SecretNotFoundException: If secret doesn't exist.
      :throws AccessDeniedException: If user lacks permission.

   .. php:method:: clearCache(): void

      Clear the request-scoped cache of decrypted secrets, securely
      wiping cached plaintext from memory.

   .. php:method:: http(): VaultHttpClientInterface

      Get an HTTP client that can inject secrets into requests.

      :returns: A PSR-18 compatible vault-aware HTTP client.

.. _api-encryption-service:

EncryptionService
=================

The crypto boundary: libsodium envelope encryption (per-secret DEK
wrapped by the master key).

.. php:namespace:: Netresearch\NrVault\Crypto

.. php:interface:: EncryptionServiceInterface

   Low-level encryption operations. Most callers use
   :php:`VaultServiceInterface` instead.

   .. note::

      Plaintext and key parameters (``$plaintext``, ``$encryptedValue``,
      ``$encryptedDek``, ``$oldMasterKey``, ``$newMasterKey``) carry the
      ``#[\SensitiveParameter]`` attribute on the interface.

   .. php:method:: encrypt(string $plaintext, string $identifier): EncryptedData

      Encrypt a plaintext value with a unique DEK. ``$plaintext`` is a
      ``#[\SensitiveParameter]``.

      :param string $plaintext: The value to encrypt (``#[\SensitiveParameter]``).
      :param string $identifier: Secret identifier (used as AAD).
      :returns: An ``EncryptedData`` value object (``Netresearch\NrVault\Crypto\EncryptedData``) holding the ciphertext, encrypted DEK, and nonces.
      :throws EncryptionException: If encryption fails.

   .. php:method:: decrypt(string $encryptedValue, string $encryptedDek, string $dekNonce, string $valueNonce, string $identifier, int $encryptionVersion = 1, string $encryptionAlgorithm = ''): string

      Decrypt a previously encrypted value. ``$encryptedValue`` and
      ``$encryptedDek`` are ``#[\SensitiveParameter]``.

      :param string $encryptedValue: Base64-encoded ciphertext (``#[\SensitiveParameter]``).
      :param string $encryptedDek: Base64-encoded encrypted DEK (``#[\SensitiveParameter]``).
      :param string $dekNonce: Base64-encoded DEK nonce.
      :param string $valueNonce: Base64-encoded value nonce.
      :param string $identifier: Secret identifier (used as AAD).
      :param int $encryptionVersion: Stored per-secret encryption version. Defaults to ``ENCRYPTION_VERSION_LEGACY`` (1), where the algorithm is derived from host capabilities.
      :param string $encryptionAlgorithm: Stored per-secret algorithm marker. Required for version 2+, must be ``''`` for version 1.
      :returns: The decrypted plaintext.
      :throws EncryptionException: If decryption fails or the marker is unknown on this host.

   .. php:method:: generateDek(): string

      Generate a new Data Encryption Key.

      :returns: A 32-byte random key.

   .. php:method:: calculateChecksum(string $plaintext): string

      Calculate a value checksum for change detection. ``$plaintext`` is
      a ``#[\SensitiveParameter]``.

      :param string $plaintext: The secret value (``#[\SensitiveParameter]``).
      :returns: SHA-256 hash (64 hex characters).

   .. php:method:: reEncryptDek(string $encryptedDek, string $dekNonce, string $identifier, string $oldMasterKey, string $newMasterKey, int $encryptionVersion = 1, string $encryptionAlgorithm = ''): ReEncryptedDek

      Re-encrypt a DEK with a new master key (used during master-key
      rotation). ``$encryptedDek``, ``$oldMasterKey`` and
      ``$newMasterKey`` are ``#[\SensitiveParameter]``.

      :param string $encryptedDek: Current encrypted DEK (``#[\SensitiveParameter]``).
      :param string $dekNonce: Current DEK nonce.
      :param string $identifier: Secret identifier.
      :param string $oldMasterKey: Previous master key (``#[\SensitiveParameter]``).
      :param string $newMasterKey: New master key (``#[\SensitiveParameter]``).
      :param int $encryptionVersion: Stored per-secret encryption version.
      :param string $encryptionAlgorithm: Stored per-secret algorithm marker (required for version 2+).
      :returns: A ``ReEncryptedDek`` value object (``Netresearch\NrVault\Crypto\ReEncryptedDek``).

      The DEK is re-wrapped with the SAME algorithm the secret was encrypted
      with; the version and algorithm markers are unchanged by the operation.

.. _api-envelope-codec:

EnvelopeCodec
=============

Envelope encryption for a payload you keep in ONE column of your own table
(:ref:`ADR-032 <adr-032-portable-envelope-codec>`). Use this instead of
:php:`EncryptionServiceInterface` when you have a blob rather than the vault's
seven-column layout.

.. php:namespace:: Netresearch\NrVault\Crypto

.. php:interface:: EnvelopeCodecInterface

   .. php:const:: MARKER

      ``'nrv1:'`` — the version marker of the envelopes :php:`seal()` produces.
      A stored value is self-identifying, so a column can hold sealed and
      unsealed values during a migration.

   .. php:method:: seal(string $plaintext, string $identifier): string

      Encrypt a payload into a single string. ``$plaintext`` is a
      ``#[\SensitiveParameter]``.

      :param string $plaintext: The payload to protect (``#[\SensitiveParameter]``).
      :param string $identifier: Context label bound to the ciphertext as additional authenticated data. Use a stable, per-purpose value (a column or use-case name), never a per-row one.
      :returns: ``MARKER`` + base64-encoded JSON envelope.
      :throws EncryptionException: If encryption fails or the master key is unavailable.

   .. php:method:: open(string $sealed, string $identifier): string

      Decrypt a sealed string. The stored change-detection checksum is not
      verified — integrity comes from the AEAD tag, which is always checked.

      :param string $sealed: A string produced by :php:`seal()`.
      :param string $identifier: The SAME identifier the payload was sealed with.
      :returns: The decrypted payload.
      :throws EnvelopeFormatException: If the string is not a well-formed envelope.
      :throws EncryptionException: If authentication fails, the algorithm marker is unknown on this host, or the master key is unavailable.

   .. php:method:: isSealed(string $value): bool

      Whether a stored value is an envelope, as opposed to a plain value written
      before sealing was introduced.

   .. php:method:: rewrap(string $sealed, string $identifier, string $oldMasterKey, string $newMasterKey): string

      Re-wrap the envelope's DEK from one master key to another, leaving the
      payload ciphertext untouched — nothing is decrypted. This is the primitive
      behind :php:`ForeignEnvelopeRotatorInterface`; you normally reach it through
      :php:`EnvelopeRotationContext::rewrap()` rather than calling it directly.

.. warning::

   :php:`seal()` wraps the payload's DEK with the CURRENT master key, and that
   wrapped DEK lives in YOUR table where ``vault:rotate-master-key`` cannot reach
   it. If you seal payloads you MUST also register a
   :php:`ForeignEnvelopeRotatorInterface` (below), or your data becomes
   permanently undecryptable the first time an operator rotates the master key.

.. _api-foreign-envelope-rotator:

ForeignEnvelopeRotator
======================

How a consuming extension joins master-key rotation
(:ref:`ADR-033 <adr-033-foreign-envelope-rotation>`). Tag your implementation:

.. code-block:: yaml
   :caption: Configuration/Services.yaml (in YOUR extension)

   Vendor\Extension\Crypto\MyEnvelopeRotator:
     tags: ['nrvault.foreign_envelope_rotator']

.. php:interface:: ForeignEnvelopeRotatorInterface

   .. php:method:: getIdentifier(): string

      Short label naming your extension and the data it owns, for the
      operator-facing rotation report (e.g. ``nr-llm: agent run state``).

   .. php:method:: getTables(): array

      Every table :php:`rewrapAll()` writes to. The command refuses to rotate when
      one of them is mapped to a different database connection than
      ``tx_nrvault_secret``, because atomicity across two connections is a
      fiction.

   .. php:method:: countEnvelopes(): int

      How many sealed envelopes you hold. Called outside the transaction, for the
      dry-run report and the operator summary. Throwing aborts the rotation
      before anything is touched.

   .. php:method:: rewrapAll(EnvelopeRotationContext $context): int

      Re-wrap every envelope you own; return how many. Runs INSIDE the vault's
      rotation transaction, after the vault's own secrets and before the commit.

      Do not open, commit or roll back a transaction, and do not swallow
      failures: throwing rolls the ENTIRE rotation back, which is deliberate —
      a partial rotation leaves data wrapped under a key the operator has been
      told to destroy. Work in batches; the whole pass is one transaction.

.. php:class:: EnvelopeRotationContext

   Handed to :php:`rewrapAll()`. It closes over the old and new master keys and
   exposes only the operation, so you move envelopes between keys without ever
   holding key material.

   .. php:method:: rewrap(string $sealed, string $identifier): string

      Re-wrap one envelope's DEK. The payload is not decrypted.

   .. php:method:: isSealed(string $value): bool

      For skipping rows written before you started sealing.

.. _api-secret-redactor:

SecretRedactor
==============

The shared catalogue of recognisable secret shapes
(:ref:`ADR-031 <adr-031-shared-secret-pattern-catalogue>`), used by this
extension's plaintext scanner and available to any consumer that needs to mask
secrets in log lines, error messages or outbound payloads.

This is a best-effort net for secrets that have already escaped their proper
home. It recognises the catalogued shapes and nothing else, and is not a
substitute for keeping secrets in the vault.

.. php:namespace:: Netresearch\NrVault\Secret

.. php:interface:: SecretRedactorInterface

   .. php:method:: redact(string $text, bool $includeEmails = false): string

      Replace every recognised secret occurrence in free text with a mask.

      :param bool $includeEmails: Also mask e-mail addresses. Off by default: an address is personal data rather than a secret, and masking one inside, say, a model prompt changes what the text says.
      :returns: The masked text. If the regex engine gives up on a pathological input the text is returned as-is rather than emptied.

   .. php:method:: isSecretIdentifier(string $identifier, SecretIdentifierKind $kind): bool

      Whether a name reads as secret-bearing within its namespace. The kind
      matters: database columns and configuration keys are suffix-anchored, while
      environment variables use a broad substring rule. A name check alone is not
      enough — ``GITHUB_PAT`` says nothing about being secret — so pair it with
      :php:`identifyValue()` or :php:`redact()` on the value.

   .. php:method:: identifyValue(string $value)

      The shape name when the WHOLE value is a known secret format, else null.
      Leading and trailing whitespace is ignored.

      :returns: ``string|null`` — the matched shape name, or null.

.. php:enum:: SecretIdentifierKind

   ``DatabaseColumn``, ``ConfigurationKey``, ``EnvironmentVariable`` — the three
   identifier namespaces, deliberately not merged into one rule set.

.. _api-usage-examples:

Usage examples
--------------

.. _api-example-storing:

Storing a secret
~~~~~~~~~~~~~~~~

.. code-block:: php
   :caption: Store a secret with VaultService

   use Netresearch\NrVault\Service\VaultServiceInterface;

   class MyService
   {
       public function __construct(
           private readonly VaultServiceInterface $vault,
       ) {}

       public function storeApiKey(string $apiKey): void
       {
           $this->vault->store(
               'my_extension_api_key',
               $apiKey,
               [
                   'description' => 'API key for external service',
                   'groups' => [1, 2], // Admin, Editor groups
                   'context' => 'payment',
                   'expiresAt' => time() + 86400 * 90, // 90 days
               ]
           );
       }
   }

.. _api-example-retrieving:

Retrieving a secret
~~~~~~~~~~~~~~~~~~~

.. code-block:: php
   :caption: Retrieve a secret value

   public function getApiKey(): ?string
   {
       return $this->vault->retrieve('my_extension_api_key');
   }

.. _api-http-client:

Vault HTTP client
-----------------

The vault provides a PSR-18 compatible HTTP client that can inject secrets
into requests without exposing them to your code. Configure authentication
with :php:`withAuthentication()`, then use standard :php:`sendRequest()`.

.. _api-http-direct-injection:

Direct injection (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: php
   :caption: Inject VaultHttpClientInterface

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
           // Configure authentication, then use standard PSR-18
           $client = $this->httpClient->withAuthentication(
               'api_token',
               SecretPlacement::Bearer,
           );

           $request = new Request('GET', 'https://api.example.com/data');
           $response = $client->sendRequest($request);

           return json_decode($response->getBody()->getContents(), true);
       }
   }

.. _api-http-via-service:

Via VaultService
~~~~~~~~~~~~~~~~

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

.. php:namespace:: Netresearch\NrVault\Http

.. php:interface:: VaultHttpClientInterface

   PSR-18 compatible HTTP client with vault-based authentication.
   Extends :php:`Psr\Http\Client\ClientInterface`.

   .. php:method:: withAuthentication(string $secretIdentifier, SecretPlacement $placement = SecretPlacement::Bearer, array $options = []): static

      Create a new client instance configured with authentication.
      Returns an immutable instance - the original is unchanged.

      :param string $secretIdentifier: Vault identifier for the secret.
      :param SecretPlacement $placement: How to inject the secret.
      :param array $options: Additional options (headerName, prefix, queryParam, bodyField, usernameSecret, reason).
      :returns: New client instance with authentication configured.

   .. php:method:: withOAuth(OAuthConfig $config, string $reason = 'OAuth2 API call'): static

      Create a new client instance configured with OAuth 2.0 authentication.

      :param OAuthConfig $config: OAuth configuration.
      :param string $reason: Audit log reason.
      :returns: New client instance with OAuth configured.

   .. php:method:: withReason(string $reason): static

      Create a new client instance with a custom audit reason.

      :param string $reason: Audit log reason for requests.
      :returns: New client instance with reason configured.

   .. php:method:: withTimeout(int $seconds): static

      Create a new client instance with a request timeout override.
      Applies Guzzle's ``timeout`` option (total request duration) to every
      request sent through the returned instance, authenticated or not — use
      it for long-running API calls that exceed the instance-wide
      :php:`$GLOBALS['TYPO3_CONF_VARS']['HTTP']['timeout']`. Connection
      establishment (``connect_timeout``) stays platform-managed.

      :param int $seconds: Timeout in seconds; non-positive values mean "no override" and fall back to the platform default.
      :returns: New client instance with the timeout configured.

   .. php:method:: sendRequest(RequestInterface $request): ResponseInterface

      Send an HTTP request (PSR-18 method).

      :param RequestInterface $request: PSR-7 request.
      :returns: PSR-7 response.
      :throws ClientExceptionInterface: If request fails.

.. _api-http-auth-options:

Authentication options
~~~~~~~~~~~~~~~~~~~~~~

The :php:`withAuthentication()` method accepts these options:

headerName
   Custom header name (for :php:`SecretPlacement::Header`, default: ``X-API-Key``).

prefix
   Auth scheme/prefix prepended to the secret (for :php:`SecretPlacement::Header`).
   Use for non-Bearer ``Authorization: <scheme> <secret>`` schemes — e.g. ``'Key '``
   for the TYPO3 FAL providers or ``'DeepL-Auth-Key '`` for DeepL.

queryParam
   Query parameter name (for :php:`SecretPlacement::QueryParam`, default: ``api_key``).

bodyField
   Body field name (for :php:`SecretPlacement::BodyField`, default: ``api_key``).

usernameSecret
   Separate username secret identifier (for :php:`SecretPlacement::BasicAuth`).

reason
   Reason for access (logged in audit).

.. _api-secret-placement:

SecretPlacement enum
~~~~~~~~~~~~~~~~~~~~

placement
   Authentication placement using :php:`SecretPlacement` enum:

   -  :php:`SecretPlacement::Bearer` - Bearer token in Authorization header.
   -  :php:`SecretPlacement::BasicAuth` - HTTP Basic Authentication.
   -  :php:`SecretPlacement::Header` - Custom header value.
   -  :php:`SecretPlacement::QueryParam` - Query parameter.
   -  :php:`SecretPlacement::BodyField` - Field in request body.
   -  :php:`SecretPlacement::OAuth2` - OAuth 2.0 with automatic token refresh.
   -  :php:`SecretPlacement::ApiKey` - X-API-Key header (shorthand).

.. _api-http-auth-examples:

.. code-block:: php
   :caption: Authentication examples

   use GuzzleHttp\Psr7\Request;
   use Netresearch\NrVault\Http\SecretPlacement;

   // Bearer authentication
   $client = $this->vault->http()
       ->withAuthentication('stripe_api_key', SecretPlacement::Bearer);
   $response = $client->sendRequest(
       new Request('POST', 'https://api.stripe.com/v1/charges', [], $body)
   );

   // Custom header
   $client = $this->vault->http()
       ->withAuthentication('api_token', SecretPlacement::Header, [
           'headerName' => 'X-API-Key',
       ]);
   $response = $client->sendRequest(
       new Request('GET', 'https://api.example.com/data')
   );

   // Custom Authorization scheme (e.g. DeepL "Authorization: DeepL-Auth-Key <key>")
   $client = $this->vault->http()
       ->withAuthentication('deepl_api_key', SecretPlacement::Header, [
           'headerName' => 'Authorization',
           'prefix' => 'DeepL-Auth-Key ',
       ]);
   $response = $client->sendRequest(
       new Request('POST', 'https://api-free.deepl.com/v2/translate', [], $body)
   );

   // Basic authentication with separate credentials
   $client = $this->vault->http()
       ->withAuthentication('service_password', SecretPlacement::BasicAuth, [
           'usernameSecret' => 'service_username',
           'reason' => 'Fetching secure data',
       ]);
   $response = $client->sendRequest(
       new Request('GET', 'https://api.example.com/secure')
   );

   // Query parameter
   $client = $this->vault->http()
       ->withAuthentication('api_key', SecretPlacement::QueryParam, [
           'queryParam' => 'key',
       ]);
   $response = $client->sendRequest(
       new Request('GET', 'https://maps.example.com/geocode')
   );

.. _api-events:

PSR-14 events
-------------

The vault dispatches events during secret operations.

.. php:namespace:: Netresearch\NrVault\Event

.. php:class:: SecretCreatedEvent

   Dispatched when a new secret is created.

   -  :php:`getIdentifier()`: The secret identifier.
   -  :php:`getSecret()`: The Secret entity.
   -  :php:`getActorUid()`: User ID who created it.

.. php:class:: SecretAccessedEvent

   Dispatched when a secret is read.

   -  :php:`getIdentifier()`: The secret identifier.
   -  :php:`getActorUid()`: User ID who accessed it.
   -  :php:`getContext()`: The secret's context.

.. php:class:: SecretRotatedEvent

   Dispatched when a secret is rotated.

   -  :php:`getIdentifier()`: The secret identifier.
   -  :php:`getNewVersion()`: The new version number.
   -  :php:`getActorUid()`: User ID who rotated it.
   -  :php:`getReason()`: The rotation reason.

.. php:class:: SecretDeletedEvent

   Dispatched when a secret is deleted.

   -  :php:`getIdentifier()`: The secret identifier.
   -  :php:`getActorUid()`: User ID who deleted it.
   -  :php:`getReason()`: The deletion reason.

.. php:class:: SecretUpdatedEvent

   Dispatched when a secret value is updated (without rotation).

   -  :php:`getIdentifier()`: The secret identifier.
   -  :php:`getNewVersion()`: The new version number.
   -  :php:`getActorUid()`: User ID who updated it.

.. php:class:: MasterKeyRotatedEvent

   Dispatched by ``vault:rotate-master-key`` after the rotation transaction has
   COMMITTED, so a listener never observes a rotation that was rolled back.

   -  :php:`getSecretsReEncrypted()`: Number of this extension's secrets re-encrypted.
   -  :php:`getForeignEnvelopesReEncrypted()`: Number of consumer-owned envelopes
      re-wrapped (:ref:`ADR-033 <adr-033-foreign-envelope-rotation>`).
   -  :php:`getActorUid()`: The acting backend user, or 0 in a CLI context.
   -  :php:`getRotatedAt()`: When the rotation completed.

   This is a notification, not a participation hook: a listener cannot re-wrap
   anything, because both master keys are gone by the time it runs. To have your
   own envelopes rotated, implement :php:`ForeignEnvelopeRotatorInterface`.

   -  :php:`getSecretsReEncrypted()`: Number of secrets re-encrypted.
   -  :php:`getActorUid()`: User ID who performed the rotation.
   -  :php:`getRotatedAt()`: DateTimeImmutable of when rotation completed.
