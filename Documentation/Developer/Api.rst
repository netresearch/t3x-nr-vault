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

   .. php:method:: decrypt(string $encryptedValue, string $encryptedDek, string $dekNonce, string $valueNonce, string $identifier): string

      Decrypt a previously encrypted value. ``$encryptedValue`` and
      ``$encryptedDek`` are ``#[\SensitiveParameter]``.

      :param string $encryptedValue: Base64-encoded ciphertext (``#[\SensitiveParameter]``).
      :param string $encryptedDek: Base64-encoded encrypted DEK (``#[\SensitiveParameter]``).
      :param string $dekNonce: Base64-encoded DEK nonce.
      :param string $valueNonce: Base64-encoded value nonce.
      :param string $identifier: Secret identifier (used as AAD).
      :returns: The decrypted plaintext.
      :throws EncryptionException: If decryption fails.

   .. php:method:: generateDek(): string

      Generate a new Data Encryption Key.

      :returns: A 32-byte random key.

   .. php:method:: calculateChecksum(string $plaintext): string

      Calculate a value checksum for change detection. ``$plaintext`` is
      a ``#[\SensitiveParameter]``.

      :param string $plaintext: The secret value (``#[\SensitiveParameter]``).
      :returns: SHA-256 hash (64 hex characters).

   .. php:method:: reEncryptDek(string $encryptedDek, string $dekNonce, string $identifier, string $oldMasterKey, string $newMasterKey): ReEncryptedDek

      Re-encrypt a DEK with a new master key (used during master-key
      rotation). ``$encryptedDek``, ``$oldMasterKey`` and
      ``$newMasterKey`` are ``#[\SensitiveParameter]``.

      :param string $encryptedDek: Current encrypted DEK (``#[\SensitiveParameter]``).
      :param string $dekNonce: Current DEK nonce.
      :param string $identifier: Secret identifier.
      :param string $oldMasterKey: Previous master key (``#[\SensitiveParameter]``).
      :param string $newMasterKey: New master key (``#[\SensitiveParameter]``).
      :returns: A ``ReEncryptedDek`` value object (``Netresearch\NrVault\Crypto\ReEncryptedDek``).

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

.. php:interface:: VaultHttpClientInterface

   PSR-18 compatible HTTP client with vault-based authentication.
   Extends :php:`Psr\Http\Client\ClientInterface`.

   .. php:method:: withAuthentication(string $secretIdentifier, SecretPlacement $placement = SecretPlacement::Bearer, array $options = []): static

      Create a new client instance configured with authentication.
      Returns an immutable instance - the original is unchanged.

      :param string $secretIdentifier: Vault identifier for the secret.
      :param SecretPlacement $placement: How to inject the secret.
      :param array $options: Additional options (headerName, queryParam, usernameSecret, reason).
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

   Dispatched after master key rotation completes.

   -  :php:`getSecretsReEncrypted()`: Number of secrets re-encrypted.
   -  :php:`getActorUid()`: User ID who performed the rotation.
   -  :php:`getRotatedAt()`: DateTimeImmutable of when rotation completed.
