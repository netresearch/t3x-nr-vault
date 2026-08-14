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
      :throws AccessDeniedException: If the per-secret ACL or the operation permission refuses the write — ``secret.create`` on a new secret, ``secret.rotate`` on an existing one, and additionally ``secret.manage_policy`` when the options change the owner or the group tiers.
      :throws EncryptionException: If encryption fails.

      Operation permissions and the per-secret ACL are two independent gates.
      Holding one never implies the other, and both are asserted before the
      value is written.

   .. php:method:: retrieve(string $identifier)

      Retrieve a secret from the vault.

      :param string $identifier: The secret identifier.
      :returns: The decrypted secret value or null if not found.
      :returntype: string|null
      :throws AccessDeniedException: If user lacks read permission.
      :throws SecretExpiredException: If the secret has expired.

   .. php:method:: retrieveForFrontend(string $identifier)

      Frontend-scoped counterpart of ``retrieve()``. Only secrets flagged
      ``frontend_accessible`` resolve here, and that requirement holds for
      every caller — including a request that happens to carry a backend
      session, whose ambient privileges would otherwise widen
      ``retrieve()``'s access decision. Expiry, decryption, audit logging
      and read statistics behave as in ``retrieve()``. See
      :ref:`adr-035-frontend-placeholder-allow-set`.

      :param string $identifier: The secret identifier.
      :returns: The decrypted secret value or null if not found.
      :returntype: string|null
      :throws AccessDeniedException: If the secret is not frontend-accessible, or the actor lacks read permission.
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

   .. php:method:: assertDeletable(string $identifier): void

      Assert that ``delete()`` is permitted for this identifier — without
      deleting. Exists for callers that delete several secrets as one
      logical unit, such as a record delete spanning multiple vault fields:
      a vault delete is a hard delete with no restore, so a partially
      applied batch cannot be compensated, and the only way to keep it
      all-or-nothing is to run every permission gate up front and abort
      before the first deletion.

      A secret that does not exist returns without throwing — the goal state
      is already reached. Ask ``exists()`` to distinguish absent from
      present. Passing does **not** guarantee the subsequent delete
      succeeds: an audit-write failure, or a permission revoked in between,
      can still abort it.

      :param string $identifier: The secret identifier.
      :throws AccessDeniedException: If the current actor lacks delete permission.

   .. php:method:: rotate(string $identifier, string $newSecret, string $reason = ''): void

      Rotate a secret with a new value. ``$newSecret`` is a
      ``#[\SensitiveParameter]``.

      :param string $identifier: The secret identifier.
      :param string $newSecret: The new secret value (``#[\SensitiveParameter]``).
      :param string $reason: Optional reason for rotation (logged).
      :throws SecretNotFoundException: If the secret does not exist.
      :throws AccessDeniedException: If the per-secret ACL or the ``secret.rotate`` operation permission refuses it.
      :throws EncryptionException: If encryption fails.

   .. php:method:: setEnabled(string $identifier, bool $enabled, string $reason = ''): void

      Enable or disable a secret — the single write path for its availability.

      Disabling withdraws the secret from every read path at once: the record
      carries TCA's ``disabled`` enable column, so a disabled secret resolves
      to nothing in :php:`retrieve()`, :php:`retrieveForFrontend()` and every
      placeholder that goes through them. It stays administrable — it can be
      re-enabled, rotated, deleted, and its metadata read — and reports its
      state in :php:`SecretDetails::$enabled`.

      The state is absolute rather than a toggle: setting the state a secret
      already has is a no-op and writes no audit entry. A change is audited as
      ``metadata_update``, the same action the FormEngine path writes for the
      same column, and is all-or-nothing with that entry
      (:ref:`adr-036-mutation-audit-atomicity`): if the audit write fails the
      previous availability is restored and the failure surfaces.

      :param string $identifier: The secret identifier.
      :param bool $enabled: The availability the secret should have afterwards.
      :param string $reason: Optional justification, recorded in the audit entry alongside the direction of the change.
      :throws SecretNotFoundException: If the secret does not exist.
      :throws AccessDeniedException: If the per-secret ACL or the ``secret.manage_policy`` operation permission refuses it.

   .. php:method:: list(?string $pattern = null, bool $includeDisabled = false): array

      List accessible secrets.

      :param string|null $pattern: Optional pattern to filter identifiers (supports the ``*`` wildcard).
      :param bool $includeDisabled: Also return disabled secrets. Off by default, so a consumer asking which secrets are available keeps the answer it had; the management surfaces pass ``true``, because a disabled secret that never appears in a listing cannot be re-enabled.
      :returns: A ``list<SecretMetadata>`` of secret metadata DTOs (``Netresearch\NrVault\Domain\Dto\SecretMetadata``); each entry reports its availability in ``$enabled``.

   .. php:method:: getMetadata(string $identifier): SecretDetails

      Get metadata for a secret without retrieving its value. Resolves a
      disabled secret too — metadata is not the value, and withholding it
      would hide the record from the form that re-enables it.

      :param string $identifier: The secret identifier.
      :returns: A ``SecretDetails`` DTO (``Netresearch\NrVault\Domain\Dto\SecretDetails``) with identifier, description, owner, groups, version, availability (``$enabled``), etc.
      :throws SecretNotFoundException: If secret doesn't exist.
      :throws AccessDeniedException: If user lacks permission.

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

.. _api-http-cancellable:

Cancelling an outbound request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PSR-18 returns a response, never a handle, so :php:`sendRequest()` cannot be
aborted once it is running — a caller whose own work was cancelled still waits
out the timeout. :php:`CancellableHttpClientInterface` adds a second send that
polls a caller-supplied signal and tears the socket down when it turns true.

It is a *send*, not an exported handle, and that is a security property rather
than a matter of taste. Four of this client's protections — the scheme
allowlist, the ``allowed_hosts`` gate, the credential injection and the audit
write — are statements inside the sending method, not middleware on the handler
stack, so they do not travel with a transport. The rule the package holds to is
therefore narrow and sharp: **nothing hands you a client that already carries a
vault secret**, and :php:`VaultHttpClient` is the only place nr-vault attaches a
secret to *your* request. There is no send you can drive that puts a vault
secret on the wire without those four: every public method of that class returns
a configured clone, a PSR-7 response or a bool, and
:php:`sendCancellable()` takes no options parameter — asserted by
``VaultHttpClientCancellableTest::theCredentialBearingClientExportsNoTransportAndNoPromise()``.

nr-vault sends two credentials of its own on paths that are not your request and
do not carry all four: the ``X-Vault-Token`` header of the transit master-key
provider, on a plain Guzzle client, and the ``client_secret`` of the OAuth token
leg, which does apply the ``allowed_hosts`` gate but writes no audit row. They
are listed in :ref:`adr-037-cancellable-outbound-send`.

Building a hardened transport *without* vault credentials remains a supported,
public case: :php:`SecureHttpClientFactory::create()` and
:php:`createCancellable()` return one, carrying the SSRF reject middleware and
the ``CURLOPT_RESOLVE`` DNS pin — and no secret, no allowlist gate, no audit
write.

The interface is separate from :php:`VaultHttpClientInterface` and purely
additive, so consumers feature-detect instead of raising a version floor:

.. code-block:: php
   :caption: Aborting a call when the surrounding operation is cancelled

   use Netresearch\NrVault\Http\CancellableHttpClientInterface;
   use Netresearch\NrVault\Http\CancellationSignalInterface;
   use Netresearch\NrVault\Exception\RequestCancelledException;

   final class RunCancellationSignal implements CancellationSignalInterface
   {
       public function __construct(private readonly MyRunState $run) {}

       public function isCancelled(): bool
       {
           return $this->run->wasCancelled();
       }
   }

   $client = $this->vaultService->http()
       ->withAuthentication('tool_api_key')
       ->withReason('MCP tool call')
       ->withTimeout(15);

   try {
       $response = $client instanceof CancellableHttpClientInterface && $client->supportsCancellation()
           ? $client->sendCancellable($request, new RunCancellationSignal($run))
           : $client->sendRequest($request);
   } catch (RequestCancelledException $e) {
       // The call was abandoned on purpose; the audit log already recorded it.
   }

The signal is polled once before the request is sent and then between ticks of
the transport event loop. Implementations must be cheap and must not throw:
the method is called several times a second per in-flight request, and it runs
after the credential has been injected. A signal that throws anyway still leaves
an audit row — the write is in a ``finally`` — but the exception reaches the
caller unchanged
(``VaultHttpClientCancellableTest::aSignalThatThrowsMidFlightStillLeavesAnAuditRow()``).

.. note::

   Where a guarantee in this section names a test, that test is in
   ``Tests/Unit/Http/VaultHttpClientCancellableTest.php`` or
   ``Tests/Unit/Http/VaultHttpClientTest.php`` and enforces the sentence it is
   named in; each fixed literal listed below is asserted by a test as well,
   through the outcome-to-test table in
   :ref:`adr-037-cancellable-outbound-send`, which names one per row.

   Two statements here name none and are descriptions rather than pinned
   guarantees: what :php:`SecureHttpClientFactory::create()` and
   :php:`createCancellable()` hand out, and the invariant sentence introducing
   this section — whose operative half, that no send you can drive skips the
   four protections, does name one.

.. note::

   When this client builds the transport itself, it comes from
   :php:`SecureHttpClientFactory` and carries the same hardened options, the
   same SSRF/DNS-pin middleware
   (``ssrfDnsPinIsInstalledOnTheCancellableTransport()``) and the same timeout
   as the blocking client
   (``theTransportTheClientResolvesForItselfCarriesTheRememberedTimeout()``) —
   cancellation is an early exit, never an extension.

   A PSR-18 client you injected into :php:`VaultHttpClient`'s constructor is
   never replaced by a transport
   (``anInjectedGuzzleClientIsNeverSwappedForACancellableTransport()``):
   :php:`supportsCancellation()` reports false for such an instance and
   :php:`sendCancellable()` completes the call blocking, on your client. The one
   exception is :php:`withTimeout()`, which has to bake the override into a
   client and therefore rebuilds one from the factory — the clone it returns
   reports :php:`supportsCancellation()` **true**
   (``withTimeoutRebuildsACallerSuppliedClientAndTurnsCancellationOn()``).

   A client obtained from :php:`VaultServiceInterface::http()` supports
   cancellation on any platform with ``curl_multi_*``, through the withers
   included (``cancellationSurvivesTheWithersAndTheProductionFactory()``);
   without that extension it degrades. Ask
   :php:`supportsCancellation()` rather than assuming either.

Every :php:`sendCancellable()` writes exactly one audit row — and so does every
:php:`sendRequest()` — so the log is complete with respect to calls and not
merely to egress. The outcome-to-test table in
:ref:`adr-037-cancellable-outbound-send` is the enumeration that backs this
sentence: one row per way a call can end, one named test per row. Three actions
can result, and each means one thing — the
action is what you filter and count on, so none of them needs the error message
to be understood:

``http_call_cancelled`` (badge: warning)
   The signal stopped an **in-flight** request. The credential was retrieved,
   injected and handed to the transport: treat it as exposed. Nothing else is
   filed under this action, so "which calls were abandoned after their
   credential went out?" is a query on this one value
   (``theTwoCancellationOutcomesAreToldApartByTheirAction()``).

``http_call_cancelled_before_send`` (badge: info)
   The signal was already set when the send began. No secret was retrieved and
   nothing was handed to the transport. Its own action so you can exclude these
   rows by query rather than by reading messages
   (``cancellingBeforeSendReadsNoSecretAndStillLeavesADistinguishableRow()``).

``http_call`` with ``success = false``
   Everything that failed rather than was cancelled — a refused scheme or host,
   a transport that could not be built, a credential that could not be obtained,
   a transport error, the defensive wall-clock bound, a settlement that is not a
   response, or a throw from your signal or the ticker. Nobody asked for those,
   so they sit with the other failures. ADR-037 lists the test for each.

Within an action, the row's error message is a fixed literal shown under the
badge:

``Request cancelled before send: nothing egressed and no secret was retrieved``
   The pre-flight refusal.

``Request cancelled after send began: credential injected and transfer handed to the transport``
   In the usual case the bytes are already out; if the signal turns true before
   the first tick they may not be, which is why the literal does not claim more
   than it can.

``Cancellable transfer exceeded its wall-clock budget and was aborted``
   The defensive bound above the curl timeouts tripped, i.e. the transport
   stopped settling its promise.

``Cancellable transport settled with a value that is not an HTTP response``
   The transfer settled with something unusable.

``Cancellable transfer aborted by an unexpected error after the credential was injected: …``
   Guzzle's option handling, your signal or the ticker threw.

``Blocking send aborted by an unexpected error after the credential was injected: …``
   The degraded blocking branch threw something that is not a PSR-18
   ``ClientExceptionInterface``. The same literal can appear for a plain
   :php:`sendRequest()`, which runs the same send-and-audit helper.

``Cancellable transport could not be built; nothing was sent: …``
   Building the transport for :php:`sendCancellable()` threw. It is built after
   the two guards and before the credential is read, so nothing egressed and no
   secret was retrieved. This one is specific to :php:`sendCancellable()`.

``Cancellable transfer was rejected``
   The promise rejected with a reason that is not a ``Throwable``, so there is
   no foreign message to append. Specific to :php:`sendCancellable()`.

``Request refused before any secret was read: unsupported URI scheme "…"``
   The URI was neither ``http`` nor ``https``. The scheme is in the message
   because the audit context records method, host, path and status only.

``Request refused before any secret was read: host is not in the allowed hosts list``
   ``$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']`` refused the
   destination. The host is on the row, in the context.

``Credential injection failed; nothing was sent: …``
   The vault read, or the OAuth token leg, threw. Nothing egressed.

The last three appear for :php:`sendRequest()` as well: they are refusals of a
call that was asked for, and a call that was asked for shows up in the log.
The exception you receive is unchanged by that row — pinned by three
characterization tests in ``VaultHttpClientTest``, written before the rows
existed.

See :ref:`adr-037-cancellable-outbound-send` for the transport details and the
residual gaps — in particular that the OAuth token round trip preceding an
OAuth-authenticated call is not cancellable.

.. php:interface:: CancellableHttpClientInterface

   An outbound send that can be aborted while it is still on the wire.
   Implemented by :php:`VaultHttpClient` alongside
   :php:`VaultHttpClientInterface`.

   .. php:method:: sendCancellable(RequestInterface $request, CancellationSignalInterface $signal): ResponseInterface

      Send an HTTP request, aborting the transfer as soon as ``$signal`` says
      so. Runs the same guard sequence as :php:`sendRequest()`: scheme
      allowlist, host allowlist, credential injection, audit write.

      Accepts no per-request transport options, deliberately — see
      :ref:`adr-037-cancellable-outbound-send`.

      When :php:`supportsCancellation()` is false the call still completes,
      blocking, with an ordinary ``http_call`` audit row. It degrades; it does
      not fail
      (``aNonGuzzleInnerClientDegradesToABlockingSendWithAnOrdinaryAuditRow()``).

      :param RequestInterface $request: PSR-7 request.
      :param CancellationSignalInterface $signal: Polled before the send and between transport ticks.
      :returns: PSR-7 response.
      :throws RequestCancelledException: If the signal aborted the call.
      :throws ClientExceptionInterface: If the transfer itself failed.
      :throws VaultException: If the scheme or host is rejected, or secret retrieval fails.

   .. php:method:: supportsCancellation(): bool

      Whether this instance can abort a transfer in flight. False when the
      platform has no ``curl_multi_*`` support, and false when the inner client
      was supplied by the caller instead of built by
      :php:`SecureHttpClientFactory` — a supplied client may carry your own
      middleware or proxy, so it stays the one that sends. A *pre-flight* signal
      is still honoured in either case, because nothing has egressed yet, and
      the call is still audited
      (``aPreFlightSignalIsHonouredEvenWhenCancellationIsUnsupported()``).

.. php:interface:: CancellationSignalInterface

   .. php:method:: isCancelled(): bool

      Return true to abort the in-flight request. Must not throw, and must be
      cheap.

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

.. php:class:: AuditIntegrityAlertEvent

   Dispatched when audit verification produces a finding.

   -  :php:`getAlert()`: The alert value object.
   -  :php:`getReason()`: The stable reason code (``TABLE_RESET``,
      ``EPOCH_DOWNGRADE``, ``SINK_FAILURE``, ``NO_EXTERNAL_SINK``, …).
   -  :php:`isTamperEvidence()`: Whether this finding is evidence of tampering
      rather than an availability problem — the discriminator a pager rule
      should key on.

.. php:class:: BreakGlassActivatedEvent

   Dispatched when a break-glass window opens.

   -  :php:`getActorUid()` / :php:`getActorUsername()`: Who opened it.
   -  :php:`getReason()`: The mandatory justification.
   -  :php:`getExpiresAt()`: When the window lapses on its own.

.. php:class:: BreakGlassDeactivatedEvent

   Dispatched when a window is closed deliberately. A window that merely
   *expires* dispatches nothing — nothing runs at the moment it lapses, so
   reconstruct the closed interval from the activation event's expiry.

   -  :php:`getActorUid()` / :php:`getActorUsername()`: Who closed it.
   -  :php:`getReason()`: The closing note.
