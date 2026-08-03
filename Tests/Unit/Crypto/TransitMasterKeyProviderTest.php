<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Configuration\Dto\TransitConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\TransitMasterKeyProvider;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\ErrorSuppressionTrait;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamContent;
use org\bovigo\vfs\vfsStreamDirectory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

#[CoversClass(TransitMasterKeyProvider::class)]
#[AllowMockObjectsWithoutExpectations]
final class TransitMasterKeyProviderTest extends TestCase
{
    use ErrorSuppressionTrait;

    private const ADDRESS = 'https://vault.example.com:8200';

    private const TOKEN_ENV_VAR = 'NR_VAULT_TEST_TRANSIT_TOKEN';

    private const WRAPPED_CIPHERTEXT = 'vault:v1:dGVzdC1jaXBoZXJ0ZXh0LXBheWxvYWQ=';

    private const TOKEN = 'unit-test-vault-token';

    private vfsStreamDirectory $root;

    private ?RequestInterface $lastRequest = null;

    private int $requestCount = 0;

    protected function setUp(): void
    {
        parent::setUp();

        TransitMasterKeyProvider::clearCachedKey();
        $this->root = vfsStream::setup('transit');
        $this->lastRequest = null;
        $this->requestCount = 0;
        putenv(self::TOKEN_ENV_VAR . '=' . self::TOKEN);
    }

    protected function tearDown(): void
    {
        TransitMasterKeyProvider::clearCachedKey();
        putenv(self::TOKEN_ENV_VAR);

        parent::tearDown();
    }

    #[Test]
    public function getIdentifierReturnsTransit(): void
    {
        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        self::assertSame('transit', $provider->getIdentifier());
    }

    #[Test]
    public function getMasterKeyUnwrapsCiphertextIntoRawKey(): void
    {
        $key = random_bytes(32);
        $this->writeWrappedKeyFile();

        $client = $this->clientReturning($this->transitResponse(['plaintext' => base64_encode($key)]));

        $provider = $this->createProvider($client);

        self::assertSame($key, $provider->getMasterKey());

        $request = $this->assertSingleRequest();
        self::assertSame('POST', $request->getMethod());
        self::assertSame(
            self::ADDRESS . '/v1/transit/decrypt/nr-vault-master',
            (string) $request->getUri(),
        );
        self::assertSame(self::TOKEN, $request->getHeaderLine('X-Vault-Token'));
        self::assertSame(
            ['ciphertext' => self::WRAPPED_CIPHERTEXT],
            json_decode((string) $request->getBody(), true, 8, JSON_THROW_ON_ERROR),
        );
    }

    #[Test]
    public function getMasterKeyThrowsWhenPlaintextHasWrongLength(): void
    {
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->clientReturning($this->transitResponse(['plaintext' => base64_encode('too-short')])),
        );

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1703800009);
        $this->expectExceptionMessageToContain('Invalid master key length');

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyThrowsWhenPlaintextIsNotBase64(): void
    {
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->clientReturning($this->transitResponse(['plaintext' => 'not!valid!base64!'])),
        );

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1754100006);

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyThrowsWhenResponseHasNoDataObject(): void
    {
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->clientReturning(new Response(200, [], '{"errors":[]}')),
        );

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1754100006);

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyOnForbiddenReportsStatusWithoutLeakingTokenOrCiphertext(): void
    {
        $this->writeWrappedKeyFile();

        // Vault echoes the submitted ciphertext on some error paths — the body
        // must never reach the exception message.
        $body = json_encode([
            'errors' => ['permission denied for ' . self::WRAPPED_CIPHERTEXT . ' with token ' . self::TOKEN],
        ], JSON_THROW_ON_ERROR);

        $provider = $this->createProvider($this->clientReturning(new Response(403, [], $body)));

        try {
            $provider->getMasterKey();
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertSame(1754100004, $e->getCode());
            self::assertStringContainsString('HTTP 403', $e->getMessage());
            self::assertStringNotContainsString(self::TOKEN, $e->getMessage());
            self::assertStringNotContainsString(self::WRAPPED_CIPHERTEXT, $e->getMessage());
        }
    }

    #[Test]
    public function getMasterKeyRedactsTokensFromTransportErrors(): void
    {
        $this->writeWrappedKeyFile();

        $client = $this->createMock(ClientInterface::class);
        $client
            ->method('sendRequest')
            ->willThrowException(new class ('cURL error 7 with X-Vault-Token: ' . self::TOKEN) extends RuntimeException implements ClientExceptionInterface {});

        $provider = $this->createProvider($client);

        try {
            $provider->getMasterKey();
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertSame(1754100005, $e->getCode());
            self::assertStringNotContainsString(self::TOKEN, $e->getMessage());
            self::assertStringContainsString('[REDACTED]', $e->getMessage());
        }
    }

    #[Test]
    public function isAvailableReturnsFalseWhenWrappedKeyFileIsMissing(): void
    {
        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function getMasterKeyThrowsWhenWrappedKeyFileIsMissing(): void
    {
        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessageToContain('Master key not found');

        $provider->getMasterKey();
    }

    #[Test]
    public function isAvailableReturnsTrueWhenConfigurationAndWrappedKeyArePresent(): void
    {
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        self::assertTrue($provider->isAvailable());
    }

    #[Test]
    public function isAvailableReturnsFalseWithoutToken(): void
    {
        $this->writeWrappedKeyFile();
        putenv(self::TOKEN_ENV_VAR);

        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function isAvailableReturnsFalseForUnsupportedAuthMethod(): void
    {
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->createMock(ClientInterface::class),
            $this->transitConfig(authMethod: 'approle'),
        );

        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function getMasterKeyThrowsForUnsupportedAuthMethod(): void
    {
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->createMock(ClientInterface::class),
            $this->transitConfig(authMethod: 'kubernetes'),
        );

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1754100003);

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyThrowsWhenTokenIsMissing(): void
    {
        $this->writeWrappedKeyFile();
        putenv(self::TOKEN_ENV_VAR);

        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        try {
            $provider->getMasterKey();
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertSame(1754100002, $e->getCode());
            self::assertStringContainsString(self::TOKEN_ENV_VAR, $e->getMessage());
            self::assertStringContainsString('[REDACTED]', $e->getMessage());
        }
    }

    #[Test]
    public function getMasterKeyThrowsWhenMountPathIsUnsafe(): void
    {
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->createMock(ClientInterface::class),
            $this->transitConfig(mount: '../../sys'),
        );

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1754100007);

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyThrowsWhenKeyNameIsATraversalSegment(): void
    {
        $this->writeWrappedKeyFile();

        // A dot is legal inside a key name, but "." / ".." are traversal
        // segments and must never be interpolated into the Vault API path.
        $provider = $this->createProvider(
            $this->createMock(ClientInterface::class),
            $this->transitConfig(keyName: '..'),
        );

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1754100007);

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyThrowsWhenLocalFileHoldsNoTransitCiphertext(): void
    {
        // A raw key file (file-provider format) must not be mistaken for a
        // wrapped blob and shipped to Vault.
        file_put_contents($this->wrappedKeyPath(), base64_encode(random_bytes(32)));

        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1754100001);

        $provider->getMasterKey();
    }

    #[Test]
    public function storeMasterKeyPersistsOnlyTheCiphertext(): void
    {
        $key = random_bytes(32);

        $client = $this->clientReturning($this->transitResponse(['ciphertext' => self::WRAPPED_CIPHERTEXT]));

        $this->createProvider($client)->storeMasterKey($key);

        $request = $this->assertSingleRequest();
        self::assertSame(
            self::ADDRESS . '/v1/transit/encrypt/nr-vault-master',
            (string) $request->getUri(),
        );
        self::assertSame(
            ['plaintext' => base64_encode($key)],
            json_decode((string) $request->getBody(), true, 8, JSON_THROW_ON_ERROR),
        );

        $stored = (string) file_get_contents($this->wrappedKeyPath());
        self::assertSame(self::WRAPPED_CIPHERTEXT, $stored);
        self::assertStringNotContainsString($key, $stored);
        self::assertStringNotContainsString(base64_encode($key), $stored);
    }

    #[Test]
    public function storeMasterKeyWritesTheWrappedKeyWithOwnerOnlyPermissions(): void
    {
        $client = $this->clientReturning($this->transitResponse(['ciphertext' => self::WRAPPED_CIPHERTEXT]));

        $this->createProvider($client)->storeMasterKey(random_bytes(32));

        $file = $this->root->getChild('vault-master.key.transit');
        self::assertNotNull($file);
        self::assertSame(0o600, $file->getPermissions());
    }

    #[Test]
    public function storeMasterKeyLeavesNoTemporaryFileBehind(): void
    {
        $client = $this->clientReturning($this->transitResponse(['ciphertext' => self::WRAPPED_CIPHERTEXT]));

        $this->createProvider($client)->storeMasterKey(random_bytes(32));

        // glob() cannot traverse stream wrappers — inspect the vfs tree directly.
        $names = array_map(
            static fn (vfsStreamContent $child): string => $child->getName(),
            $this->root->getChildren(),
        );

        self::assertSame(['vault-master.key.transit'], $names);
    }

    #[Test]
    public function storeMasterKeyThrowsWhenVaultReturnsNoCiphertext(): void
    {
        $client = $this->clientReturning($this->transitResponse(['plaintext' => 'unexpected']));

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1754100006);

        $this->createProvider($client)->storeMasterKey(random_bytes(32));
    }

    #[Test]
    public function storeMasterKeyRejectsKeyOfWrongLength(): void
    {
        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1703800009);

        $provider->storeMasterKey('too-short');
    }

    #[Test]
    public function generateMasterKeyReturns32Bytes(): void
    {
        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        self::assertSame(32, \strlen($provider->generateMasterKey()));
    }

    #[Test]
    public function nestedMountPathIsInterpolatedIntoTheEndpoint(): void
    {
        $key = random_bytes(32);
        $this->writeWrappedKeyFile();

        $client = $this->clientReturning($this->transitResponse(['plaintext' => base64_encode($key)]));

        $provider = $this->createProvider(
            $client,
            $this->transitConfig(mount: 'platform/transit', keyName: 'master_key-1'),
        );

        self::assertSame($key, $provider->getMasterKey());
        self::assertSame(
            self::ADDRESS . '/v1/platform/transit/decrypt/master_key-1',
            (string) $this->assertSingleRequest()->getUri(),
        );
    }

    #[Test]
    public function configuredTokenIsUsedWhenNoEnvironmentVariableIsSetAndSurvivesRepeatedLookups(): void
    {
        $this->writeWrappedKeyFile();
        putenv(self::TOKEN_ENV_VAR);

        $config = $this->transitConfig(token: self::TOKEN);
        $key = random_bytes(32);

        $client = $this->clientReturning($this->transitResponse(['plaintext' => base64_encode($key)]));
        $provider = $this->createProvider($client, $config);

        // isAvailable() also resolves the token; the configuration DTO shares its
        // string buffer with the ExtensionConfiguration singleton, so a
        // sodium_memzero() on that copy would corrupt the token for this call.
        self::assertTrue($provider->isAvailable());
        self::assertSame($key, $provider->getMasterKey());

        self::assertSame(self::TOKEN, $this->assertSingleRequest()->getHeaderLine('X-Vault-Token'));
        self::assertSame(self::TOKEN, $config->token);
    }

    #[Test]
    public function isAvailableReturnsFalseWhenMountPathIsUnsafe(): void
    {
        // Availability must fail closed on an unsafe key reference, otherwise a
        // traversal mount is only caught once the hot path builds the URL.
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->createMock(ClientInterface::class),
            $this->transitConfig(mount: '../../sys'),
        );

        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function getMasterKeyThrowsWhenPlaintextIsAnEmptyString(): void
    {
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->clientReturning($this->transitResponse(['plaintext' => ''])),
        );

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1754100006);

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyRejectsAStatusOfExactlyThreeHundred(): void
    {
        // 300 is outside the 2xx success band; only a `>= 300` bound rejects it.
        $this->writeWrappedKeyFile();

        $body = json_encode(
            ['data' => ['plaintext' => base64_encode(sodium_crypto_secretbox_keygen())]],
            JSON_THROW_ON_ERROR,
        );

        $provider = $this->createProvider($this->clientReturning(new Response(300, [], $body)));

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionCode(1754100004);

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyAcceptsAResponseAtTheSupportedJsonDepth(): void
    {
        $key = sodium_crypto_secretbox_keygen();
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->clientReturning(new Response(200, [], $this->nestedTransitBody($key, 29))),
        );

        self::assertSame($key, $provider->getMasterKey());
    }

    #[Test]
    public function getMasterKeyRejectsAResponseNestedBeyondTheSupportedJsonDepth(): void
    {
        // A deliberately over-nested body must be refused rather than parsed —
        // the depth cap is the defence against decoder resource exhaustion.
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->clientReturning(
                new Response(200, [], $this->nestedTransitBody(sodium_crypto_secretbox_keygen(), 30)),
            ),
        );

        try {
            $provider->getMasterKey();
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertSame(1754100006, $e->getCode());
            self::assertStringContainsString('not valid JSON', $e->getMessage());
        }
    }

    #[Test]
    public function getMasterKeyReadsPlaintextFromAMultiFieldDataObject(): void
    {
        // Vault answers with `key_version` alongside `plaintext`; the whole data
        // object must be handed back, not just its first entry.
        $key = sodium_crypto_secretbox_keygen();
        $this->writeWrappedKeyFile();

        $provider = $this->createProvider(
            $this->clientReturning($this->transitResponse([
                'key_version' => '1',
                'plaintext' => base64_encode($key),
            ])),
        );

        self::assertSame($key, $provider->getMasterKey());
    }

    #[Test]
    public function getMasterKeyReportsAMissingWrappedKeyWithoutClaimingItIsUnreadable(): void
    {
        $provider = $this->createProvider($this->createMock(ClientInterface::class));

        try {
            $provider->getMasterKey();
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertSame('Master key not found at: ' . $this->wrappedKeyPath(), $e->getMessage());
        }
    }

    #[Test]
    public function wrappedKeyFileIsTrimmedBeforeItIsSentToVault(): void
    {
        // Editors and shell redirection add surrounding whitespace; the prefix
        // check and the submitted ciphertext must both see the trimmed blob.
        $key = sodium_crypto_secretbox_keygen();
        file_put_contents($this->wrappedKeyPath(), " \n" . self::WRAPPED_CIPHERTEXT . "\n");

        $client = $this->clientReturning($this->transitResponse(['plaintext' => base64_encode($key)]));
        $provider = $this->createProvider($client);

        self::assertSame($key, $provider->getMasterKey());
        self::assertSame(
            ['ciphertext' => self::WRAPPED_CIPHERTEXT],
            json_decode((string) $this->assertSingleRequest()->getBody(), true, 8, JSON_THROW_ON_ERROR),
        );
    }

    #[Test]
    public function transportFailureMessageEndsWithTheCausingExceptionClass(): void
    {
        $this->writeWrappedKeyFile();

        $transportError = new class ('cURL error 7: connection refused') extends RuntimeException implements ClientExceptionInterface {};

        $client = $this->createMock(ClientInterface::class);
        $client->method('sendRequest')->willThrowException($transportError);

        try {
            $this->createProvider($client)->getMasterKey();
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertStringStartsWith(
                'Vault Transit decrypt request could not be sent: cURL error 7: connection refused',
                $e->getMessage(),
            );
            self::assertStringEndsWith(
                \sprintf(' (caused by %s)', $transportError::class),
                $e->getMessage(),
            );
        }
    }

    #[Test]
    public function transportFailureRedactsHeaderTokensAndBareServiceTokens(): void
    {
        $this->writeWrappedKeyFile();

        // Clearly synthetic, generated at runtime: the legacy `s.` service-token
        // shape the third redaction pattern targets.
        $bareToken = 's.' . bin2hex(random_bytes(12));
        $headerToken = 'unit-test-header-token-' . bin2hex(random_bytes(4));

        $client = $this->createMock(ClientInterface::class);
        $client->method('sendRequest')->willThrowException(
            new class ('sending failed with X-Vault-Token: ' . $headerToken . ' using ' . $bareToken . ' downstream') extends RuntimeException implements ClientExceptionInterface {},
        );

        try {
            $this->createProvider($client)->getMasterKey();
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertStringNotContainsString($headerToken, $e->getMessage());
            self::assertStringNotContainsString($bareToken, $e->getMessage());
            // The header NAME survives (only its value is replaced), and the
            // bare token is replaced rather than dropped.
            self::assertStringContainsString('X-Vault-Token: [REDACTED]', $e->getMessage());
            self::assertStringContainsString('using [REDACTED] downstream', $e->getMessage());
        }
    }

    #[Test]
    public function storeMasterKeyCreatesTheKeyDirectoryWithOwnerOnlyPermissions(): void
    {
        $client = $this->clientReturning($this->transitResponse(['ciphertext' => self::WRAPPED_CIPHERTEXT]));

        $provider = $this->createProvider($client, $this->transitConfig(
            wrappedKeyPath: vfsStream::url('transit/created/deep/wrapped.key'),
        ));
        $provider->storeMasterKey(sodium_crypto_secretbox_keygen());

        $outer = $this->root->getChild('created');
        self::assertNotNull($outer);
        self::assertSame(0o700, $outer->getPermissions());

        $inner = $this->root->getChild('created/deep');
        self::assertNotNull($inner);
        self::assertSame(0o700, $inner->getPermissions());
    }

    #[Test]
    public function storeMasterKeyReportsAnUncreatableDirectoryRatherThanTheFailedWrite(): void
    {
        mkdir(vfsStream::url('transit/readonly'), 0o500);

        $client = $this->clientReturning($this->transitResponse(['ciphertext' => self::WRAPPED_CIPHERTEXT]));
        $provider = $this->createProvider($client, $this->transitConfig(
            wrappedKeyPath: vfsStream::url('transit/readonly/nested/wrapped.key'),
        ));

        try {
            $this->withoutPhpDiagnostics(
                static fn (): null => $provider->storeMasterKey(sodium_crypto_secretbox_keygen()),
            );
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertSame(
                'Cannot store master key: Cannot create directory: ' . vfsStream::url('transit/readonly/nested'),
                $e->getMessage(),
            );
        }
    }

    #[Test]
    public function storeMasterKeyRestoresThePreviousUmask(): void
    {
        $client = $this->clientReturning($this->transitResponse(['ciphertext' => self::WRAPPED_CIPHERTEXT]));
        $provider = $this->createProvider($client);

        $outerUmask = umask(0o022);

        try {
            $provider->storeMasterKey(sodium_crypto_secretbox_keygen());

            self::assertSame(0o022, umask());
        } finally {
            umask($outerUmask);
        }
    }

    #[Test]
    public function storeMasterKeyRestoresThePreviousUmaskWhenTheWriteFails(): void
    {
        // The umask is tightened for the write; a failing write must not leak
        // the tightened value into the rest of the request.
        mkdir(vfsStream::url('transit/readonly'), 0o500);

        $client = $this->clientReturning($this->transitResponse(['ciphertext' => self::WRAPPED_CIPHERTEXT]));
        $provider = $this->createProvider($client, $this->transitConfig(
            wrappedKeyPath: vfsStream::url('transit/readonly/wrapped.key'),
        ));

        $outerUmask = umask(0o022);

        try {
            $this->withoutPhpDiagnostics(
                static fn (): null => $provider->storeMasterKey(sodium_crypto_secretbox_keygen()),
            );
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertStringContainsString('Cannot write to', $e->getMessage());
            self::assertSame(0o022, umask());
        } finally {
            umask($outerUmask);
        }
    }

    #[Test]
    public function destructionClearsTheRequestLifetimeKeyCache(): void
    {
        $this->writeWrappedKeyFile();

        $first = sodium_crypto_secretbox_keygen();
        $provider = $this->createProvider(
            $this->clientReturning($this->transitResponse(['plaintext' => base64_encode($first)])),
        );
        self::assertSame($first, $provider->getMasterKey());
        unset($provider);

        $second = sodium_crypto_secretbox_keygen();
        $successor = $this->createProvider(
            $this->clientReturning($this->transitResponse(['plaintext' => base64_encode($second)])),
        );

        self::assertSame($second, $successor->getMasterKey());
    }

    /**
     * A syntactically valid transit response whose `data` object carries an
     * extra branch nested $levels deep, used to probe the json_decode() depth
     * cap from both sides.
     */
    private function nestedTransitBody(string $key, int $levels): string
    {
        $nested = 1;
        for ($i = 0; $i < $levels; ++$i) {
            $nested = [$nested];
        }

        return json_encode(
            ['data' => ['plaintext' => base64_encode($key), 'deep' => $nested]],
            JSON_THROW_ON_ERROR,
        );
    }

    private function createProvider(
        ClientInterface $client,
        ?TransitConfig $config = null,
    ): TransitMasterKeyProvider {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration
            ->method('getTransitConfig')
            ->willReturn($config ?? $this->transitConfig());

        $httpFactory = new HttpFactory();

        return new TransitMasterKeyProvider($configuration, $client, $httpFactory, $httpFactory);
    }

    private function transitConfig(
        string $mount = 'transit',
        string $keyName = 'nr-vault-master',
        string $authMethod = 'token',
        string $token = '',
        ?string $wrappedKeyPath = null,
    ): TransitConfig {
        return new TransitConfig(
            address: self::ADDRESS,
            mount: $mount,
            keyName: $keyName,
            wrappedKeyPath: $wrappedKeyPath ?? $this->wrappedKeyPath(),
            authMethod: $authMethod,
            tokenEnvVar: self::TOKEN_ENV_VAR,
            token: $token,
        );
    }

    private function wrappedKeyPath(): string
    {
        return vfsStream::url('transit/vault-master.key.transit');
    }

    private function writeWrappedKeyFile(): void
    {
        file_put_contents($this->wrappedKeyPath(), self::WRAPPED_CIPHERTEXT);
    }

    /**
     * @param array<string, string> $data
     */
    private function transitResponse(array $data): ResponseInterface
    {
        return new Response(
            200,
            ['Content-Type' => 'application/json'],
            json_encode(['data' => $data], JSON_THROW_ON_ERROR),
        );
    }

    /**
     * PSR-18 client that records every dispatched request and always answers
     * with $response.
     */
    private function clientReturning(ResponseInterface $response): ClientInterface
    {
        $client = $this->createMock(ClientInterface::class);
        $client
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request) use ($response): ResponseInterface {
                $this->lastRequest = $request;
                ++$this->requestCount;

                return $response;
            });

        return $client;
    }

    /**
     * Assert exactly one request was dispatched and return it.
     */
    private function assertSingleRequest(): RequestInterface
    {
        self::assertSame(1, $this->requestCount);
        $request = $this->lastRequest;
        self::assertNotNull($request);

        return $request;
    }
}
