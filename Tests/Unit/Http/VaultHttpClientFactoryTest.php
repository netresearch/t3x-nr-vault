<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Http\DnsResolverInterface;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Http\VaultHttpClientFactory;
use Netresearch\NrVault\Http\VaultHttpClientInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Client\ClientInterface;
use ReflectionProperty;

/**
 * The factory is the only place a VaultHttpClient is assembled for callers of
 * `VaultServiceInterface::http()`. Its wiring decides two things that matter
 * beyond "an object comes back": the client must talk through the hardened
 * client built by SecureHttpClientFactory (a bare Guzzle client would have no
 * SSRF defence and would log request bodies in debug mode), and it must carry
 * the audit log service, since an unaudited HTTP client would use secrets
 * without leaving a trace.
 */
#[CoversClass(VaultHttpClientFactory::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultHttpClientFactoryTest extends TestCase
{
    use GuzzleClientConfigTrait;

    private VaultHttpClientFactory $subject;

    private AuditLogServiceInterface&MockObject $auditLogService;

    private VaultServiceInterface&MockObject $vaultService;

    private mixed $originalGlobals = null;

    protected function setUp(): void
    {
        parent::setUp();

        // No allowed-hosts / proxy configuration: the factory must build a
        // working client from the platform defaults alone.
        $this->originalGlobals = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['HTTP' => []];

        $this->auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $this->vaultService = $this->createMock(VaultServiceInterface::class);

        // A resolver double keeps the seam free of real DNS traffic even if a
        // future change resolves eagerly instead of at request time.
        $dnsResolver = $this->createMock(DnsResolverInterface::class);
        $dnsResolver->method('resolve')->willReturn([]);

        $this->subject = new VaultHttpClientFactory(
            $this->auditLogService,
            new SecureHttpClientFactory($dnsResolver),
        );
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        if ($this->originalGlobals !== null) {
            $GLOBALS['TYPO3_CONF_VARS'] = $this->originalGlobals;
        } else {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    #[Test]
    public function createReturnsAVaultHttpClient(): void
    {
        self::assertInstanceOf(VaultHttpClient::class, $this->subject->create($this->vaultService));
    }

    /**
     * VaultHttpClient is an immutable per-call-chain object: handing out a
     * shared instance would leak one caller's configured authentication into
     * the next caller's requests.
     */
    #[Test]
    public function everyCallReturnsAFreshClient(): void
    {
        self::assertNotSame(
            $this->subject->create($this->vaultService),
            $this->subject->create($this->vaultService),
        );
    }

    #[Test]
    public function clientIsBoundToTheVaultServiceItWasCreatedFor(): void
    {
        $otherVaultService = $this->createMock(VaultServiceInterface::class);

        $first = $this->subject->create($this->vaultService);
        $second = $this->subject->create($otherVaultService);

        self::assertSame($this->vaultService, $this->readProperty($first, 'vaultService'));
        self::assertSame($otherVaultService, $this->readProperty($second, 'vaultService'));
    }

    /**
     * The audit service comes from DI, not from the caller — every client the
     * factory hands out writes to the same audit chain.
     */
    #[Test]
    public function clientIsBoundToTheInjectedAuditLogService(): void
    {
        $client = $this->subject->create($this->vaultService);

        self::assertSame($this->auditLogService, $this->readProperty($client, 'auditLogService'));
    }

    /**
     * The inner transport must be the hardened one: `debug` off so request
     * bodies carrying secrets are never dumped, `http_errors` off so failures
     * reach the audit log instead of throwing past it, and redirects off so a
     * 302 cannot replay the Authorization header at another origin.
     */
    #[Test]
    public function innerClientIsTheHardenedTransport(): void
    {
        $client = $this->subject->create($this->vaultService);

        $innerClient = $this->readProperty($client, 'innerClient');
        self::assertInstanceOf(ClientInterface::class, $innerClient);

        $config = $this->getGuzzleConfig($innerClient);

        self::assertFalse($config['debug']);
        self::assertFalse($config['http_errors']);
        self::assertFalse($config['allow_redirects']);
    }

    /**
     * A freshly created client authenticates nothing until a `with*()` call
     * configures it — otherwise it would attach a secret to requests the
     * caller never asked to authenticate.
     */
    #[Test]
    public function freshClientCarriesNoAuthenticationConfiguration(): void
    {
        $client = $this->subject->create($this->vaultService);

        self::assertNull($this->readProperty($client, 'secretIdentifier'));
        self::assertNull($this->readProperty($client, 'placement'));
        self::assertNull($this->readProperty($client, 'oauthConfig'));
    }

    private function readProperty(VaultHttpClientInterface $client, string $property): mixed
    {
        return (new ReflectionProperty(VaultHttpClient::class, $property))->getValue($client);
    }
}
