<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Sink;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\Sink\JsonFileAuditSink;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\AuditSinkException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\EnvironmentSandboxTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;
use TYPO3\CMS\Core\Core\Environment;

/**
 * Unit tests for the append-only NDJSON audit sink.
 *
 * These run against a REAL temporary directory rather than vfsStream, on purpose.
 * Everything worth testing here is genuine filesystem behaviour that a virtual
 * filesystem only approximates: `fopen('ab')` append semantics, `flock()`,
 * `chmod()` result bits, and — most importantly — the `realpath()`-based
 * public-web-root check, which cannot resolve a `vfs://` URL at all. Testing
 * against vfsStream would have required weakening that check to accept stream
 * wrappers, i.e. changing production security behaviour to suit the test.
 *
 * Each test gets a throwaway project layout under the system temp directory and
 * points `Environment` at it, so the public-web-root boundary being checked is a
 * real directory under the test's control. The layout is removed in tearDown.
 */
#[CoversClass(JsonFileAuditSink::class)]
final class JsonFileAuditSinkTest extends TestCase
{
    use EnvironmentSandboxTrait;

    private string $baseDirectory = '';

    private string $entryPath = '';

    private string $anchorPath = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpEnvironmentSandbox();

        $this->baseDirectory = Environment::getVarPath() . '/log';
        $this->entryPath = $this->baseDirectory . '/audit.ndjson';
        $this->anchorPath = $this->baseDirectory . '/anchor.ndjson';
    }

    protected function tearDown(): void
    {
        $this->tearDownEnvironmentSandbox();

        parent::tearDown();
    }

    #[Test]
    public function identifierIsStableAndFreeOfPathInformation(): void
    {
        $subject = $this->createSubject();

        self::assertSame('file', $subject->getIdentifier());
        self::assertStringNotContainsString($this->baseDirectory, $subject->getIdentifier());
    }

    #[Test]
    public function disabledConfigurationReportsNotEnabled(): void
    {
        self::assertFalse($this->createSubject(enabled: false)->isEnabled());
    }

    #[Test]
    public function enabledConfigurationWithSafePathsReportsEnabled(): void
    {
        self::assertTrue($this->createSubject()->isEnabled());
    }

    #[Test]
    public function publishWritesOneJsonObjectPerLine(): void
    {
        $subject = $this->createSubject();

        $subject->publish($this->createEntry(uid: 1), 'tip-1');
        $subject->publish($this->createEntry(uid: 2), 'tip-2');

        $lines = $this->readLines($this->entryPath);

        self::assertCount(2, $lines);
        foreach ($lines as $line) {
            self::assertIsArray(json_decode($line, true, 512, JSON_THROW_ON_ERROR));
        }
    }

    #[Test]
    public function publishedLineCarriesTheUidAndChainTip(): void
    {
        $this->createSubject()->publish($this->createEntry(uid: 77), 'tip-77');

        $record = $this->decodeFirstLine($this->entryPath);

        self::assertSame('entry', $record['type']);
        self::assertSame(77, $record['uid']);
        self::assertSame('tip-77', $record['chainTip']);
    }

    #[Test]
    public function publishedLineCarriesTheAuditEntryPayload(): void
    {
        $this->createSubject()->publish($this->createEntry(), 'tip');

        $record = $this->decodeFirstLine($this->entryPath);

        self::assertIsArray($record['entry']);
        self::assertSame('api/stripe', $record['entry']['secretIdentifier']);
        self::assertSame('read', $record['entry']['action']);
    }

    /**
     * Append-only is the whole point: a sink that rewrote the file would let a
     * single later write erase the evidence of every earlier one.
     */
    #[Test]
    public function writesAppendRatherThanTruncate(): void
    {
        mkdir($this->baseDirectory, 0o700, true);
        file_put_contents($this->entryPath, "pre-existing\n");

        $this->createSubject()->publish($this->createEntry(), 'tip');

        $lines = $this->readLines($this->entryPath);

        self::assertCount(2, $lines);
        self::assertSame('pre-existing', $lines[0]);
    }

    /**
     * The stream names every secret identifier and actor. World-readable would
     * hand an unprivileged local account a reconnaissance feed.
     */
    #[Test]
    public function createdFileIsOwnerReadWriteOnly(): void
    {
        $this->createSubject()->publish($this->createEntry(), 'tip');

        clearstatcache(true, $this->entryPath);

        $permissions = fileperms($this->entryPath);
        self::assertIsInt($permissions);
        self::assertSame('0600', substr(\sprintf('%o', $permissions), -4));
    }

    #[Test]
    public function missingDirectoryIsCreated(): void
    {
        self::assertDirectoryDoesNotExist($this->baseDirectory);

        $this->createSubject()->publish($this->createEntry(), 'tip');

        self::assertFileExists($this->entryPath);
    }

    #[Test]
    public function anchorsGoToTheAnchorStreamNotTheEntryStream(): void
    {
        $this->createSubject()->publishAnchor(new ChainTipAnchor(5, 'tip', 1_750_000_000, 3));

        self::assertFileExists($this->anchorPath);
        self::assertFileDoesNotExist($this->entryPath);

        $record = $this->decodeFirstLine($this->anchorPath);
        self::assertSame('anchor', $record['type']);
        self::assertSame(5, $record['anchor']['sequence']);
        self::assertSame('tip', $record['anchor']['chainTip']);
        self::assertSame(3, $record['anchor']['hmacEpoch']);
    }

    #[Test]
    public function alertsGoToTheAnchorStream(): void
    {
        $this->createSubject()->publishAlert(
            AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'chain shrank', ['anchoredSequence' => 9]),
        );

        $record = $this->decodeFirstLine($this->anchorPath);

        self::assertSame('alert', $record['type']);
        self::assertSame('TABLE_RESET', $record['alert']['reason']);
        self::assertTrue($record['alert']['tamperEvidence']);
    }

    /**
     * Anchors and alerts share the stream, so a reader must be able to tell them
     * apart without guessing — the `type` discriminator is load-bearing.
     */
    #[Test]
    public function anchorStreamRecordsAreDistinguishableByType(): void
    {
        $subject = $this->createSubject();
        $subject->publishAnchor(new ChainTipAnchor(1, 'tip', 1, 3));
        $subject->publishAlert(AuditIntegrityAlert::create(AuditIntegrityReason::SinkFailure, 'x'));

        $types = array_map(
            static fn (string $line): mixed => json_decode($line, true, 512, JSON_THROW_ON_ERROR)['type'] ?? null,
            $this->readLines($this->anchorPath),
        );

        self::assertSame(['anchor', 'alert'], $types);
    }

    /**
     * A path under the document root would publish the audit trail over HTTP.
     * Disabling is the correct outcome — writing anyway is worse than not having
     * an external sink at all.
     */
    #[Test]
    public function pathInsideThePublicWebRootDisablesTheSink(): void
    {
        $subject = $this->createSubject(
            entryPath: Environment::getPublicPath() . '/fileadmin/audit.ndjson',
        );

        self::assertFalse($subject->isEnabled());
    }

    #[Test]
    public function anchorPathInsideThePublicWebRootDisablesTheSinkEvenWhenTheEntryPathIsSafe(): void
    {
        $subject = $this->createSubject(
            anchorPath: Environment::getPublicPath() . '/fileadmin/anchor.ndjson',
        );

        self::assertFalse($subject->isEnabled());
    }

    /**
     * `..` traversal must be collapsed before the boundary comparison, or a path
     * that textually starts outside the root can still land inside it.
     */
    #[Test]
    public function traversalIntoThePublicWebRootDisablesTheSink(): void
    {
        $subject = $this->createSubject(
            entryPath: Environment::getVarPath() . '/../' . basename(Environment::getPublicPath()) . '/audit.ndjson',
        );

        self::assertFalse($subject->isEnabled());
    }

    #[Test]
    #[DataProvider('unusablePathProvider')]
    public function unusablePathDisablesTheSink(string $path): void
    {
        self::assertFalse($this->createSubject(entryPath: $path)->isEnabled());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusablePathProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'relative' => ['var/log/audit.ndjson'];
        yield 'relative with traversal' => ['../audit.ndjson'];
    }

    /**
     * A sink that silently returned on failure would be indistinguishable from a
     * working one, so failures must surface to the registry.
     */
    #[Test]
    public function unwritableTargetThrowsAuditSinkException(): void
    {
        mkdir($this->baseDirectory, 0o700, true);
        // A directory cannot be opened for appending.
        mkdir($this->entryPath, 0o700);

        $this->expectException(AuditSinkException::class);

        $this->createSubject()->publish($this->createEntry(), 'tip');
    }

    /**
     * Invalid UTF-8 reaches the sink from request headers (user agent), and
     * `json_encode()` would otherwise fail the whole write on it.
     */
    #[Test]
    public function invalidUtf8InThePayloadIsSubstitutedRatherThanFailingTheWrite(): void
    {
        $this->createSubject()->publish(
            $this->createEntry(userAgent: "Mozilla\xC3\x28"),
            'tip',
        );

        $record = $this->decodeFirstLine($this->entryPath);

        self::assertIsArray($record['entry']);
        self::assertIsString($record['entry']['userAgent']);
    }

    private function createSubject(
        bool $enabled = true,
        ?string $entryPath = null,
        ?string $anchorPath = null,
    ): JsonFileAuditSink {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('isAuditSinkFileEnabled')->willReturn($enabled);
        $configuration->method('getAuditSinkFilePath')->willReturn($entryPath ?? $this->entryPath);
        $configuration->method('getAuditSinkAnchorPath')->willReturn($anchorPath ?? $this->anchorPath);

        return new JsonFileAuditSink($configuration, new NullLogger());
    }

    private function createEntry(int $uid = 1, string $userAgent = 'Mozilla/5.0'): AuditLogEntry
    {
        return new AuditLogEntry(
            uid: $uid,
            secretIdentifier: 'api/stripe',
            action: 'read',
            success: true,
            errorMessage: null,
            reason: null,
            actorUid: 7,
            actorType: 'be_user',
            actorUsername: 'editor',
            actorRole: 'groups:1',
            ipAddress: '203.0.113.7',
            userAgent: $userAgent,
            requestId: 'req-1',
            previousHash: 'prev',
            entryHash: 'hash-' . $uid,
            hashBefore: '',
            hashAfter: '',
            crdate: 1_750_000_000,
            context: [],
        );
    }

    /**
     * @return list<string>
     */
    private function readLines(string $path): array
    {
        $contents = file_get_contents($path);
        self::assertIsString($contents);

        return array_values(array_filter(explode("\n", $contents), static fn (string $l): bool => trim($l) !== ''));
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeFirstLine(string $path): array
    {
        $decoded = json_decode($this->readLines($path)[0], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
