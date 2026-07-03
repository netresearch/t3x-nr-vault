<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Utility;

use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

#[AllowMockObjectsWithoutExpectations]
final class VaultFieldResolverTest extends TestCase
{
    private const UUID_V7 = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const DECRYPTION_FAILED = 'Decryption failed';

    protected TcaSchemaFactory&MockObject $tcaSchemaFactory;

    private VaultServiceInterface&MockObject $vaultService;

    private LoggerInterface&MockObject $logger;

    private VaultFieldResolver $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->tcaSchemaFactory = $this->createMock(TcaSchemaFactory::class);
        $this->logger = $this->createMock(LoggerInterface::class);

        $this->subject = new VaultFieldResolver(
            $this->vaultService,
            $this->tcaSchemaFactory,
            $this->logger,
        );
    }

    #[Test]
    public function isVaultIdentifierReturnsTrueForValidUuid(): void
    {
        // Valid UUID v7 identifiers
        self::assertTrue($this->subject->isVaultIdentifier(self::UUID_V7));
        self::assertTrue($this->subject->isVaultIdentifier('01937b6f-0000-7000-8000-000000000000'));
        self::assertTrue($this->subject->isVaultIdentifier('01937b6f-ffff-7fff-bfff-ffffffffffff'));
    }

    #[Test]
    public function isVaultIdentifierReturnsFalseForInvalidIdentifier(): void
    {
        // Empty or non-string
        self::assertFalse($this->subject->isVaultIdentifier(''));
        self::assertFalse($this->subject->isVaultIdentifier(null));
        self::assertFalse($this->subject->isVaultIdentifier(123));
        self::assertFalse($this->subject->isVaultIdentifier([]));

        // Wrong format
        self::assertFalse($this->subject->isVaultIdentifier('invalid'));
        self::assertFalse($this->subject->isVaultIdentifier('not-a-valid-uuid'));
        self::assertFalse($this->subject->isVaultIdentifier('tx_myext__api_key__42')); // Legacy TCA format (rejected)
        self::assertFalse($this->subject->isVaultIdentifier('01937b6e-4b6c-1abc-8def-0123456789ab')); // UUID v1 (not v7)
        self::assertFalse($this->subject->isVaultIdentifier('01937b6e-4b6c-4abc-8def-0123456789ab')); // UUID v4 (not v7)
        self::assertFalse($this->subject->isVaultIdentifier('01937b6e-4b6c-7abc-cdef-0123456789ab')); // Wrong variant
    }

    #[Test]
    public function getVaultFieldsForTableReturnsEmptyForUnknownTable(): void
    {
        $this->tcaSchemaFactory->method('has')->with('tx_nonexistent_table')->willReturn(false);

        $fields = $this->subject->getVaultFieldsForTable('tx_nonexistent_table');

        self::assertSame([], $fields);
    }

    #[Test]
    public function hasVaultFieldsReturnsFalseForTableWithoutVaultFields(): void
    {
        $this->tcaSchemaFactory->method('has')->with('tx_nonexistent_table')->willReturn(false);

        self::assertFalse($this->subject->hasVaultFields('tx_nonexistent_table'));
    }

    #[Test]
    public function resolveFieldsPreservesNonVaultFields(): void
    {
        $data = [
            'title' => 'Test Title',
            'description' => 'Some description',
            'count' => 42,
        ];

        // None of these are vault identifiers, so they should be unchanged
        $result = $this->subject->resolveFields($data, ['title', 'description', 'count']);

        self::assertSame($data, $result);
    }

    #[Test]
    public function resolveFieldsSkipsMissingFields(): void
    {
        $data = [
            'title' => 'Test',
        ];

        // Field doesn't exist, should not throw
        $result = $this->subject->resolveFields($data, ['api_key']);

        self::assertSame($data, $result);
    }

    #[Test]
    #[DataProvider('identifierProvider')]
    public function isVaultIdentifierWithDataProvider(mixed $value, bool $expected): void
    {
        self::assertSame($expected, $this->subject->isVaultIdentifier($value));
    }

    /**
     * @return array<string, array{0: mixed, 1: bool}>
     */
    public static function identifierProvider(): array
    {
        return [
            'valid uuid v7 lowercase' => [self::UUID_V7, true],
            'valid uuid v7 uppercase' => ['01937B6E-4B6C-7ABC-8DEF-0123456789AB', true],
            'valid uuid v7 mixed case' => ['01937b6e-4B6C-7abc-8DEF-0123456789ab', true],
            'empty string' => ['', false],
            'null' => [null, false],
            'integer' => [42, false],
            'array' => [['test'], false],
            'old format table__field__uid' => ['tx_ext__field__1', false],
            'uuid v1' => ['01937b6e-4b6c-1abc-8def-0123456789ab', false],
            'uuid v4' => ['01937b6e-4b6c-4abc-8def-0123456789ab', false],
            'uuid with wrong variant' => ['01937b6e-4b6c-7abc-cdef-0123456789ab', false],
            'too short' => ['01937b6e-4b6c-7abc-8def', false],
            'too long' => ['01937b6e-4b6c-7abc-8def-0123456789ab1', false],
            'missing hyphens' => ['01937b6e4b6c7abc8def0123456789ab', false],
        ];
    }

    #[Test]
    public function getVaultFieldsForTableReturnsVaultSecretFields(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'title' => ['type' => 'input'],
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'api_secret' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $fields = $this->subject->getVaultFieldsForTable('tx_test');

        self::assertSame(['api_key', 'api_secret'], $fields);
    }

    #[Test]
    public function hasVaultFieldsReturnsTrueForTableWithVaultFields(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        self::assertTrue($this->subject->hasVaultFields('tx_test'));
    }

    #[Test]
    public function resolveSingleReturnsNullForNonUuid(): void
    {
        $result = $this->subject->resolve('not-a-uuid');

        self::assertNull($result);
    }

    #[Test]
    public function resolveSingleReturnsNullForEmptyString(): void
    {
        $result = $this->subject->resolve('');

        self::assertNull($result);
    }

    #[Test]
    public function resolveSingleReturnsSecretValue(): void
    {
        $identifier = self::UUID_V7;
        $secretValue = 'my-secret-value';

        $this->vaultService
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secretValue);

        $result = $this->subject->resolve($identifier);

        self::assertSame($secretValue, $result);
    }

    #[Test]
    public function resolveSingleReturnsNullForSecretNotFound(): void
    {
        $identifier = self::UUID_V7;

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new SecretNotFoundException($identifier, 1234567890));

        $result = $this->subject->resolve($identifier);

        self::assertNull($result);
    }

    #[Test]
    public function resolveFieldsResolvesVaultIdentifiers(): void
    {
        $identifier = self::UUID_V7;
        $secretValue = 'my-api-key';

        $this->vaultService
            ->expects(self::once())
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secretValue);

        $data = [
            'title' => 'Test',
            'api_key' => $identifier,
        ];

        $result = $this->subject->resolveFields($data, ['api_key']);

        self::assertSame('Test', $result['title']);
        self::assertSame($secretValue, $result['api_key']);
    }

    #[Test]
    public function resolveFieldsReturnsNullForSecretNotFound(): void
    {
        $identifier = self::UUID_V7;

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new SecretNotFoundException($identifier, 1234567890));

        $data = [
            'api_key' => $identifier,
        ];

        $result = $this->subject->resolveFields($data, ['api_key']);

        self::assertNull($result['api_key']);
    }

    #[Test]
    public function resolveFieldsLogsErrorForVaultException(): void
    {
        $identifier = self::UUID_V7;

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new VaultException(self::DECRYPTION_FAILED, 1234567890));

        $this->logger
            ->expects(self::once())
            ->method('error')
            ->with('Failed to resolve vault field', self::callback(fn (array $context): bool => $context['field'] === 'api_key'
                && $context['identifier'] === $identifier
                && str_contains((string) $context['error'], self::DECRYPTION_FAILED)));

        $data = [
            'api_key' => $identifier,
        ];

        $result = $this->subject->resolveFields($data, ['api_key']);

        self::assertNull($result['api_key']);
    }

    #[Test]
    public function resolveFieldsThrowsWhenThrowOnErrorIsTrue(): void
    {
        $identifier = self::UUID_V7;

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new VaultException(self::DECRYPTION_FAILED, 1234567890));

        $data = [
            'api_key' => $identifier,
        ];

        $this->expectException(VaultException::class);
        $this->subject->resolveFields($data, ['api_key'], true);
    }

    #[Test]
    public function resolveRecordResolvesVaultFields(): void
    {
        $identifier = self::UUID_V7;
        $secretValue = 'resolved-secret';

        $this->mockTcaSchemaForTable('tx_test', [
            'title' => ['type' => 'input'],
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $this->vaultService
            ->expects(self::once())
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secretValue);

        $record = [
            'title' => 'Test Record',
            'api_key' => $identifier,
        ];

        $result = $this->subject->resolveRecord('tx_test', $record);

        self::assertSame('Test Record', $result['title']);
        self::assertSame($secretValue, $result['api_key']);
    }

    #[Test]
    public function resolveRecordReturnsRecordUnchangedIfNoVaultFields(): void
    {
        $this->tcaSchemaFactory->method('has')->with('tx_nonexistent')->willReturn(false);

        $record = [
            'title' => 'Test',
        ];

        $result = $this->subject->resolveRecord('tx_nonexistent', $record);

        self::assertSame($record, $result);
    }

    /**
     * Kill Continue_ mutation on line 57 — `continue` (not `break`) when a
     * field is missing. Second field must still be resolved.
     */
    #[Test]
    public function resolveFieldsContinuesToLaterFieldsWhenEarlierOnesAreMissing(): void
    {
        $identifier = self::UUID_V7;
        $resolved = 'resolved-value';

        $this->vaultService
            ->expects(self::once())
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($resolved);

        // First field is missing → `continue` skips it, second field is a vault identifier.
        $data = [
            'present' => $identifier,
            // 'missing' is NOT set in $data.
        ];

        $result = $this->subject->resolveFields($data, ['missing', 'present']);

        self::assertSame($resolved, $result['present']);
    }

    /**
     * Kill Continue_ mutation on line 63 — `continue` (not `break`) when a
     * value is NOT a vault identifier. Later vault-identifier fields must still
     * be resolved even when an earlier non-vault field appears first.
     */
    #[Test]
    public function resolveFieldsContinuesToLaterFieldsWhenEarlierOnesAreNotVaultIdentifiers(): void
    {
        $identifier = self::UUID_V7;
        $resolved = 'real-secret';

        $this->vaultService
            ->expects(self::once())
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($resolved);

        // Earlier field is a plain string → `continue` skips it, later field is a UUID.
        $data = [
            'title' => 'plain-string-not-a-uuid',
            'api_key' => $identifier,
        ];

        $result = $this->subject->resolveFields($data, ['title', 'api_key']);

        self::assertSame('plain-string-not-a-uuid', $result['title']);
        self::assertSame($resolved, $result['api_key']);
    }

    /**
     * Kill ReturnRemoval on line 97 — resolve() returns null, not void.
     */
    #[Test]
    public function resolveReturnsNullExplicitlyForNonUuid(): void
    {
        // If ReturnRemoval mutation applies, the function would fall through and
        // try to call vaultService->retrieve('not-a-uuid'), which would never match
        // the expectation set below — but more importantly, the return value must
        // be strictly null (not void/undefined).
        $this->vaultService->expects(self::never())->method('retrieve');

        $result = $this->subject->resolve('not-a-uuid');

        self::assertNull($result);
    }

    /**
     * Kill ReturnRemoval on line 122 + ArrayOneItem — resolveRecord must return
     * the untouched record when there are no vault fields for the table.
     */
    #[Test]
    public function resolveRecordReturnsExactRecordWhenNoVaultFields(): void
    {
        $this->tcaSchemaFactory->method('has')->with('tx_nonexistent')->willReturn(false);

        $record = [
            'title' => 'Test',
            'description' => 'description with multiple items',
            'count' => 42,
        ];

        $result = $this->subject->resolveRecord('tx_nonexistent', $record);

        // Exact array match — kills ArrayOneItem (would truncate to 1 item).
        self::assertSame($record, $result);
        self::assertCount(3, $result);
    }

    /**
     * Kill Continue_ on lines 57 and 63 together — mix missing, non-UUID and
     * real UUID fields, verify vault is called exactly once.
     */
    #[Test]
    public function resolveFieldsHandlesMixedFieldsRobustly(): void
    {
        $identifier = self::UUID_V7;

        $this->vaultService
            ->expects(self::once())
            ->method('retrieve')
            ->with($identifier)
            ->willReturn('secret-value');

        $data = [
            'plain' => 'not-a-uuid',
            'vault' => $identifier,
            // 'missing' is absent.
            'another_plain' => 'also-not-a-uuid',
        ];

        $result = $this->subject->resolveFields(
            $data,
            ['missing', 'plain', 'vault', 'another_plain'],
        );

        self::assertSame('not-a-uuid', $result['plain']);
        self::assertSame('secret-value', $result['vault']);
        self::assertSame('also-not-a-uuid', $result['another_plain']);
        self::assertArrayNotHasKey('missing', $result);
    }
}
