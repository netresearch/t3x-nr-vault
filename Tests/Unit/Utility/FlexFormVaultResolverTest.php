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
use Netresearch\NrVault\Utility\FlexFormVaultResolver;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

#[AllowMockObjectsWithoutExpectations]
final class FlexFormVaultResolverTest extends TestCase
{
    private const TEST_UUID = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const DECRYPTION_FAILED_MESSAGE = 'Decryption failed';

    private VaultServiceInterface&MockObject $vaultService;

    private LoggerInterface&MockObject $logger;

    private TcaSchemaFactory&MockObject $tcaSchemaFactory;

    private FlexFormVaultResolver $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->tcaSchemaFactory = $this->createMock(TcaSchemaFactory::class);

        $this->subject = new FlexFormVaultResolver(
            $this->vaultService,
            $this->logger,
            $this->tcaSchemaFactory,
        );
    }

    #[Test]
    public function isVaultIdentifierReturnsTrueForValidUuid(): void
    {
        // FlexForm and TCA vault fields now use UUID v7 format
        self::assertTrue($this->subject->isVaultIdentifier(
            self::TEST_UUID,
        ));
        self::assertTrue($this->subject->isVaultIdentifier(
            '01937b6f-0000-7000-8000-000000000000',
        ));
    }

    #[Test]
    public function isVaultIdentifierReturnsFalseForInvalidIdentifier(): void
    {
        // Empty or non-string
        self::assertFalse($this->subject->isVaultIdentifier(''));
        self::assertFalse($this->subject->isVaultIdentifier(null));
        self::assertFalse($this->subject->isVaultIdentifier(123));

        // Old format (no longer valid)
        self::assertFalse($this->subject->isVaultIdentifier('tx_ext__field__1'));
        self::assertFalse($this->subject->isVaultIdentifier(
            'tt_content__pi_flexform__settings__apiKey__123',
        ));

        // Wrong UUID format
        self::assertFalse($this->subject->isVaultIdentifier('not-a-uuid'));
        self::assertFalse($this->subject->isVaultIdentifier(
            '01937b6e-4b6c-1abc-8def-0123456789ab', // UUID v1, not v7
        ));
        self::assertFalse($this->subject->isVaultIdentifier(
            '01937b6e-4b6c-4abc-8def-0123456789ab', // UUID v4, not v7
        ));
    }

    #[Test]
    public function resolveSettingsPreservesNonVaultFields(): void
    {
        $settings = [
            'title' => 'Test Title',
            'limit' => 10,
            'showTitle' => true,
        ];

        $result = $this->subject->resolveSettings($settings, ['title', 'limit']);

        self::assertSame($settings, $result);
    }

    #[Test]
    public function resolveSettingsSkipsMissingFields(): void
    {
        $settings = [
            'title' => 'Test',
        ];

        $result = $this->subject->resolveSettings($settings, ['apiKey']);

        self::assertSame($settings, $result);
    }

    #[Test]
    public function resolveSettingsResolvesVaultIdentifiers(): void
    {
        $identifier = self::TEST_UUID;
        $secretValue = 'my-secret-api-key';

        $this->vaultService
            ->expects($this->once())
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secretValue);

        $settings = [
            'title' => 'Test',
            'apiKey' => $identifier,
        ];

        $result = $this->subject->resolveSettings($settings, ['apiKey']);

        self::assertSame('Test', $result['title']);
        self::assertSame($secretValue, $result['apiKey']);
    }

    #[Test]
    #[DataProvider('uuidIdentifierProvider')]
    public function isVaultIdentifierWithDataProvider(mixed $value, bool $expected): void
    {
        self::assertSame($expected, $this->subject->isVaultIdentifier($value));
    }

    public static function uuidIdentifierProvider(): array
    {
        return [
            'valid uuid v7 lowercase' => [self::TEST_UUID, true],
            'valid uuid v7 uppercase' => ['01937B6E-4B6C-7ABC-8DEF-0123456789AB', true],
            'valid uuid v7 mixed case' => ['01937b6e-4B6C-7abc-8DEF-0123456789ab', true],
            'empty string' => ['', false],
            'null' => [null, false],
            'integer' => [42, false],
            'array' => [['test'], false],
            'old TCA format (3 parts)' => ['tx_ext__field__1', false],
            'old FlexForm format (5 parts)' => ['tt_content__pi_flexform__settings__apiKey__123', false],
            'uuid v1' => ['01937b6e-4b6c-1abc-8def-0123456789ab', false],
            'uuid v4' => ['01937b6e-4b6c-4abc-8def-0123456789ab', false],
            'uuid with wrong variant' => ['01937b6e-4b6c-7abc-cdef-0123456789ab', false],
            'too short' => ['01937b6e-4b6c-7abc-8def', false],
        ];
    }

    #[Test]
    public function resolveAllResolvesNestedVaultIdentifiers(): void
    {
        $identifier1 = self::TEST_UUID;
        $identifier2 = '01937b6f-0000-7000-8000-000000000000';

        $this->vaultService
            ->expects(self::exactly(2))
            ->method('retrieve')
            ->willReturnMap([
                [$identifier1, 'secret1'],
                [$identifier2, 'secret2'],
            ]);

        $settings = [
            'title' => 'Test',
            'nested' => [
                'apiKey' => $identifier1,
                'deeper' => [
                    'apiSecret' => $identifier2,
                ],
            ],
        ];

        $result = $this->subject->resolveAll($settings);

        self::assertSame('Test', $result['title']);
        self::assertSame('secret1', $result['nested']['apiKey']);
        self::assertSame('secret2', $result['nested']['deeper']['apiSecret']);
    }

    #[Test]
    public function resolveSettingsReturnsNullForSecretNotFound(): void
    {
        $identifier = self::TEST_UUID;

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new SecretNotFoundException($identifier, 1234567890));

        $settings = [
            'apiKey' => $identifier,
        ];

        $result = $this->subject->resolveSettings($settings, ['apiKey']);

        self::assertNull($result['apiKey']);
    }

    #[Test]
    public function resolveSettingsLogsErrorForVaultException(): void
    {
        $identifier = self::TEST_UUID;

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new VaultException(self::DECRYPTION_FAILED_MESSAGE, 1234567890));

        $this->logger
            ->expects(self::once())
            ->method('error')
            ->with('Failed to resolve FlexForm vault field', self::callback(fn (array $context): bool => $context['field'] === 'apiKey'
                && $context['identifier'] === $identifier
                && str_contains((string) $context['error'], self::DECRYPTION_FAILED_MESSAGE)));

        $settings = [
            'apiKey' => $identifier,
        ];

        $result = $this->subject->resolveSettings($settings, ['apiKey']);

        self::assertNull($result['apiKey']);
    }

    #[Test]
    public function resolveSettingsThrowsWhenThrowOnErrorIsTrue(): void
    {
        $identifier = self::TEST_UUID;

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new VaultException(self::DECRYPTION_FAILED_MESSAGE, 1234567890));

        $settings = [
            'apiKey' => $identifier,
        ];

        $this->expectException(VaultException::class);
        $this->subject->resolveSettings($settings, ['apiKey'], true);
    }

    #[Test]
    public function resolveAllLogsErrorForVaultException(): void
    {
        $identifier = self::TEST_UUID;

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new VaultException(self::DECRYPTION_FAILED_MESSAGE, 1234567890));

        $this->logger
            ->expects(self::once())
            ->method('error')
            ->with('Failed to resolve vault identifier', self::callback(fn (array $context): bool => $context['key'] === 'apiKey'
                && $context['identifier'] === $identifier
                && str_contains((string) $context['error'], self::DECRYPTION_FAILED_MESSAGE)));

        $settings = [
            'apiKey' => $identifier,
        ];

        $result = $this->subject->resolveAll($settings);

        self::assertNull($result['apiKey']);
    }

    #[Test]
    public function resolveAllHandlesSecretNotFoundException(): void
    {
        $identifier = self::TEST_UUID;

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new SecretNotFoundException($identifier, 1234567890));

        $settings = [
            'nested' => [
                'apiKey' => $identifier,
            ],
        ];

        $result = $this->subject->resolveAll($settings);

        self::assertNull($result['nested']['apiKey']);
    }
}
