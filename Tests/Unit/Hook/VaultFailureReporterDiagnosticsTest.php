<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Error;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Hook\VaultFailureReporter;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Throwable;

#[CoversClass(VaultFailureReporter::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultFailureReporterDiagnosticsTest extends TestCase
{
    /**
     * @param class-string<Throwable> $loggerFailureClass
     */
    #[Test]
    #[DataProvider('diagnosticFailures')]
    public function writerFailurePreservesCauseIndependentUserDiagnostic(
        string $loggerFailureClass,
        bool $denied,
    ): void {
        $identifier = 'synthetic-foreign-record';
        $cause = $denied ? AccessDeniedException::forIdentifier(
            $identifier,
            'synthetic private denial',
        ) : SecretNotFoundException::forIdentifier($identifier);
        $writerFailure = new $loggerFailureClass('synthetic private writer failure');
        $attempts = [];
        $logger = self::createMock(LoggerInterface::class);
        $logger
            ->method('error')
            ->willReturnCallback(
                static function (
                    string $message,
                    array $context,
                ) use (&$attempts, $writerFailure): never {
                    $attempts[] = [$message, $context];

                    throw $writerFailure;
                },
            );
        $subject = new VaultFailureReporter($logger);
        $returned = null;
        $escaped = null;

        try {
            $returned = $subject->report(
                $cause,
                [
                    'identifier' => $identifier,
                    'operation' => 'synthetic_diagnostic_probe',
                ],
            );
        } catch (Throwable $error) {
            $escaped = $error;
        }

        self::assertNull(
            $escaped,
            'A failed diagnostic writer must not replace the operation failure or interrupt its recovery.',
        );
        self::assertIsString($returned);
        self::assertCount(
            1,
            $attempts,
            'A failing diagnostic writer is attempted once, without recursive fallback logging.',
        );
        self::assertSame('Vault operation failed', $attempts[0][0]);
        self::assertSame($cause::class, $attempts[0][1]['exceptionClass']);
        self::assertSame($identifier, $attempts[0][1]['identifier']);
        self::assertMatchesRegularExpression('/\b[0-9a-f]{16}\b/', $returned);
        self::assertIsString($attempts[0][1]['reference']);
        self::assertStringContainsString(
            $attempts[0][1]['reference'],
            $returned,
        );
        self::assertStringNotContainsString($identifier, $returned);
        self::assertStringNotContainsString(
            'synthetic private denial',
            $returned,
        );
        self::assertStringNotContainsString(
            'synthetic private writer failure',
            $returned,
        );
        self::assertStringNotContainsString('not found', $returned);
    }

    /**
     * @return iterable<string, array{class-string<Throwable>, bool}>
     */
    public static function diagnosticFailures(): iterable
    {
        foreach ([RuntimeException::class, Error::class] as $class) {
            foreach ([false, true] as $denied) {
                yield $class . '-' . (int) $denied => [$class, $denied];
            }
        }
    }
}
