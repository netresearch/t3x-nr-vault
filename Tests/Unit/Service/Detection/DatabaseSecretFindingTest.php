<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Detection;

use Netresearch\NrVault\Service\Detection\DatabaseSecretFinding;
use Netresearch\NrVault\Service\Detection\SecretFinding;
use Netresearch\NrVault\Service\Detection\Severity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(DatabaseSecretFinding::class)]
final class DatabaseSecretFindingTest extends TestCase
{
    #[Test]
    public function implementsSecretFinding(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'be_users',
            column: 'api_key',
            recordCount: 10,
            plaintextCount: 5,
            severity: Severity::High,
        );

        self::assertInstanceOf(SecretFinding::class, $finding);
    }

    #[Test]
    public function constructorSetsProperties(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'tx_extension_table',
            column: 'secret_field',
            recordCount: 100,
            plaintextCount: 50,
            severity: Severity::Critical,
            patterns: ['Stripe live key', 'AWS Key'],
        );

        self::assertEquals('tx_extension_table', $finding->table);
        self::assertEquals('secret_field', $finding->column);
        self::assertEquals(100, $finding->recordCount);
        self::assertEquals(50, $finding->plaintextCount);
        self::assertEquals(Severity::Critical, $finding->severity);
        self::assertEquals(['Stripe live key', 'AWS Key'], $finding->patterns);
    }

    #[Test]
    public function getKeyReturnsFormattedKey(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'be_users',
            column: 'api_key',
            recordCount: 10,
            plaintextCount: 5,
            severity: Severity::High,
        );

        self::assertEquals('database:be_users.api_key', $finding->getKey());
    }

    #[Test]
    public function getSourceReturnsDatabase(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'table',
            column: 'column',
            recordCount: 0,
            plaintextCount: 0,
            severity: Severity::Low,
        );

        self::assertEquals('database', $finding->getSource());
    }

    #[Test]
    public function getSeverityReturnsSeverity(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'table',
            column: 'column',
            recordCount: 0,
            plaintextCount: 0,
            severity: Severity::Medium,
        );

        self::assertEquals(Severity::Medium, $finding->getSeverity());
    }

    #[Test]
    public function getPatternsReturnsPatterns(): void
    {
        $patterns = ['Pattern 1', 'Pattern 2'];
        $finding  = new DatabaseSecretFinding(
            table: 'table',
            column: 'column',
            recordCount: 0,
            plaintextCount: 0,
            severity: Severity::Low,
            patterns: $patterns,
        );

        self::assertEquals($patterns, $finding->getPatterns());
    }

    #[Test]
    public function patternsDefaultToEmptyArray(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'table',
            column: 'column',
            recordCount: 0,
            plaintextCount: 0,
            severity: Severity::Low,
        );

        self::assertEquals([], $finding->getPatterns());
    }

    #[Test]
    public function getDetailsReturnsFormattedCounts(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'table',
            column: 'column',
            recordCount: 100,
            plaintextCount: 25,
            severity: Severity::High,
        );

        self::assertEquals('100 records (25 plaintext)', $finding->getDetails());
    }

    #[Test]
    public function jsonSerializeReturnsCorrectStructure(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'be_users',
            column: 'api_key',
            recordCount: 50,
            plaintextCount: 10,
            severity: Severity::High,
            patterns: ['API Key'],
        );

        $json = $finding->jsonSerialize();

        self::assertEquals([
            'source'         => 'database',
            'table'          => 'be_users',
            'column'         => 'api_key',
            'count'          => 50,
            'plaintextCount' => 10,
            'severity'       => 'high',
            'patterns'       => ['API Key'],
        ], $json);
    }

    #[Test]
    public function canBeJsonEncoded(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'test',
            column: 'col',
            recordCount: 5,
            plaintextCount: 2,
            severity: Severity::Low,
        );

        $json = json_encode($finding);

        self::assertJson($json);
        self::assertStringContainsString('"source":"database"', $json);
        self::assertStringContainsString('"table":"test"', $json);
    }
}
