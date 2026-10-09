<?php

/* Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use InvalidArgumentException;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\Fixtures\AlwaysPublicDnsResolver;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientInterface;

#[CoversClass(VaultHttpClient::class)]
final class AdditionalBodyCredentialBoundsFuzzTest extends TestCase
{
    #[Test]
    public function everyFieldLengthAndBindingCountHasTheDocumentedBoundary(): void
    {
        foreach (range(0, 90) as $length) {
            $accepted = false;

            try {
                $this
                    ->client()
                    ->withAdditionalBodyField('id', str_repeat('a', $length));
                $accepted = true;
            } catch (InvalidArgumentException) {
            }

            self::assertSame($length >= 1 && $length <= 64, $accepted);
        }

        foreach (range(0, 12) as $count) {
            $accepted = false;

            try {
                $client = $this->client();
                for ($i = 0; $i < $count; ++$i) {
                    $client = $client->withAdditionalBodyField('id-' . $i, 'field_' . $i);
                }

                $accepted = true;
            } catch (InvalidArgumentException) {
            }

            self::assertSame($count <= 8, $accepted);
        }
    }

    #[Test]
    public function identifierBoundsAndUnsafeFieldCharactersAreRefused(): void
    {
        foreach (range(0, 280) as $length) {
            $accepted = false;

            try {
                $this
                    ->client()
                    ->withAdditionalBodyField(str_repeat('a', $length), 'subject_token');
                $accepted = true;
            } catch (InvalidArgumentException) {
            }

            self::assertSame($length >= 1 && $length <= 255, $accepted);
        }

        foreach (range(0, 127) as $byte) {
            $character = \chr($byte);
            if (preg_match('/[A-Za-z0-9_]/D', $character) === 1) {
                continue;
            }

            try {
                $this
                    ->client()
                    ->withAdditionalBodyField('id', 'field' . $character);
                self::fail('An unsafe field character was accepted.');
            } catch (InvalidArgumentException $exception) {
                self::assertStringContainsString(
                    'field',
                    $exception->getMessage(),
                );
            }
        }

        foreach (array_merge(range(0, 31), [127]) as $byte) {
            try {
                $this
                    ->client()
                    ->withAdditionalBodyField('id' . \chr($byte), 'field');
                self::fail('An identifier control character was accepted.');
            } catch (InvalidArgumentException $exception) {
                self::assertStringContainsString(
                    'identifier',
                    $exception->getMessage(),
                );
            }
        }
    }

    private function client(): VaultHttpClient
    {
        return new VaultHttpClient(
            self::createStub(VaultServiceInterface::class),
            self::createStub(AuditLogServiceInterface::class),
            self::createStub(ClientInterface::class),
            secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
        );
    }
}
