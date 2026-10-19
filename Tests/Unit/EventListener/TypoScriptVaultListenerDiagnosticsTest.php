<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\EventListener;

use Error;
use GuzzleHttp\Psr7\ServerRequest;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\EventListener\TypoScriptVaultListener;
use Netresearch\NrVault\Security\FrontendPlaceholderPolicy;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\AbstractLogger;
use RuntimeException;
use Stringable;
use Throwable;
use TYPO3\CMS\Core\Core\ApplicationContext;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;
use TYPO3\CMS\Frontend\ContentObject\Event\AfterStdWrapFunctionsExecutedEvent;

#[CoversClass(TypoScriptVaultListener::class)]
#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
final class TypoScriptVaultListenerDiagnosticsTest extends TestCase
{
    #[Test]
    #[DataProvider('diagnosticCases')]
    public function optionalDiagnosticsPreserveOutputAndAttemptTheExpectedRecord(
        string $path,
        string $context,
        string $fault,
    ): void {
        $project = \dirname(__DIR__, 3);
        // Core documents initialize() for tests. An isolated child models a web
        // SAPI without leaking its application context or CLI flag to the suite.
        /** @phpstan-ignore staticMethod.internal */
        Environment::initialize(
            new ApplicationContext($context),
            false,
            true,
            $project,
            $project . '/.Build/web',
            $project . '/.Build/var',
            $project . '/.Build/config',
            $project . '/.Build/web/index.php',
            'UNIX',
        );
        $failure = match ($fault) {
            'runtime' => new RuntimeException('diagnostic sink rejected record', 1785000101),
            'error' => new Error('diagnostic sink rejected record', 1785000102),
            default => null,
        };
        $logger = new class ($failure) extends AbstractLogger {
            /** @var list<array{0: mixed, 1: string, 2: array<array-key, mixed>}> */
            public array $records = [];

            public function __construct(private readonly ?Throwable $failure) {}

            public function log(
                $level,
                string|Stringable $message,
                array $context = [],
            ): void {
                $this->records[] = [$level, (string) $message, $context];
                if ($this->failure instanceof Throwable) {
                    throw $this->failure;
                }
            }
        };
        $config = self::createStub(ExtensionConfigurationInterface::class);
        $config
            ->method('isFrontendPlaceholderLegacyCliEnabled')
            ->willReturn(false);
        $policy = new FrontendPlaceholderPolicy($config);
        $request = (new ServerRequest('GET', 'https://example.com/'))->withAttribute(
            'applicationType',
            1,
        );
        if ($path === 'warning') {
            $policy->allowIdentifier('missing_key', $request);
            $policy->allowIdentifier('public_key', $request);
        }

        /** @var list<string> $reads */
        $reads = [];
        $vault = $this->createMock(VaultServiceInterface::class);
        $vault->expects(self::never())->method('retrieve');
        $vault
            ->method('retrieveForFrontend')
            ->willReturnCallback(
                static function (string $identifier) use (&$reads): string {
                    $reads[] = $identifier;
                    if ($identifier === 'public_key') {
                        return 'synthetic-visible-value';
                    }

                    throw new RuntimeException('missing actual secret', 1785000103);
                },
            );
        $renderer = self::createStub(ContentObjectRenderer::class);
        $renderer->method('getRequest')->willReturn($request);
        $original = '%vault(missing_key)% and %vault(missing_key)% then %vault(public_key)%';
        $event = new AfterStdWrapFunctionsExecutedEvent($original, [], $renderer);
        $listener = new TypoScriptVaultListener($vault, $logger, $policy);
        $caught = null;

        try {
            $listener($event);
        } catch (Throwable $unexpected) {
            $caught = $unexpected;
        }

        self::assertNull(
            $caught,
            'Optional diagnostics must not replace frontend output.',
        );
        self::assertSame(
            $path === 'warning' ? '%vault(missing_key)% and %vault(missing_key)% then synthetic-visible-value' : $original,
            $event->getContent(),
        );
        self::assertSame(
            $path === 'warning' ? ['missing_key', 'missing_key', 'public_key'] : [],
            $reads,
        );
        $attemptsRecord = $path === 'warning' || $context === 'Development';
        self::assertCount(
            $attemptsRecord ? 1 : 0,
            $logger->records,
            'Strict web requests attempt at most one diagnostic, and Production skips notices.',
        );
        self::assertSame(!$attemptsRecord, $policy->claimLogSlot($renderer));
        if (!$attemptsRecord) {
            return;
        }

        self::assertSame($path, $logger->records[0][0]);
        self::assertSame('missing_key', $logger->records[0][2]['identifier']);
        if ($path === 'warning') {
            self::assertSame(
                'Failed to resolve vault reference in TypoScript',
                $logger->records[0][1],
            );
            self::assertSame(
                'missing actual secret',
                $logger->records[0][2]['error'],
            );
        } else {
            self::assertStringContainsString(
                'not published for frontend resolution',
                $logger->records[0][1],
            );
            self::assertArrayNotHasKey('error', $logger->records[0][2]);
        }

        self::assertStringNotContainsString(
            'synthetic-visible-value',
            json_encode($logger->records, JSON_THROW_ON_ERROR),
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function diagnosticCases(): iterable
    {
        foreach (['warning', 'notice'] as $path) {
            foreach (['Development', 'Production'] as $context) {
                foreach (['healthy', 'runtime', 'error'] as $fault) {
                    yield $path . '/' . $context . '/' . $fault => [$path, $context, $fault];
                }
            }
        }
    }
}
