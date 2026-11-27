<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage\Aws;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Storage\Aws\AwsClientFactory;
use Netresearch\NrVault\Storage\Aws\AwsSecretsManagerStore;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\AbstractLogger;
use Stringable;

use function array_slice;
use function count;
use function is_string;

/**
 * The rollback of a write against a stateful fake of one secret (#567). The
 * rollback moves AWSCURRENT back to the version the write replaced with a
 * conditional UpdateSecretVersionStage, so a writer that lands between the
 * write and the rollback keeps its value. The fake follows the AWS API
 * reference; the behaviour is not verified against AWS itself.
 */
#[CoversClass(AwsSecretsManagerStore::class)]
#[AllowMockObjectsWithoutExpectations]
final class AwsSecretsManagerStoreRestoreTest extends TestCase
{
    use AccessKeyFixtures;

    private const SECRET_NAME = 'typo3/api_key';

    /** @var list<array{string, string, array<array-key, mixed>}> */
    private array $logged = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->logged = [];
        putenv('NR_VAULT_AWS_ACCESS_KEY_ID=' . self::akia('UNITTESTKEY00001'));
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY=unit-test-secret-access-key-value');
    }

    protected function tearDown(): void
    {
        putenv('NR_VAULT_AWS_ACCESS_KEY_ID');
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY');

        parent::tearDown();
    }

    /**
     * AWS does not document the error of a mismatching RemoveFromVersionId;
     * moto answers InvalidParameterException. The store must not depend on it.
     *
     * @return array<string, array{string}>
     */
    public static function mismatchCodeProvider(): array
    {
        return [
            'InvalidParameterException (moto)' => ['InvalidParameterException'],
            'InvalidRequestException'          => ['InvalidRequestException'],
        ];
    }

    #[Test]
    #[DataProvider('mismatchCodeProvider')]
    public function aWriterLandingBetweenTheWriteAndTheRollbackKeepsItsValue(string $mismatchCode): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME, $mismatchCode);
        $previous = $secret->seed(['v' => 'previous']);
        $store    = $this->store($secret);

        $ours = $store->write('api_key', ['v' => 'ours']);
        $secret->concurrentPutBeforeNextWrite(['v' => 'concurrent']);

        self::assertFalse($store->restoreIfCurrent('api_key', ['v' => 'previous'], $ours, $previous), 'somebody wrote after our version');
        self::assertSame(['v' => 'concurrent'], $secret->currentData(), 'the concurrent value is not overwritten');
        self::assertSame([], $this->warnings(), 'a skipped rollback is reported by the adapter, not as a failure here');
    }

    #[Test]
    public function aRollbackMovesAwsCurrentBackToTheVersionTheWriteReplaced(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $store    = $this->store($secret);

        $ours   = $store->write('api_key', ['v' => 'ours']);
        $before = count($secret->targets());

        self::assertTrue($store->restoreIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

        self::assertSame(['UpdateSecretVersionStage'], array_slice($secret->targets(), $before), 'one conditional request, no read and no put');
        self::assertSame($previous, $secret->versionLabelled('AWSCURRENT'));
        self::assertSame($ours, $secret->versionLabelled('AWSPREVIOUS'));
        self::assertSame(['v' => 'previous'], $secret->currentData());
        self::assertSame(2, $secret->versionCount(), 'no version was added');
        self::assertSame([], $this->warnings());
    }

    #[Test]
    public function withoutThePermissionTheRollbackFallsBackToReadThenWriteAndNamesThePermission(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $secret->deny('UpdateSecretVersionStage');
        $store = $this->store($secret);

        $ours   = $store->write('api_key', ['v' => 'ours']);
        $before = count($secret->targets());

        self::assertTrue($store->restoreIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

        self::assertSame(['UpdateSecretVersionStage', 'GetSecretValue', 'PutSecretValue'], array_slice($secret->targets(), $before));
        self::assertSame(['v' => 'previous'], $secret->currentData(), 'the previous value is back, as a new version');
        self::assertSame(3, $secret->versionCount());
        self::assertCount(1, $this->warnings());
        self::assertStringContainsString('refused UpdateSecretVersionStage (AccessDeniedException)', $this->warnings()[0]);
        self::assertStringContainsString('grant secretsmanager:UpdateSecretVersionStage', $this->warnings()[0]);
    }

    #[Test]
    public function withoutThePermissionAConcurrentWriterSeenByTheReadIsStillNotOverwritten(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $secret->deny('UpdateSecretVersionStage');
        $store = $this->store($secret);

        $ours = $store->write('api_key', ['v' => 'ours']);
        $secret->seed(['v' => 'concurrent']);

        self::assertFalse($store->restoreIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));
        self::assertSame(['v' => 'concurrent'], $secret->currentData());
    }

    #[Test]
    public function aMoveThatFailsWhileTheSecretIsStillAtOurVersionFallsBackToReadThenWrite(): void
    {
        $secret = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $secret->seed(['v' => 'previous']);

        $store = $this->store($secret);

        $ours   = $store->write('api_key', ['v' => 'ours']);
        $before = count($secret->targets());

        // The version to move back to is gone, so the move fails although
        // AWSCURRENT is still on our version.
        self::assertTrue($store->restoreIfCurrent('api_key', ['v' => 'previous'], $ours, '99999999-0000-4000-8000-999999999999'));

        self::assertSame(['UpdateSecretVersionStage', 'GetSecretValue', 'PutSecretValue'], array_slice($secret->targets(), $before));
        self::assertSame(['v' => 'previous'], $secret->currentData());
        self::assertCount(1, $this->warnings());
        self::assertStringContainsString('InvalidParameterException', $this->warnings()[0]);
    }

    #[Test]
    public function aMoveThatAppliedButWhoseAnswerWasLostCountsAsApplied(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $store    = $this->store($secret);

        $ours = $store->write('api_key', ['v' => 'ours']);
        $secret->applyThenFail('UpdateSecretVersionStage');
        $before = count($secret->targets());

        // The SDK retries the 500 once; the retry is refused because
        // AWSCURRENT is no longer on our version.
        self::assertTrue($store->restoreIfCurrent('api_key', ['v' => 'previous'], $ours, $previous), 'the rollback applied');

        self::assertSame(['UpdateSecretVersionStage', 'UpdateSecretVersionStage', 'GetSecretValue', 'GetSecretValue', 'GetSecretValue'], array_slice($secret->targets(), $before), 'no put after the move applied');
        self::assertSame($previous, $secret->versionLabelled('AWSCURRENT'));
        self::assertSame(2, $secret->versionCount(), 'nothing was put back on top');
        self::assertSame([], $this->warnings());
    }

    #[Test]
    public function withoutThePreviousVersionIdTheRollbackReadsThenWrites(): void
    {
        $secret = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $secret->seed(['v' => 'previous']);

        $store = $this->store($secret);

        $ours   = $store->write('api_key', ['v' => 'ours']);
        $before = count($secret->targets());

        self::assertTrue($store->restoreIfCurrent('api_key', ['v' => 'previous'], $ours));
        self::assertSame(['GetSecretValue', 'PutSecretValue'], array_slice($secret->targets(), $before));
        self::assertSame([], $this->warnings());
    }

    #[Test]
    public function readWithVersionReturnsTheDocumentAndTheVersionFromOneResponse(): void
    {
        $secret  = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $version = $secret->seed(['v' => 'stored']);

        self::assertSame(['data' => ['v' => 'stored'], 'versionId' => $version], $this->store($secret)->readWithVersion('api_key'));
        self::assertSame(['GetSecretValue'], $secret->targets());
    }

    #[Test]
    public function readWithVersionOfAMissingSecretIsNull(): void
    {
        $secret = new FakeSecretsManagerSecret(self::SECRET_NAME);

        self::assertNull($this->store($secret)->readWithVersion('api_key'));
    }

    /**
     * @param array<array-key, mixed> $context
     */
    public function record(string $level, string $message, array $context): void
    {
        $this->logged[] = [$level, $message, $context];
    }

    /**
     * @return list<string>
     */
    private function warnings(): array
    {
        $warnings = [];
        foreach ($this->logged as [$level, $message, $context]) {
            if ($level === 'warning') {
                $code       = $context['code'] ?? '';
                $warnings[] = strtr($message, ['{code}' => is_string($code) ? $code : '']);
            }
        }

        return $warnings;
    }

    private function store(FakeSecretsManagerSecret $secret): AwsSecretsManagerStore
    {
        // Like SecureHttpClientFactory: statuses are responses, not exceptions.
        $client = new Client(['handler' => HandlerStack::create($secret), 'http_errors' => false]);

        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('getAwsConfig')->willReturn(new AwsSecretsConfig(region: 'eu-central-1', secretPrefix: 'typo3/'));

        $logger = new class ($this) extends AbstractLogger {
            public function __construct(private readonly AwsSecretsManagerStoreRestoreTest $test) {}

            public function log($level, string|Stringable $message, array $context = []): void
            {
                $this->test->record(is_string($level) ? $level : '', (string) $message, $context);
            }
        };

        return new AwsSecretsManagerStore(
            $configuration,
            new AwsClientFactory($configuration, $client),
            null,
            $logger,
        );
    }
}
