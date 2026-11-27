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
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
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

    private const OTHER_VERSION = '77777777-0000-4000-8000-777777777777';

    /** @var list<array{string, string, array<array-key, mixed>}> */
    private array $logged = [];

    /** @var list<int> */
    private array $sleeps = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->logged = [];
        $this->sleeps = [];
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

        self::assertFalse($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous), 'somebody wrote after our version');
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

        self::assertTrue($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

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

        self::assertTrue($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

        self::assertSame(['UpdateSecretVersionStage', 'GetSecretValue', 'PutSecretValue'], array_slice($secret->targets(), $before));
        self::assertSame(['v' => 'previous'], $secret->currentData(), 'the previous value is back, as a new version');
        self::assertSame(3, $secret->versionCount());
        self::assertCount(1, $this->warnings());
        self::assertStringContainsString('refused UpdateSecretVersionStage (AccessDeniedException); grant secretsmanager:UpdateSecretVersionStage', $this->warnings()[0]);
        self::assertSame(['api_key'], $this->warningSecrets());
    }

    #[Test]
    public function aBare403IsTakenAsTheMissingPermission(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $secret->denyWithBare403('UpdateSecretVersionStage');
        $store = $this->store($secret);

        $ours   = $store->write('api_key', ['v' => 'ours']);
        $before = count($secret->targets());

        self::assertTrue($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

        self::assertSame(['UpdateSecretVersionStage', 'GetSecretValue', 'PutSecretValue'], array_slice($secret->targets(), $before));
        self::assertCount(1, $this->warnings());
        self::assertStringContainsString('(HTTP 403); grant secretsmanager:UpdateSecretVersionStage', $this->warnings()[0]);
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

        self::assertFalse($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));
        self::assertSame(['v' => 'concurrent'], $secret->currentData());
    }

    #[Test]
    public function aMoveThatFailsWhileTheSecretIsStillOursIsTriedOnceMore(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $store    = $this->store($secret);

        $ours = $store->write('api_key', ['v' => 'ours']);
        $secret->failNext('UpdateSecretVersionStage', 'InvalidRequestException');
        $before = count($secret->targets());

        self::assertTrue($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

        self::assertSame(['UpdateSecretVersionStage', 'GetSecretValue', 'UpdateSecretVersionStage'], array_slice($secret->targets(), $before), 'moved, not written');
        self::assertSame($previous, $secret->versionLabelled('AWSCURRENT'));
        self::assertSame(2, $secret->versionCount());
        self::assertSame([], $this->warnings());
    }

    #[Test]
    public function aMoveThatKeepsFailingWhileTheSecretIsStillOursIsAFailedRollbackWithoutAWrite(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $store    = $this->store($secret);

        $ours = $store->write('api_key', ['v' => 'ours']);
        $secret->failNext('UpdateSecretVersionStage', 'InvalidRequestException', 'InvalidRequestException');
        $before = count($secret->targets());

        try {
            $store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous);
            self::fail('A rollback that cannot apply while our version is current must be reported.');
        } catch (AwsSecretsManagerException $e) {
            self::assertStringContainsString('InvalidRequestException', $e->getMessage());
        }

        self::assertSame(['UpdateSecretVersionStage', 'GetSecretValue', 'UpdateSecretVersionStage', 'GetSecretValue'], array_slice($secret->targets(), $before));
        self::assertSame($ours, $secret->versionLabelled('AWSCURRENT'));
        self::assertSame(2, $secret->versionCount(), 'nothing was written');
    }

    #[Test]
    public function aRetryRefusedForLackOfThePermissionFallsBackToReadThenWrite(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $store    = $this->store($secret);

        $ours = $store->write('api_key', ['v' => 'ours']);
        $secret->failNext('UpdateSecretVersionStage', 'InvalidRequestException', 'AccessDeniedException');
        $before = count($secret->targets());

        self::assertTrue($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

        self::assertSame(['UpdateSecretVersionStage', 'GetSecretValue', 'UpdateSecretVersionStage', 'GetSecretValue', 'PutSecretValue'], array_slice($secret->targets(), $before));
        self::assertSame(['v' => 'previous'], $secret->currentData());
        self::assertCount(1, $this->warnings());
        self::assertStringContainsString('grant secretsmanager:UpdateSecretVersionStage', $this->warnings()[0]);
    }

    #[Test]
    public function aLaggingReadThatShowsTheReplacedVersionIsConfirmedBeforeTheRollbackCounts(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $store    = $this->store($secret);

        $ours = $store->write('api_key', ['v' => 'ours']);
        // The move fails without applying, and the reads lag behind our write.
        $secret->failNext('UpdateSecretVersionStage', 'InvalidRequestException');
        $secret->staleReads($previous, $previous, $previous);

        self::assertTrue($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

        self::assertSame($previous, $secret->versionLabelled('AWSCURRENT'), 'the confirming read showed our version, so the move was tried again');
        self::assertSame(2, $secret->versionCount());
        self::assertSame([150_000, 150_000, 150_000], $this->sleeps, 'the delays go through the injected sleep');
    }

    #[Test]
    public function aLaggingReadThatShowsOurVersionAfterAnAppliedMoveDoesNotWriteAgain(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $store    = $this->store($secret);

        $ours = $store->write('api_key', ['v' => 'ours']);
        // The move applies but its answer is lost; the SDK's retry is refused,
        // and the first read has not caught up with the move.
        $secret->applyThenFail('UpdateSecretVersionStage');
        $secret->staleReads($ours);

        $before = count($secret->targets());

        self::assertTrue($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

        self::assertNotContains('PutSecretValue', array_slice($secret->targets(), $before));
        self::assertSame($previous, $secret->versionLabelled('AWSCURRENT'));
        self::assertSame(2, $secret->versionCount(), 'nothing was put back on top');
    }

    #[Test]
    public function anOutcomeThatCannotBeConfirmedIsReportedWithTheSecret(): void
    {
        $secret   = new FakeSecretsManagerSecret(self::SECRET_NAME);
        $previous = $secret->seed(['v' => 'previous']);
        $store    = $this->store($secret);

        $ours = $store->write('api_key', ['v' => 'ours']);
        $secret->failNext('UpdateSecretVersionStage', 'InvalidRequestException');
        $secret->staleReads($previous, $previous, $previous, self::OTHER_VERSION);

        self::assertFalse($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous));

        self::assertCount(1, $this->warnings());
        self::assertStringContainsString('unconfirmed', $this->warnings()[0]);
        self::assertSame(['api_key'], $this->warningSecrets());
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
        self::assertTrue($store->restoreToVersionIfCurrent('api_key', ['v' => 'previous'], $ours, $previous), 'the rollback applied');

        self::assertNotContains('PutSecretValue', array_slice($secret->targets(), $before));
        self::assertSame($previous, $secret->versionLabelled('AWSCURRENT'));
        self::assertSame(2, $secret->versionCount(), 'nothing was put back on top');
        self::assertSame([], $this->warnings());
    }

    #[Test]
    public function restoreIfCurrentReadsThenWrites(): void
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

    /**
     * @return list<mixed>
     */
    private function warningSecrets(): array
    {
        $secrets = [];
        foreach ($this->logged as [$level, , $context]) {
            if ($level === 'warning') {
                $secrets[] = $context['secret'] ?? null;
            }
        }

        return $secrets;
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
            function (int $microseconds): void {
                $this->sleeps[] = $microseconds;
            },
            $logger,
        );
    }
}
