<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage\Aws;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
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
use Psr\Http\Message\RequestInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * The store against the real SDK, with the HTTP exchange scripted. The client
 * is built the way production builds it: `http_errors` off, as the hardened
 * factory does, so a rejected request only reaches the store as an error when
 * the SDK is told to treat statuses as errors.
 */
#[CoversClass(AwsSecretsManagerStore::class)]
#[AllowMockObjectsWithoutExpectations]
final class AwsSecretsManagerStoreTest extends TestCase
{
    use AccessKeyFixtures;

    private const SECRET_KEY = 'unit-test-secret-access-key-value';

    /** @var list<RequestInterface> */
    private array $requests = [];

    /** @var list<int> */
    private array $sleeps = [];

    private LoggerInterface $logger;

    protected function setUp(): void
    {
        parent::setUp();

        $this->requests = [];
        $this->sleeps   = [];
        $this->logger   = self::createStub(LoggerInterface::class);
        putenv('NR_VAULT_AWS_ACCESS_KEY_ID=' . self::akia('UNITTESTKEY00001'));
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY=' . self::SECRET_KEY);
    }

    protected function tearDown(): void
    {
        putenv('NR_VAULT_AWS_ACCESS_KEY_ID');
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY');

        parent::tearDown();
    }

    #[Test]
    public function readReturnsTheStoredFieldsAndSignsWithTheConfiguredKey(): void
    {
        $store = $this->store($this->json(200, ['Name' => 'typo3/api_key', 'SecretString' => '{"k":"v"}']));

        self::assertSame(['k' => 'v'], $store->read('api_key'));

        self::assertSame('secretsmanager.GetSecretValue', $this->request(0)->getHeaderLine('X-Amz-Target'));
        self::assertSame(['SecretId' => 'typo3/api_key'], $this->bodyOf(0));
        self::assertStringContainsString('Credential=' . self::akia('UNITTESTKEY00001') . '/', $this->request(0)->getHeaderLine('Authorization'));
        self::assertStringNotContainsString(self::SECRET_KEY, $this->request(0)->getHeaderLine('Authorization'));
    }

    #[Test]
    public function readReturnsNullForASecretThatDoesNotExist(): void
    {
        $store = $this->store($this->awsError(400, 'ResourceNotFoundException'));

        self::assertNull($store->read('api_key'));
    }

    #[Test]
    public function aRejectedRequestIsAnErrorEvenThoughTheHardenedClientReportsStatusesAsResponses(): void
    {
        $store = $this->store(new Response(403, [], '<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>'));

        try {
            $store->read('api_key');
            self::fail('A 403 must not read as an empty success.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500006, $e->getCode());
            self::assertStringContainsString('HTTP 403', $e->getMessage());
        }
    }

    #[Test]
    public function aRejectionNamesTheOperationTheStatusAndTheAwsErrorCodeOnly(): void
    {
        $store = $this->store(new Response(400, [], json_encode([
            '__type'  => 'AccessDeniedException',
            'Message' => 'User arn:aws:iam::123456789012:user/secret-name is not authorized; token ABCDEF-LEAK',
        ], JSON_THROW_ON_ERROR)));

        try {
            $store->write('api_key', ['k' => 'sensitive-payload']);
            self::fail('A rejected write must throw.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame('AWS Secrets Manager write was rejected with HTTP 400 (AccessDeniedException).', $e->getMessage());
            self::assertNotInstanceOf(Throwable::class, $e->getPrevious(), 'the SDK exception holds the request and is not chained');
            self::assertStringNotContainsString('sensitive-payload', $e->getTraceAsString());
        }
    }

    #[Test]
    public function readRefusesAValueThatIsNotAJsonObject(): void
    {
        foreach (['not json', '"a string"', '7', ''] as $stored) {
            $store = $this->store($this->json(200, ['Name' => 'typo3/api_key', 'SecretString' => $stored]));

            try {
                $store->read('api_key');
                self::fail(sprintf('"%s" must be refused.', $stored));
            } catch (AwsSecretsManagerException $e) {
                self::assertSame(1794500008, $e->getCode());
            }
        }
    }

    #[Test]
    public function readRefusesASecretThatHoldsBinaryInsteadOfAString(): void
    {
        $store = $this->store($this->json(200, ['Name' => 'typo3/api_key', 'SecretBinary' => base64_encode('x')]));

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500008);

        $store->read('api_key');
    }

    #[Test]
    public function writeAddsAVersionToTheExistingSecret(): void
    {
        $store = $this->store($this->json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v1']));

        $store->write('api_key', ['k' => 'v']);

        self::assertCount(1, $this->requests);
        self::assertSame('secretsmanager.PutSecretValue', $this->request(0)->getHeaderLine('X-Amz-Target'));
        self::assertSame('typo3/api_key', $this->bodyOf(0)['SecretId']);
        self::assertSame('{"k":"v"}', $this->bodyOf(0)['SecretString']);
    }

    #[Test]
    public function writeCreatesTheSecretWhenAwsSaysItDoesNotExist(): void
    {
        $store = $this->store(
            $this->awsError(400, 'ResourceNotFoundException'),
            $this->json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v1']),
        );

        $store->write('api_key', ['k' => 'v']);

        self::assertCount(2, $this->requests);
        self::assertSame('secretsmanager.CreateSecret', $this->request(1)->getHeaderLine('X-Amz-Target'));
        self::assertSame('typo3/api_key', $this->bodyOf(1)['Name']);
        self::assertSame('{"k":"v"}', $this->bodyOf(1)['SecretString']);
    }

    #[Test]
    public function writeRaisesTheConflictWhenAConcurrentCreateWonInBetween(): void
    {
        $store = $this->store(
            $this->awsError(400, 'ResourceNotFoundException'),
            $this->awsError(400, 'ResourceExistsException'),
            $this->json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v2']),
        );

        try {
            $store->write('api_key', ['k' => 'v']);
            self::fail('A secret another writer created must not be written into.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500012, $e->getCode());
        }

        self::assertSame(
            ['PutSecretValue', 'CreateSecret'],
            array_map(static fn (RequestInterface $request): string => substr($request->getHeaderLine('X-Amz-Target'), strlen('secretsmanager.')), $this->requests),
        );
    }

    #[Test]
    public function writeDoesNotCreateAfterADifferentRejection(): void
    {
        $store = $this->store($this->awsError(400, 'AccessDeniedException'));

        try {
            $store->write('api_key', ['k' => 'v']);
            self::fail('A rejected write must throw.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500006, $e->getCode());
        }

        self::assertCount(1, $this->requests, 'a rejection is not a missing secret');
    }

    #[Test]
    public function createCreatesTheSecretAndReturnsItsVersionId(): void
    {
        $store = $this->store(self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-created']));

        self::assertSame('v-created', $store->create('api_key', ['k' => 'v']));

        self::assertCount(1, $this->requests);
        self::assertSame('secretsmanager.CreateSecret', $this->requests[0]->getHeaderLine('X-Amz-Target'));
    }

    #[Test]
    public function createRefusesAnExistingNameWithoutWritingAnything(): void
    {
        $store = $this->store(self::awsError(400, 'ResourceExistsException'));

        try {
            $store->create('api_key', ['k' => 'v']);
            self::fail('An existing name must be refused.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500012, $e->getCode());
        }

        self::assertCount(1, $this->requests);
    }

    #[Test]
    public function createReportsAnotherRejection(): void
    {
        $store = $this->store(self::awsError(400, 'AccessDeniedException'));

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500006);

        $store->create('api_key', ['k' => 'v']);
    }

    #[Test]
    public function writeReturnsTheVersionIdItCreated(): void
    {
        $store = $this->store(
            self::awsError(400, 'ResourceNotFoundException'),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-first']),
        );

        self::assertSame('v-first', $store->write('api_key', ['k' => 'v']));
    }

    #[Test]
    public function aResponseWithoutAVersionIdIsRefused(): void
    {
        $store = $this->store(self::json(200, ['Name' => 'typo3/api_key']));

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500008);

        $store->write('api_key', ['k' => 'v']);
    }

    #[Test]
    public function readWithVersionRefusesAResponseWithoutAVersionIdWithItsOwnCode(): void
    {
        $store = $this->store(self::json(200, ['Name' => 'typo3/api_key', 'SecretString' => '{"k":"v"}']));

        try {
            $store->readWithVersion('api_key');
            self::fail('A read without a version id must be refused.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500015, $e->getCode(), 'not 1794500008, which callers take for a value that is not a JSON object');
        }
    }

    #[Test]
    public function restoreIfCurrentPutsTheFieldsBackOnlyWhileTheCurrentVersionIsTheGivenOne(): void
    {
        $store = $this->store(
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-ours', 'SecretString' => '{"x":"theirs-or-ours"}']),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-restored']),
        );

        self::assertTrue($store->restoreIfCurrent('api_key', ['k' => 'previous'], 'v-ours'));

        self::assertSame(
            ['GetSecretValue', 'PutSecretValue'],
            array_map(static fn (RequestInterface $request): string => substr($request->getHeaderLine('X-Amz-Target'), strlen('secretsmanager.')), $this->requests),
        );
        self::assertSame('{"k":"previous"}', $this->bodyOf(1)['SecretString']);
    }

    #[Test]
    public function restoreIfCurrentChangesNothingWhenSomebodyWroteSince(): void
    {
        $store = $this->store(
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-theirs', 'SecretString' => '{}']),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-theirs', 'SecretString' => '{}']),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-theirs', 'SecretString' => '{}']),
        );

        self::assertFalse($store->restoreIfCurrent('api_key', ['k' => 'previous'], 'v-ours'));
        self::assertCount(3, $this->requests, 'three reads, nothing was written');
    }

    #[Test]
    public function restoreIfCurrentRetriesAReadThatHasNotCaughtUpWithTheWrite(): void
    {
        $store = $this->store(
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-older', 'SecretString' => '{}']),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-ours', 'SecretString' => '{}']),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-restored']),
        );

        self::assertTrue($store->restoreIfCurrent('api_key', ['k' => 'previous'], 'v-ours'));
        self::assertCount(3, $this->requests);
    }

    #[Test]
    public function destroyIfCurrentDeletesOnlyWhileTheCurrentVersionIsTheGivenOne(): void
    {
        $store = $this->store(
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-theirs', 'SecretString' => '{}']),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-theirs', 'SecretString' => '{}']),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-theirs', 'SecretString' => '{}']),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-ours', 'SecretString' => '{}']),
            self::json(200, ['Name' => 'typo3/api_key', 'DeletionDate' => 1_700_000_000]),
        );

        self::assertFalse($store->destroyIfCurrent('api_key', 'v-ours'));
        self::assertTrue($store->destroyIfCurrent('api_key', 'v-ours'));

        self::assertSame(
            ['GetSecretValue', 'GetSecretValue', 'GetSecretValue', 'GetSecretValue', 'DeleteSecret'],
            array_map(static fn (RequestInterface $request): string => substr($request->getHeaderLine('X-Amz-Target'), strlen('secretsmanager.')), $this->requests),
        );
    }

    #[Test]
    public function destroyIfCurrentOfAMissingSecretIsFalse(): void
    {
        $store = $this->store(
            self::awsError(400, 'ResourceNotFoundException'),
            self::awsError(400, 'ResourceNotFoundException'),
            self::awsError(400, 'ResourceNotFoundException'),
        );

        self::assertFalse($store->destroyIfCurrent('api_key', 'v-ours'));
        self::assertCount(3, $this->requests, 'not found is retried like a stale version');
    }

    #[Test]
    public function destroyIfCurrentRetriesASecretThatIsNotVisibleYet(): void
    {
        $store = $this->store(
            self::awsError(400, 'ResourceNotFoundException'),
            self::json(200, ['Name' => 'typo3/api_key', 'VersionId' => 'v-ours', 'SecretString' => '{}']),
            self::json(200, ['Name' => 'typo3/api_key', 'DeletionDate' => 1_700_000_000]),
        );

        self::assertTrue($store->destroyIfCurrent('api_key', 'v-ours'));
    }

    #[Test]
    public function destroyDeletesWithoutARecoveryWindowSoNoVersionSurvives(): void
    {
        $store = $this->store($this->json(200, ['Name' => 'typo3/api_key', 'DeletionDate' => 1_700_000_000]));

        $store->destroy('api_key');

        self::assertSame('secretsmanager.DeleteSecret', $this->request(0)->getHeaderLine('X-Amz-Target'));
        self::assertSame(['SecretId' => 'typo3/api_key', 'ForceDeleteWithoutRecovery' => true], $this->bodyOf(0));
    }

    #[Test]
    public function destroyOfASecretThatIsAlreadyGoneSucceeds(): void
    {
        $store = $this->store($this->awsError(400, 'ResourceNotFoundException'));

        $store->destroy('api_key');

        self::assertCount(1, $this->requests);
    }

    #[Test]
    public function destroyReportsARejection(): void
    {
        $store = $this->store($this->awsError(400, 'AccessDeniedException'));

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500006);

        $store->destroy('api_key');
    }

    #[Test]
    public function aTransportFailureKeepsCredentialsOutOfTheMessage(): void
    {
        $failure = new ConnectException(
            'cURL error 7: could not connect. Authorization: AWS4-HMAC-SHA256 Credential=' . self::akia('SECRETKEY12345') . '/20261113/eu-central-1/secretsmanager/aws4_request, '
            . 'SignedHeaders=host, Signature=0123456789abcdef0123456789abcdef',
            new Request('POST', 'https://secretsmanager.eu-central-1.amazonaws.com/'),
        );
        $store = $this->store($failure, $failure);

        try {
            $store->read('api_key');
            self::fail('A transport failure must throw.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500007, $e->getCode());
            self::assertStringContainsString('could not connect', $e->getMessage());
            self::assertStringNotContainsString(self::akia('SECRETKEY12345'), $e->getMessage());
            self::assertStringNotContainsString('0123456789abcdef', $e->getMessage());
            self::assertNotInstanceOf(Throwable::class, $e->getPrevious());
        }
    }

    #[Test]
    public function redactRemovesEveryCredentialShape(): void
    {
        $redacted = AwsSecretsManagerStore::redact(
            'key ' . self::akia('ABCDEFGHIJKLMNOP') . ', temp ' . self::asia('ABCDEFGHIJKLMNOP') . ', Authorization: AWS4-HMAC-SHA256 Credential=x, '
            . 'X-Amz-Security-Token: tok123, ?X-Amz-Signature=deadbeefdeadbeefdeadbeef&X-Amz-Credential=AKIAZ%2F2026',
        );

        foreach ([self::akia('ABCDEFGHIJKLMNOP'), self::asia('ABCDEFGHIJKLMNOP'), 'tok123', 'deadbeef', 'AWS4-HMAC-SHA256'] as $secret) {
            self::assertStringNotContainsString($secret, $redacted);
        }
    }

    #[Test]
    public function reportsWhetherTheSdkIsInstalled(): void
    {
        self::assertTrue($this->store($this->json(200, []))->isSdkInstalled());
    }

    #[Test]
    public function referenceNamesTheRegionAndTheSecretName(): void
    {
        self::assertSame('eu-central-1:typo3/site+main+api', $this->store()->reference('site:main:api'));
    }

    /**
     * #539: AWS deletes a force-deleted secret asynchronously and asks for
     * "appropriate back off and retry logic" before creating the same name
     * again (API_DeleteSecret). The restore after a failed row delete creates
     * into exactly that window.
     */
    #[Test]
    public function createRetriesWhileAForceDeletedNameIsStillBeingDeleted(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('notice')
            ->with(self::stringContains('succeeded after'), ['retries' => 2]);
        $this->logger = $logger;

        $store = $this->store(
            $this->awsError(400, 'InvalidRequestException'),
            $this->awsError(400, 'InvalidRequestException'),
            $this->json(200, ['VersionId' => 'v-restored']),
        );

        self::assertSame('v-restored', $store->create('api_key', ['k' => 'v']));
        self::assertCount(3, $this->requests);
        self::assertSame([250_000, 500_000], $this->sleeps);
        foreach ($this->requests as $request) {
            self::assertSame('secretsmanager.CreateSecret', $request->getHeaderLine('X-Amz-Target'));
        }
    }

    #[Test]
    public function createGivesUpAfterFiveAttempts(): void
    {
        $store = $this->store(...array_fill(0, 5, $this->awsError(400, 'InvalidRequestException')));

        try {
            $store->create('api_key', ['k' => 'v']);
            self::fail('The last refusal must be reported.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500006, $e->getCode());
            self::assertStringContainsString('InvalidRequestException', $e->getMessage());
        }

        self::assertCount(5, $this->requests);
        self::assertSame([250_000, 500_000, 1_000_000, 2_000_000], $this->sleeps);
    }

    /**
     * @return array<string, array{list<Response|Throwable>, int, int}>
     */
    public static function notRetriedProvider(): array
    {
        $json = ['Content-Type' => 'application/x-amz-json-1.1'];
        $down = static fn (): ConnectException => new ConnectException('connection refused', new Request('POST', 'https://secretsmanager.eu-central-1.amazonaws.com'));

        return [
            'name exists'   => [[new Response(400, $json, '{"__type":"ResourceExistsException","Message":"x"}')], 1794500012, 1],
            'access denied' => [[new Response(400, $json, '{"__type":"AccessDeniedException","Message":"x"}')], 1794500006, 1],
            // The SDK client retries a transport failure once itself
            // (AwsClientFactory, retries => 1); the store adds nothing.
            'transport' => [[$down(), $down()], 1794500007, 2],
        ];
    }

    /**
     * @param list<Response|Throwable> $answers
     */
    #[Test]
    #[DataProvider('notRetriedProvider')]
    public function createRetriesNothingButTheDeletionWindow(array $answers, int $code, int $requests): void
    {
        $store = $this->store(...[...$answers, $this->json(200, ['VersionId' => 'never-reached'])]);

        try {
            $store->create('api_key', ['k' => 'v']);
            self::fail('The refusal must be reported.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame($code, $e->getCode());
        }

        self::assertCount($requests, $this->requests);
        self::assertSame([], $this->sleeps);
    }

    /**
     * write() is unchanged: after the put found no secret, its create is tried
     * once and a put is never sent again, so a secret another writer creates in
     * the meantime is never written into (#535).
     */
    #[Test]
    public function writeDoesNotRetryAndNeverPutsAgainAfterTheCreate(): void
    {
        $store = $this->store(
            $this->awsError(400, 'ResourceNotFoundException'),
            $this->awsError(400, 'InvalidRequestException'),
            $this->json(200, ['VersionId' => 'never-reached']),
        );

        try {
            $store->write('api_key', ['k' => 'v']);
            self::fail('The refused create must be reported.');
        } catch (AwsSecretsManagerException) {
        }

        self::assertCount(2, $this->requests);
        self::assertSame('secretsmanager.PutSecretValue', $this->request(0)->getHeaderLine('X-Amz-Target'));
        self::assertSame('secretsmanager.CreateSecret', $this->request(1)->getHeaderLine('X-Amz-Target'));
    }

    /**
     * @param array<array-key, mixed> $body
     */
    private function json(int $status, array $body): Response
    {
        return new Response($status, ['Content-Type' => 'application/x-amz-json-1.1'], json_encode($body, JSON_THROW_ON_ERROR));
    }

    private function awsError(int $status, string $code): Response
    {
        return $this->json($status, ['__type' => $code, 'Message' => 'details that must not surface']);
    }

    private function request(int $index): RequestInterface
    {
        return $this->requests[$index];
    }

    /**
     * @return array<string, mixed>
     */
    private function bodyOf(int $index): array
    {
        $decoded = json_decode((string) $this->request($index)->getBody(), true, 32, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    private function store(Response|Throwable ...$answers): AwsSecretsManagerStore
    {
        $stack = HandlerStack::create(new MockHandler(array_values($answers)));
        $stack->push(Middleware::mapRequest(function (RequestInterface $request): RequestInterface {
            $this->requests[] = $request;

            return $request;
        }));
        // Like SecureHttpClientFactory: statuses are responses, not exceptions.
        $client = new Client(['handler' => $stack, 'http_errors' => false]);

        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('getAwsConfig')->willReturn(new AwsSecretsConfig(region: 'eu-central-1', secretPrefix: 'typo3/'));

        return new AwsSecretsManagerStore(
            $configuration,
            new AwsClientFactory($configuration, $client),
            function (int $microseconds): void {
                $this->sleeps[] = $microseconds;
            },
            $this->logger,
        );
    }
}
