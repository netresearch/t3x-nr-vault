<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Acceptance;

use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Attribute\ExtensionPoint;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultDoctorCommand;
use Netresearch\NrVault\Command\VaultRotateMasterKeyCommand;
use Netresearch\NrVault\Crypto\EnvelopeCodecInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Adapter\RecordingVaultAdapter;
use Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Audit\RecordingAuditSink;
use Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Crypto\PayloadEnvelopeRotator;
use Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Crypto\RecordingMasterKeyProvider;
use Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Doctor\ConsumerReadinessCheck;
use Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Service\ApiTokenClient;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * A real consuming extension, loaded next to nr-vault the way an installation
 * loads it: `Fixtures/Extensions/nr_vault_consumer_fixture` implements every
 * `#[ExtensionPoint]` interface, registers the implementations the way the
 * documentation says (tags for the audit sink, the readiness check and the
 * foreign-envelope rotator; service decoration for the storage adapter and the
 * master-key provider) and calls the vault through `VaultServiceInterface` and
 * the vault HTTP client with its own cancellation signal.
 *
 * Every assertion reads an effect in nr-vault's own paths — a store that went
 * through the consumer's adapter, an audit row the consumer's sink received,
 * a finding in `vault:doctor` output, a rotator named by
 * `vault:rotate-master-key` — rather than asking the container whether a
 * service exists.
 */
final class ConsumingExtensionTest extends AbstractVaultFunctionalTestCase
{
    private const FIXTURE_PATH = __DIR__ . '/../Fixtures/Extensions/nr_vault_consumer_fixture';

    private const TOKEN_IDENTIFIER = 'consumer_fixture_api_token';

    /**
     * Imports the fixture needs that Tests/Unit/Api/api-surface.txt does not list.
     *
     * Empty, and meant to stay that way. It held `Finding` until the snapshot
     * learned to freeze the types an extension point names in its phpdoc:
     * `ReadinessCheckInterface::run()` is declared `array` and gives its
     * element type as `list<Finding>` in a docblock alone, so the closure —
     * which follows native types — walked past a class no readiness check can
     * be written without. A new entry here means the published surface is
     * missing something an implementer must name; publish the type instead of
     * widening this list.
     *
     * @var list<class-string>
     */
    private const KNOWN_UNPUBLISHED_DEPENDENCIES = [];

    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        self::FIXTURE_PATH,
    ];

    protected ?string $backendUserFixture = __DIR__ . '/../Service/Fixtures/be_users.csv';

    #[Test]
    public function aSecretTheConsumerStoresGoesThroughItsAdapterAndKeyProviderAndReachesItsSink(): void
    {
        $client = $this->get(ApiTokenClient::class);
        self::assertInstanceOf(ApiTokenClient::class, $client);

        $token = 'consumer-token-' . bin2hex(random_bytes(8));
        $client->storeToken(self::TOKEN_IDENTIFIER, $token);
        self::assertSame($token, $client->readToken(self::TOKEN_IDENTIFIER));

        $adapter = $this->get(RecordingVaultAdapter::class);
        self::assertInstanceOf(RecordingVaultAdapter::class, $adapter);
        self::assertContains('store:' . self::TOKEN_IDENTIFIER, $adapter->calls, 'VaultService must store through the consumer adapter.');
        self::assertContains('retrieve:' . self::TOKEN_IDENTIFIER, $adapter->calls, 'VaultService must read through the consumer adapter.');
        self::assertSame($adapter, $this->get(VaultAdapterInterface::class));

        $keyProvider = $this->get(RecordingMasterKeyProvider::class);
        self::assertInstanceOf(RecordingMasterKeyProvider::class, $keyProvider);
        self::assertGreaterThan(0, $keyProvider->keyRequests, 'Envelope encryption must take its key from the consumer provider.');
        self::assertSame($keyProvider, $this->get(MasterKeyProviderInterface::class));

        $sink = $this->get(RecordingAuditSink::class);
        self::assertInstanceOf(RecordingAuditSink::class, $sink);
        $actions = array_column(array_filter($sink->entries, static fn (array $entry): bool => $entry['identifier'] === self::TOKEN_IDENTIFIER), 'action');
        self::assertSame(['create', 'read'], $actions, 'The consumer sink must receive the audit rows of the store and the read.');
        $lastEntry = end($sink->entries);
        self::assertIsArray($lastEntry);
        self::assertSame(
            $this->get(AuditLogServiceInterface::class)->getLatestHash(),
            $lastEntry['chainTip'],
            'The sink must receive the committed chain tip.',
        );
    }

    #[Test]
    public function theConsumerReadinessCheckIsReportedByVaultDoctor(): void
    {
        $tester = new CommandTester($this->command(VaultDoctorCommand::class));
        $tester->execute(['--format' => 'json']);

        $report = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($report);
        $findings = \is_array($report['findings'] ?? null) ? $report['findings'] : [];
        $consumerFindings = array_values(array_filter(
            $findings,
            static fn (mixed $finding): bool => \is_array($finding) && ($finding['id'] ?? null) === ConsumerReadinessCheck::FINDING_ID,
        ));

        self::assertCount(1, $consumerFindings, $tester->getDisplay());
        self::assertSame('pass', $consumerFindings[0]['severity'] ?? null);
        $summary = $consumerFindings[0]['summary'] ?? null;
        self::assertIsString($summary);
        self::assertStringContainsString('profile: standard', $summary);
    }

    /**
     * The inventory the dry run reports and the work the rotation does must be
     * the same number: `vault:rotate-master-key` rolls the whole rotation back
     * when a consumer re-wraps fewer envelopes than it counted. The table also
     * holds one row from before this consumer started sealing, which neither
     * side may touch.
     */
    #[Test]
    public function theConsumerEnvelopeRotatorIsCountedAndRewrappedByMasterKeyRotation(): void
    {
        $client = $this->get(ApiTokenClient::class);
        self::assertInstanceOf(ApiTokenClient::class, $client);
        $client->storeToken(self::TOKEN_IDENTIFIER, 'rotation-inventory-' . bin2hex(random_bytes(4)));

        $codec = $this->get(EnvelopeCodecInterface::class);
        self::assertInstanceOf(EnvelopeCodecInterface::class, $codec);

        $payloads = $this->getConnectionPool()->getConnectionForTable(PayloadEnvelopeRotator::TABLE);
        $payloads->insert(PayloadEnvelopeRotator::TABLE, ['sealed' => $codec->seal('consumer-payload-one', PayloadEnvelopeRotator::ENVELOPE_CONTEXT)]);
        $payloads->insert(PayloadEnvelopeRotator::TABLE, ['sealed' => $codec->seal('consumer-payload-two', PayloadEnvelopeRotator::ENVELOPE_CONTEXT)]);
        $payloads->insert(PayloadEnvelopeRotator::TABLE, ['sealed' => 'written-before-this-consumer-sealed']);

        $rotator = $this->get(PayloadEnvelopeRotator::class);
        self::assertInstanceOf(PayloadEnvelopeRotator::class, $rotator);
        self::assertSame(2, $rotator->countEnvelopes(), 'Only the sealed rows count as envelopes.');

        $before = $this->storedPayloads();
        $newKeyPath = $this->instancePath . '/rotation-target.key';
        $newKey = sodium_crypto_secretbox_keygen();
        file_put_contents($newKeyPath, $newKey);
        sodium_memzero($newKey);

        $dryRun = new CommandTester($this->command(VaultRotateMasterKeyCommand::class));
        $dryRun->execute(['--dry-run' => true, '--new-key' => $newKeyPath]);
        self::assertSame(Command::SUCCESS, $dryRun->getStatusCode(), $dryRun->getDisplay());
        $dryRunOutput = $this->normalize($dryRun);
        self::assertStringContainsString(PayloadEnvelopeRotator::IDENTIFIER . ': 2 envelope(s)', $dryRunOutput);
        self::assertStringContainsString('Would re-wrap 2 consumer-owned envelope(s).', $dryRunOutput);

        $rotation = new CommandTester($this->command(VaultRotateMasterKeyCommand::class));
        $rotation->execute(['--confirm' => true, '--new-key' => $newKeyPath]);
        // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
        unlink($newKeyPath);

        self::assertSame(Command::SUCCESS, $rotation->getStatusCode(), $rotation->getDisplay());
        $rotationOutput = $this->normalize($rotation);
        self::assertStringContainsString(PayloadEnvelopeRotator::IDENTIFIER . ': re-wrapped 2 envelope(s).', $rotationOutput);
        self::assertStringContainsString('Consumer-owned envelopes re-wrapped: 2.', $rotationOutput);

        $after = $this->storedPayloads();
        self::assertSame(array_keys($before), array_keys($after));
        foreach ($before as $uid => $value) {
            if ($codec->isSealed($value)) {
                self::assertNotSame($value, $after[$uid], \sprintf('Envelope %d must carry a DEK wrapped under the new key.', $uid));
                self::assertTrue($codec->isSealed($after[$uid]), \sprintf('Envelope %d must still be a sealed envelope.', $uid));

                continue;
            }

            self::assertSame($value, $after[$uid], 'A row written before sealing must not be rewritten.');
        }

        self::assertSame(2, $rotator->countEnvelopes(), 'The sealed count must be unchanged by the rotation.');
    }

    #[Test]
    public function aCancelledCallThroughTheVaultHttpClientIsAuditedAndReachesTheConsumerSink(): void
    {
        $client = $this->get(ApiTokenClient::class);
        self::assertInstanceOf(ApiTokenClient::class, $client);
        $client->storeToken(self::TOKEN_IDENTIFIER, 'cancelled-call-' . bin2hex(random_bytes(4)));

        try {
            $client->call(self::TOKEN_IDENTIFIER, 'https://api.example.com/v1/ping', true);
            self::fail('A call whose signal is already cancelled must not be sent.');
        } catch (RequestCancelledException) {
            // expected
        }

        $sink = $this->get(RecordingAuditSink::class);
        self::assertInstanceOf(RecordingAuditSink::class, $sink);
        self::assertContains(
            ['identifier' => self::TOKEN_IDENTIFIER, 'action' => 'http_call_cancelled_before_send'],
            array_map(static fn (array $entry): array => ['identifier' => $entry['identifier'], 'action' => $entry['action']], $sink->entries),
        );
    }

    /**
     * The fixture is written against the published API only: every nr-vault
     * class it imports is in the API snapshot, and every nr-vault interface it
     * implements is marked `#[ExtensionPoint]`.
     */
    #[Test]
    public function theConsumerUsesOnlyThePublishedApiAndImplementsOnlyExtensionPoints(): void
    {
        $surface = (string) file_get_contents(__DIR__ . '/../../Unit/Api/api-surface.txt');
        $fixtureNamespace = 'Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\\';

        $unpublished = [];
        $implemented = [];
        $files = glob(self::FIXTURE_PATH . '/Classes/*/*.php');
        self::assertNotFalse($files);
        self::assertNotEmpty($files);
        foreach ($files as $file) {
            preg_match_all('/^use (Netresearch\\\\NrVault\\\\[^;]+);$/m', (string) file_get_contents($file), $matches);
            foreach ($matches[1] as $import) {
                if (!str_starts_with($import, $fixtureNamespace) && !str_contains($surface, "\n" . $import . ' (') && !str_starts_with($surface, $import . ' (')) {
                    $unpublished[] = $import;
                }
            }

            $class = $fixtureNamespace . 'Classes\\' . basename(\dirname($file)) . '\\' . basename($file, '.php');
            self::assertTrue(class_exists($class), $class);
            foreach ((new ReflectionClass($class))->getInterfaceNames() as $interface) {
                if (str_starts_with($interface, 'Netresearch\NrVault\\')) {
                    $implemented[$interface] = (new ReflectionClass($interface))->getAttributes(ExtensionPoint::class) !== [];
                }
            }
        }

        self::assertSame(self::KNOWN_UNPUBLISHED_DEPENDENCIES, array_values(array_unique($unpublished)), 'Fixture imports outside the published API snapshot.');
        self::assertCount(6, $implemented, 'The fixture must implement all six extension points.');
        self::assertNotContains(false, $implemented, 'The fixture implements an nr-vault interface that is not an extension point.');
    }

    /**
     * The consumer's payload column, keyed by uid.
     *
     * @return array<int, string>
     */
    private function storedPayloads(): array
    {
        $rows = $this->getConnectionPool()->getConnectionForTable(PayloadEnvelopeRotator::TABLE)
            ->select(['uid', 'sealed'], PayloadEnvelopeRotator::TABLE, [], [], ['uid' => 'ASC'])
            ->fetchAllAssociative();

        $payloads = [];
        foreach ($rows as $row) {
            self::assertIsNumeric($row['uid'] ?? null);
            $payloads[(int) $row['uid']] = \is_string($row['sealed'] ?? null) ? $row['sealed'] : '';
        }

        return $payloads;
    }

    /**
     * SymfonyStyle wraps its blocks to the terminal width; collapsing
     * whitespace lets an assertion pin a whole sentence.
     */
    private function normalize(CommandTester $tester): string
    {
        return (string) preg_replace('/\s+/', ' ', $tester->getDisplay());
    }

    /**
     * @param class-string<Command> $commandClass
     */
    private function command(string $commandClass): Command
    {
        $command = $this->get($commandClass);
        self::assertInstanceOf(Command::class, $command);

        return $command;
    }
}
