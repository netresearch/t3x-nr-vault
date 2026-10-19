<?php

/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Netresearch DTT GmbH
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Documentation;

use ErrorException;
use MyVendor\MyExtension\Message\IngestMessage;
use MyVendor\MyExtension\MessageHandler\IngestHandler;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\TechnicalActorException;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Messenger\Handler\HandlersLocator;
use Symfony\Component\Messenger\MessageBus;
use Symfony\Component\Messenger\Middleware\HandleMessageMiddleware;
use Throwable;
use UnexpectedValueException;

final class TechnicalActorExampleTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Controller/Fixtures/be_users.csv';

    #[Test]
    public function documentedYamlWiresTheUidAndRetrievesWithRealGroupPermissions(): void
    {
        $this->importCSVDataSet(
            __DIR__ . '/../Security/Fixtures/technical_actors.csv',
        );
        $vault = $this->get(VaultServiceInterface::class);
        $vault->store(
            'my_ext_embeddings_api_key',
            'example-secret',
            ['owner' => 999, 'groups' => [5]],
        );
        self::assertSame(
            'example-secret',
            $vault->retrieve('my_ext_embeddings_api_key'),
        );
        $before = $this->get(AuditLogServiceInterface::class)->query();
        $context = $this->get(TechnicalActorContextInterface::class);
        $ambient = $GLOBALS['BE_USER'];
        $caught = null;
        set_error_handler(
            static function (
                int $severity,
                string $message,
                string $file,
                int $line,
            ): never {
                throw new ErrorException($message, 0, $severity, $file, $line);
            },
        );

        try {
            $handler = $this->configuredHandler();
            (new MessageBus(
                [
                    new HandleMessageMiddleware(
                        new HandlersLocator(
                            [IngestMessage::class => [$handler]],
                        ),
                    ),
                ],
            ))->dispatch(new IngestMessage());
        } catch (Throwable $exception) {
            $caught = $exception;
        } finally {
            restore_error_handler();
        }

        self::assertNull(
            $caught,
            $caught?->getMessage() ?? 'Documented handler must execute',
        );
        self::assertNull($context->getCurrentActor());
        self::assertSame($ambient, $GLOBALS['BE_USER']);
        $newEntries = $this->newEntries($before);
        self::assertCount(1, $newEntries);
        $read = $newEntries[0];
        self::assertSame('my_ext_embeddings_api_key', $read->secretIdentifier);
        self::assertSame('read', $read->action);
        self::assertTrue($read->success);
        self::assertSame(10, $read->actorUid);
        self::assertSame('technical', $read->actorType);
        self::assertSame('tech_indexer', $read->actorUsername);
        self::assertTrue(
            $this
                ->get(AuditLogServiceInterface::class)
                ->verifyHashChain()
                ->isValid(),
        );
    }

    #[Test]
    public function disabledConfiguredUserCannotEnterTheExampleCallback(): void
    {
        $this->importCSVDataSet(
            __DIR__ . '/../Security/Fixtures/technical_actors.csv',
        );
        $vault = $this->get(VaultServiceInterface::class);
        $vault->store(
            'my_ext_embeddings_api_key',
            'example-secret',
            ['owner' => 999, 'groups' => [5]],
        );
        $before = $this->get(AuditLogServiceInterface::class)->query();
        $context = $this->get(TechnicalActorContextInterface::class);
        $ambient = $GLOBALS['BE_USER'];
        $caught = null;

        try {
            $handler = $this->configuredHandler(11);
            $handler(new IngestMessage());
        } catch (TechnicalActorException $exception) {
            $caught = $exception;
        }

        self::assertInstanceOf(TechnicalActorException::class, $caught);
        self::assertSame(1784000003, $caught->getCode());
        self::assertNull($context->getCurrentActor());
        self::assertSame($ambient, $GLOBALS['BE_USER']);
        self::assertSame([], $this->newEntries($before));
    }

    #[Test]
    public function ambientAdministratorCannotReplaceTheExamplesTechnicalAcl(): void
    {
        $this->importCSVDataSet(
            __DIR__ . '/../Security/Fixtures/technical_actors.csv',
        );
        $vault = $this->get(VaultServiceInterface::class);
        $vault->store(
            'my_ext_embeddings_api_key',
            'example-secret',
            ['owner' => 999, 'groups' => [10]],
        );
        $before = $this->get(AuditLogServiceInterface::class)->query();
        $context = $this->get(TechnicalActorContextInterface::class);
        $ambient = $GLOBALS['BE_USER'];
        $caught = null;

        try {
            $handler = $this->configuredHandler();
            $handler(new IngestMessage());
        } catch (AccessDeniedException $exception) {
            $caught = $exception;
        }

        self::assertInstanceOf(AccessDeniedException::class, $caught);
        self::assertNull($context->getCurrentActor());
        self::assertSame($ambient, $GLOBALS['BE_USER']);
        $newEntries = $this->newEntries($before);
        self::assertCount(1, $newEntries);
        self::assertSame(10, $newEntries[0]->actorUid);
        self::assertSame('technical', $newEntries[0]->actorType);
        self::assertSame('access_denied', $newEntries[0]->action);
        self::assertFalse($newEntries[0]->success);
        self::assertSame(
            'my_ext_embeddings_api_key',
            $newEntries[0]->secretIdentifier,
        );
    }

    #[Test]
    public function missingSecretIsRefusedAndTheScopeIsRestored(): void
    {
        $this->importCSVDataSet(
            __DIR__ . '/../Security/Fixtures/technical_actors.csv',
        );
        $context = $this->get(TechnicalActorContextInterface::class);
        $ambient = $GLOBALS['BE_USER'];
        $caught = null;

        try {
            $handler = $this->configuredHandler();
            $handler(new IngestMessage());
        } catch (RuntimeException $exception) {
            $caught = $exception;
        }

        self::assertInstanceOf(RuntimeException::class, $caught);
        self::assertSame(1784000112, $caught->getCode());
        self::assertSame('API key is not configured', $caught->getMessage());
        self::assertNull($context->getCurrentActor());
        self::assertSame($ambient, $GLOBALS['BE_USER']);
        self::assertSame(
            [],
            $this->get(AuditLogServiceInterface::class)->query(),
        );
    }

    private function configuredHandler(?int $uidOverride = null): IngestHandler
    {
        require_once __DIR__ . '/Fixtures/IngestMessage.php';
        require_once __DIR__ . '/../../../Documentation/Examples/TechnicalActor/IngestHandler.php';
        $container = new ContainerBuilder();
        $loader = new YamlFileLoader(
            $container,
            new FileLocator(
                __DIR__ . '/../../../Documentation/Examples/TechnicalActor',
            ),
        );
        $loader->load('Services.yaml');
        $container
            ->register(TechnicalActorContextInterface::class)
            ->setSynthetic(true);
        $container->register(VaultServiceInterface::class)->setSynthetic(true);
        $container->getDefinition(IngestHandler::class)->setPublic(true);
        if ($uidOverride !== null) {
            $container->setParameter(
                'my_extension.technical_be_user_uid',
                $uidOverride,
            );
        }

        $container->compile();
        $container->set(
            TechnicalActorContextInterface::class,
            $this->get(TechnicalActorContextInterface::class),
        );
        $container->set(
            VaultServiceInterface::class,
            $this->get(VaultServiceInterface::class),
        );
        $handler = $container->get(IngestHandler::class);
        if (!$handler instanceof IngestHandler) {
            throw new UnexpectedValueException(
                'Documented configuration produced the wrong handler',
                1784000113,
            );
        }

        return $handler;
    }

    /** @param list<AuditLogEntry> $before
     * @return list<AuditLogEntry>
     */
    private function newEntries(array $before): array
    {
        $knownUids = array_map(static fn (AuditLogEntry $entry): int => $entry->uid, $before);

        return array_values(
            array_filter(
                $this->get(AuditLogServiceInterface::class)->query(),
                static fn (
                    AuditLogEntry $entry,
                ): bool => !\in_array($entry->uid, $knownUids, true),
            ),
        );
    }
}
