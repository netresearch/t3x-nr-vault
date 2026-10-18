<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Documentation;

use Acme\SitePackage\Service\FrontendAccessibleSecret;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\ServerRequest;

#[CoversNothing]
final class FrontendAccessibleExampleTest extends AbstractVaultFunctionalTestCase
{
    protected array $coreExtensionsToLoad = ['backend', 'frontend'];

    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    protected array $extensionConfiguration = ['auditHmacEpoch' => 1];

    #[Test]
    public function literalExampleStoresTheAccessFlagAndPermitsAFrontendRead(): void
    {
        require_once __DIR__ . '/../../../Documentation/Configuration/_FrontendAccessibleSecret.php';

        $vault = $this->get(VaultServiceInterface::class);
        $example = new FrontendAccessibleSecret($vault);
        $value = 'public-client-api-example';
        $example->storeApiKey($value);

        $row = $this->findRecord('google_maps_key');
        self::assertIsArray(
            $row,
            'The literal example must store the documented identifier.',
        );
        self::assertSame('google_maps_key', $row['identifier']);
        self::assertSame(1, (int) $row['frontend_accessible']);
        self::assertIsString($row['encrypted_value']);
        self::assertNotSame('', $row['encrypted_value']);
        self::assertNotSame($value, $row['encrypted_value']);
        self::assertSame([], $vault->getMetadata('google_maps_key')->metadata);

        $GLOBALS['TYPO3_REQUEST'] = $this->frontendRequest();
        self::assertSame($value, $vault->retrieveForFrontend('google_maps_key'));
        self::assertTrue(
            $this
                ->get(AuditLogServiceInterface::class)
                ->verifyHashChain()
                ->isValid(),
        );
    }

    #[Test]
    public function customMetadataDoesNotPublishASecretToTheFrontend(): void
    {
        $vault = $this->get(VaultServiceInterface::class);
        $value = 'private-client-api-example';
        $vault->store(
            'metadata_only_key',
            $value,
            ['metadata' => ['frontend_accessible' => true]],
        );

        $row = $this->findRecord('metadata_only_key');
        self::assertIsArray($row);
        self::assertSame(0, (int) $row['frontend_accessible']);
        self::assertSame(
            ['frontend_accessible' => true],
            $vault->getMetadata('metadata_only_key')->metadata,
        );

        $GLOBALS['TYPO3_REQUEST'] = $this->frontendRequest();
        $caught = null;
        $actual = null;

        try {
            $actual = $vault->retrieveForFrontend('metadata_only_key');
        } catch (Throwable $failure) {
            $caught = $failure;
        }

        self::assertInstanceOf(AccessDeniedException::class, $caught);
        self::assertSame(1703800003, $caught->getCode());
        self::assertSame(
            'Access denied to secret "metadata_only_key": not frontend accessible',
            $caught->getMessage(),
        );
        self::assertNull($actual);
        self::assertIsString($row['encrypted_value']);
        self::assertTrue(
            $this
                ->get(AuditLogServiceInterface::class)
                ->verifyHashChain()
                ->isValid(),
        );
    }

    /**
     * @return array<string, mixed>|null
     */
    private function findRecord(string $identifier): ?array
    {
        $builder = $this->getConnectionPool()->getQueryBuilderForTable('tx_nrvault_secret');
        $builder->getRestrictions()->removeAll();
        $row = $builder
            ->select('identifier', 'frontend_accessible', 'encrypted_value')
            ->from('tx_nrvault_secret')
            ->where(
                $builder->expr()->eq(
                    'identifier',
                    $builder->createNamedParameter($identifier),
                ),
            )
            ->executeQuery()
            ->fetchAssociative();

        return $row === false ? null : $row;
    }

    /**
     * Build the actual TYPO3 request context tested by the frontend read API.
     * Core marks its concrete request and request-type constant as internal.
     */
    private function frontendRequest(): ServerRequestInterface
    {
        /** @phpstan-ignore classConstant.internal */
        $applicationType = SystemEnvironmentBuilder::REQUESTTYPE_FE;
        /** @phpstan-ignore new.internalClass, method.internalClass */
        $request = new ServerRequest();

        /** @phpstan-ignore method.internalClass */
        return $request->withAttribute('applicationType', $applicationType);
    }
}
