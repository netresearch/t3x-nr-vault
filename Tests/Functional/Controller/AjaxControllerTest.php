<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Netresearch\NrVault\Controller\AjaxController;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Http\Stream;

/**
 * Functional tests for AjaxController.
 *
 * Tests the AJAX endpoints for revealing and rotating secrets.
 */
#[CoversClass(AjaxController::class)]
final class AjaxControllerTest extends AbstractVaultFunctionalTestCase
{
    private const REASON_TEST_CLEANUP = 'Test cleanup';

    // Each test explicitly calls `setUpBackendUser()` with its own uid (admin
    // vs. editor), so the base class must not log anyone in automatically.
    protected ?int $backendUserUid = null;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    #[Test]
    public function revealActionWithValidIdentifierReturnsDecryptedSecret(): void
    {
        $this->setUpBackendUser(1);

        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();
        $secretValue = 'my-super-secret-value';
        $vaultService->store($identifier, $secretValue);

        $controller = $this->get(AjaxController::class);
        $request = $this->createJsonPostRequest(['identifier' => $identifier]);

        $response = $controller->revealAction($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        self::assertTrue($body['success']);
        self::assertSame($secretValue, $body['secret']);
        self::assertTrue($body['copyAllowed']);

        // The plaintext-bearing response must never be cached anywhere.
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function revealActionWithoutIdentifierReturns400(): void
    {
        $this->setUpBackendUser(1);

        $controller = $this->get(AjaxController::class);
        $request = $this->createJsonPostRequest([]);

        $response = $controller->revealAction($request);

        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertFalse($body['success']);
        self::assertSame('No identifier provided', $body['error']);
    }

    /**
     * A NON-admin holding `secret.use` + `secret.reveal` through a backend group
     * (be_groups.custom_options) can reveal a secret whose read tier admits
     * their group — end-to-end, through the real `check('custom_options', …)`
     * path rather than a mocked seam.
     *
     * Both permissions are required: the endpoint asserts `secret.reveal`, and
     * the shared read path in `VaultService::retrieve()` asserts `secret.use`.
     */
    #[Test]
    public function revealActionSucceedsForNonAdminGrantedUseAndReveal(): void
    {
        // Store as admin, admitting the revealer's group to the read tier.
        $this->setUpBackendUser(1);
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();
        $secretValue = 'group-readable-value';
        $vaultService->store($identifier, $secretValue, ['groups' => [10]]);

        $this->setUpBackendUser(3);

        $controller = $this->get(AjaxController::class);
        $response = $controller->revealAction($this->createJsonPostRequest(['identifier' => $identifier]));

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        self::assertTrue($body['success']);
        self::assertSame($secretValue, $body['secret']);

        // Cleanup as admin
        $this->setUpBackendUser(1);
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    /**
     * `audit.view` is not a secret permission: holding it must not open the
     * reveal endpoint. The secret's read tier admits nobody but the owner here,
     * but the 403 is produced by the operation gate before any secret lookup.
     */
    #[Test]
    public function revealActionReturns403ForNonAdminWithOnlyAuditViewPermission(): void
    {
        $this->setUpBackendUser(1);
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'not-for-auditors', ['groups' => [11]]);

        $this->setUpBackendUser(4);

        $controller = $this->get(AjaxController::class);
        $response = $controller->revealAction($this->createJsonPostRequest(['identifier' => $identifier]));

        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        self::assertFalse($body['success']);
        self::assertSame('Access denied', $body['error']);

        // Cleanup as admin
        $this->setUpBackendUser(1);
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    /**
     * The revealer group deliberately does NOT carry `secret.rotate`: reading a
     * secret and replacing its value are separate grants.
     */
    #[Test]
    public function rotateActionReturns403ForNonAdminWithoutRotatePermission(): void
    {
        $this->setUpBackendUser(1);
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'original-secret', ['groups' => [10]]);

        $this->setUpBackendUser(3);

        $controller = $this->get(AjaxController::class);
        $response = $controller->rotateAction($this->createJsonPostRequest([
            'identifier' => $identifier,
            'secret' => 'rotated-by-revealer',
        ]));

        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        self::assertFalse($body['success']);

        // The value is untouched.
        $this->setUpBackendUser(1);
        self::assertSame('original-secret', $vaultService->retrieve($identifier));
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function revealActionAsNonAdminReturns403(): void
    {
        // Store secret as admin first
        $this->setUpBackendUser(1);
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'admin-secret');

        // Switch to non-admin user
        $this->setUpBackendUser(2);

        $controller = $this->get(AjaxController::class);
        $request = $this->createJsonPostRequest(['identifier' => $identifier]);

        $response = $controller->revealAction($request);

        // Non-admin gets either 403 (AccessDeniedException) or 404 (not visible)
        self::assertContains($response->getStatusCode(), [403, 404]);
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertFalse($body['success']);

        // Cleanup as admin
        $this->setUpBackendUser(1);
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function rotateActionWithValidDataReturnsSuccess(): void
    {
        $this->setUpBackendUser(1);

        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'original-secret');

        $controller = $this->get(AjaxController::class);
        $request = $this->createJsonPostRequest([
            'identifier' => $identifier,
            'secret' => 'rotated-secret',
        ]);

        $response = $controller->rotateAction($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertTrue($body['success']);
        self::assertSame('Secret rotated successfully', $body['message']);
        self::assertSame(2, $body['version']);

        // Verify the secret was actually rotated
        $retrieved = $vaultService->retrieve($identifier);
        self::assertSame('rotated-secret', $retrieved);

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function rotateActionWithoutIdentifierReturns400(): void
    {
        $this->setUpBackendUser(1);

        $controller = $this->get(AjaxController::class);
        $request = $this->createJsonPostRequest([
            'secret' => 'some-value',
        ]);

        $response = $controller->rotateAction($request);

        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertFalse($body['success']);
        self::assertSame('No identifier provided', $body['error']);
    }

    #[Test]
    public function rotateActionWithoutSecretReturns400(): void
    {
        $this->setUpBackendUser(1);

        $controller = $this->get(AjaxController::class);
        $request = $this->createJsonPostRequest([
            'identifier' => $this->generateUuidV7(),
        ]);

        $response = $controller->rotateAction($request);

        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertFalse($body['success']);
        self::assertSame('No secret value provided', $body['error']);
    }

    #[Test]
    public function rotateActionWithNonPostMethodReturns405(): void
    {
        $this->setUpBackendUser(1);

        $controller = $this->get(AjaxController::class);

        /** @phpstan-ignore new.internalClass */
        $request = new ServerRequest('https://example.com/ajax/vault/rotate', 'GET');

        $response = $controller->rotateAction($request);

        self::assertSame(405, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertFalse($body['success']);
        self::assertSame('Method not allowed', $body['error']);
    }

    /**
     * Create a PSR-7 POST request with JSON body.
     *
     * @param array<string, mixed> $data
     */
    private function createJsonPostRequest(array $data): ServerRequest
    {
        $json = json_encode($data, JSON_THROW_ON_ERROR);
        /** @phpstan-ignore new.internalClass */
        $stream = new Stream('php://temp', 'r+');
        $stream->write($json);
        $stream->rewind();

        /** @phpstan-ignore new.internalClass */
        return (new ServerRequest('https://example.com/ajax/vault/reveal', 'POST'))
            ->withHeader('Content-Type', 'application/json')
            ->withBody($stream);
    }
}
