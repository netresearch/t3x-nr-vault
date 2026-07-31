<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Controller;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Controller\AjaxController;
use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\SecretExpiredException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

#[CoversClass(AjaxController::class)]
#[AllowMockObjectsWithoutExpectations]
final class AjaxControllerTest extends TestCase
{
    private const MSG_NO_IDENTIFIER = 'No identifier provided';

    private const MSG_ACCESS_DENIED = 'Access denied';

    private AjaxController $subject;

    private VaultServiceInterface&MockObject $vaultService;

    private AccessControlServiceInterface&MockObject $accessControlService;

    private ExtensionConfigurationInterface&MockObject $configuration;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        // Default seam: every operation permission granted, so the tests that
        // exercise the non-authorization behaviour of the endpoints get past
        // the gate. The permission-specific tests build their own controller.
        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $this->accessControlService
            ->method('isGranted')
            ->willReturn(true);
        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->configuration
            ->method('getSecurityProfile')
            ->willReturn(SecurityProfile::Standard);
        $this->subject = new AjaxController($this->vaultService, $this->accessControlService, $this->configuration);
    }

    #[Test]
    public function revealActionReturns400WhenNoIdentifier(): void
    {
        $request = $this->createRequestWithJsonBody([]);

        $response = $this->subject->revealAction($request);

        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame(self::MSG_NO_IDENTIFIER, $body['error']);
    }

    #[Test]
    public function revealActionReturnsSecretOnSuccess(): void
    {
        $identifier = 'test-secret-id';
        $secretValue = 'my-secret-value';

        $request = $this->createRequestWithJsonBody(['identifier' => $identifier]);

        $this->vaultService
            ->expects(self::once())
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secretValue);

        $response = $this->subject->revealAction($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertTrue($body['success']);
        self::assertSame($secretValue, $body['secret']);
    }

    #[Test]
    public function revealActionMarksSuccessResponseAsNotStorable(): void
    {
        $request = $this->createRequestWithJsonBody(['identifier' => 'test-secret-id']);

        $this->vaultService
            ->method('retrieve')
            ->willReturn('my-secret-value');

        $response = $this->subject->revealAction($request);

        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('no-cache', $response->getHeaderLine('Pragma'));
    }

    #[Test]
    public function revealActionMarksErrorResponseAsNotStorable(): void
    {
        $request = $this->createRequestWithJsonBody([]);

        $response = $this->subject->revealAction($request);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    #[Test]
    public function revealActionAllowsCopyInStandardProfile(): void
    {
        $request = $this->createRequestWithJsonBody(['identifier' => 'test-secret-id']);

        $this->vaultService
            ->method('retrieve')
            ->willReturn('my-secret-value');

        $response = $this->subject->revealAction($request);

        $body = json_decode((string) $response->getBody(), true);
        self::assertTrue($body['copyAllowed']);
    }

    #[Test]
    public function revealActionForbidsCopyInHardenedProfile(): void
    {
        $request = $this->createRequestWithJsonBody(['identifier' => 'test-secret-id']);

        $this->vaultService
            ->method('retrieve')
            ->willReturn('my-secret-value');

        $controller = $this->createControllerForHardenedProfile();
        $response = $controller->revealAction($request);

        $body = json_decode((string) $response->getBody(), true);
        self::assertTrue($body['success']);
        self::assertFalse($body['copyAllowed']);
    }

    #[Test]
    public function revealActionReturns404WhenSecretNotFound(): void
    {
        $identifier = 'nonexistent-id';
        $request = $this->createRequestWithJsonBody(['identifier' => $identifier]);

        $this->vaultService
            ->method('retrieve')
            ->willReturn(null);

        $response = $this->subject->revealAction($request);

        self::assertSame(404, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame('Secret not found', $body['error']);
    }

    #[Test]
    public function revealActionReturns403WhenAccessDenied(): void
    {
        $identifier = 'restricted-id';
        $request = $this->createRequestWithJsonBody(['identifier' => $identifier]);

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new AccessDeniedException(self::MSG_ACCESS_DENIED, 1234567890));

        $response = $this->subject->revealAction($request);

        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame(self::MSG_ACCESS_DENIED, $body['error']);
    }

    #[Test]
    public function revealActionReturns410WhenSecretExpired(): void
    {
        $identifier = 'expired-id';
        $request = $this->createRequestWithJsonBody(['identifier' => $identifier]);

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(SecretExpiredException::forIdentifier($identifier, 1234567800));

        $response = $this->subject->revealAction($request);

        self::assertSame(410, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame('Secret has expired', $body['error']);
    }

    #[Test]
    public function revealActionReturns500WhenEncryptionFails(): void
    {
        $identifier = 'decrypt-error-id';
        $request = $this->createRequestWithJsonBody(['identifier' => $identifier]);

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new EncryptionException('Decryption failed', 1234567890));

        $response = $this->subject->revealAction($request);

        self::assertSame(500, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertIsString($body['error']);
        self::assertStringContainsString('Decryption failed', $body['error']);
    }

    #[Test]
    public function revealActionReturns500OnGenericException(): void
    {
        $identifier = 'error-id';
        $request = $this->createRequestWithJsonBody(['identifier' => $identifier]);

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new RuntimeException('Unexpected error'));

        $response = $this->subject->revealAction($request);

        self::assertSame(500, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertIsString($body['error']);
        self::assertStringContainsString('Failed to retrieve secret', $body['error']);
    }

    #[Test]
    public function revealActionSupportsJsonBody(): void
    {
        $identifier = 'json-body-id';
        $secretValue = 'secret-from-json';

        $request = $this->createRequestWithJsonBody(['identifier' => $identifier]);

        $this->vaultService
            ->expects(self::once())
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secretValue);

        $response = $this->subject->revealAction($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertTrue($body['success']);
        self::assertSame($secretValue, $body['secret']);
    }

    #[Test]
    public function revealActionReturns405ForNonPostRequests(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');

        $response = $this->subject->revealAction($request);

        self::assertSame(405, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame('Method not allowed', $body['error']);
    }

    #[Test]
    public function revealActionReturns403WithoutRevealPermission(): void
    {
        $request = $this->createRequestWithJsonBody(['identifier' => 'restricted-id']);

        $controller = $this->createControllerGranting();

        $response = $controller->revealAction($request);

        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame(self::MSG_ACCESS_DENIED, $body['error']);
    }

    /**
     * "Use does not imply reveal": a holder of `secret.use` may let machinery
     * consume secret values, but must not be able to put a plaintext on screen.
     */
    #[Test]
    public function revealActionReturns403ForHolderOfSecretUseOnly(): void
    {
        $request = $this->createRequestWithJsonBody(['identifier' => 'restricted-id']);

        $controller = $this->createControllerGranting(VaultPermission::SecretUse);

        $this->vaultService
            ->expects(self::never())
            ->method('retrieve');

        $response = $controller->revealAction($request);

        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame(self::MSG_ACCESS_DENIED, $body['error']);
    }

    #[Test]
    public function revealActionSucceedsWithRevealPermissionOnly(): void
    {
        $request = $this->createRequestWithJsonBody(['identifier' => 'revealable-id']);

        $controller = $this->createControllerGranting(VaultPermission::SecretReveal);

        $this->vaultService
            ->method('retrieve')
            ->willReturn('plaintext-value');

        $response = $controller->revealAction($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertTrue($body['success']);
        self::assertSame('plaintext-value', $body['secret']);
    }

    #[Test]
    public function rotateActionReturns405ForNonPostRequests(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');

        $response = $this->subject->rotateAction($request);

        self::assertSame(405, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame('Method not allowed', $body['error']);
    }

    #[Test]
    public function rotateActionReturns403WithoutRotatePermission(): void
    {
        $request = $this->createPostRequestWithBody([
            'identifier' => 'restricted-id',
            'secret' => 'new-value',
        ]);

        // Every OTHER secret permission granted — only `secret.rotate` missing.
        $controller = $this->createControllerGranting(
            VaultPermission::SecretUse,
            VaultPermission::SecretReveal,
            VaultPermission::SecretCreate,
            VaultPermission::SecretDelete,
            VaultPermission::SecretManagePolicy,
        );

        $this->vaultService
            ->expects(self::never())
            ->method('rotate');

        $response = $controller->rotateAction($request);

        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame(self::MSG_ACCESS_DENIED, $body['error']);
    }

    #[Test]
    public function rotateActionReturns400WhenNoIdentifier(): void
    {
        $request = $this->createPostRequestWithBody(['secret' => 'new-secret']);

        $response = $this->subject->rotateAction($request);

        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame(self::MSG_NO_IDENTIFIER, $body['error']);
    }

    #[Test]
    public function rotateActionReturns400WhenNoSecret(): void
    {
        $request = $this->createPostRequestWithBody(['identifier' => 'test-id']);

        $response = $this->subject->rotateAction($request);

        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame('No secret value provided', $body['error']);
    }

    #[Test]
    public function rotateActionSuccessfullyRotatesSecret(): void
    {
        $identifier = 'rotate-id';
        $newSecret = 'new-secret-value';

        $request = $this->createPostRequestWithBody([
            'identifier' => $identifier,
            'secret' => $newSecret,
        ]);

        $this->vaultService
            ->expects(self::once())
            ->method('rotate')
            ->with($identifier, $newSecret);

        $this->vaultService
            ->method('getMetadata')
            ->with($identifier)
            ->willReturn($this->createSecretDetails($identifier, version: 2));

        $response = $this->subject->rotateAction($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertTrue($body['success']);
        self::assertSame('Secret rotated successfully', $body['message']);
        self::assertSame(2, $body['version']);
    }

    #[Test]
    public function rotateActionReturns404WhenSecretNotFound(): void
    {
        $identifier = 'nonexistent-id';
        $request = $this->createPostRequestWithBody([
            'identifier' => $identifier,
            'secret' => 'new-value',
        ]);

        $this->vaultService
            ->method('rotate')
            ->willThrowException(new SecretNotFoundException($identifier, 1234567890));

        $response = $this->subject->rotateAction($request);

        self::assertSame(404, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame('Secret not found', $body['error']);
    }

    #[Test]
    public function rotateActionReturns403WhenAccessDenied(): void
    {
        $request = $this->createPostRequestWithBody([
            'identifier' => 'restricted-id',
            'secret' => 'new-value',
        ]);

        $this->vaultService
            ->method('rotate')
            ->willThrowException(new AccessDeniedException(self::MSG_ACCESS_DENIED, 1234567890));

        $response = $this->subject->rotateAction($request);

        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertSame(self::MSG_ACCESS_DENIED, $body['error']);
    }

    #[Test]
    public function rotateActionReturns400OnValidationError(): void
    {
        $request = $this->createPostRequestWithBody([
            'identifier' => 'test-id',
            'secret' => 'invalid-value',
        ]);

        $this->vaultService
            ->method('rotate')
            ->willThrowException(new ValidationException('Invalid secret format', 1234567890));

        $response = $this->subject->rotateAction($request);

        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertIsString($body['error']);
        self::assertStringContainsString('Validation error', $body['error']);
    }

    #[Test]
    public function rotateActionReturns500OnEncryptionError(): void
    {
        $request = $this->createPostRequestWithBody([
            'identifier' => 'test-id',
            'secret' => 'new-value',
        ]);

        $this->vaultService
            ->method('rotate')
            ->willThrowException(new EncryptionException('Encryption failed', 1234567890));

        $response = $this->subject->rotateAction($request);

        self::assertSame(500, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertIsString($body['error']);
        self::assertStringContainsString('Encryption failed', $body['error']);
    }

    #[Test]
    public function rotateActionReturns500OnGenericException(): void
    {
        $request = $this->createPostRequestWithBody([
            'identifier' => 'test-id',
            'secret' => 'new-value',
        ]);

        $this->vaultService
            ->method('rotate')
            ->willThrowException(new RuntimeException('Unexpected error'));

        $response = $this->subject->rotateAction($request);

        self::assertSame(500, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['success']);
        self::assertIsString($body['error']);
        self::assertStringContainsString('Failed to rotate secret', $body['error']);
    }

    #[Test]
    public function rotateActionHandlesMetadataWithNoVersion(): void
    {
        $request = $this->createPostRequestWithBody([
            'identifier' => 'test-id',
            'secret' => 'new-value',
        ]);

        $this->vaultService
            ->method('rotate');

        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails('test-id', version: 1));

        $response = $this->subject->rotateAction($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertTrue($body['success']);
        self::assertSame(1, $body['version']);
    }

    #[Test]
    public function revealActionHandlesEmptyStringIdentifier(): void
    {
        $request = $this->createRequestWithJsonBody(['identifier' => '']);

        $response = $this->subject->revealAction($request);

        self::assertSame(400, $response->getStatusCode());
    }

    #[Test]
    public function rotateActionHandlesEmptyStringIdentifier(): void
    {
        $request = $this->createPostRequestWithBody([
            'identifier' => '',
            'secret' => 'some-value',
        ]);

        $response = $this->subject->rotateAction($request);

        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame(self::MSG_NO_IDENTIFIER, $body['error']);
    }

    #[Test]
    public function rotateActionHandlesEmptyStringSecret(): void
    {
        $request = $this->createPostRequestWithBody([
            'identifier' => 'valid-id',
            'secret' => '',
        ]);

        $response = $this->subject->rotateAction($request);

        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('No secret value provided', $body['error']);
    }

    /**
     * Build a controller whose access-control seam grants exactly the given
     * operation permissions and nothing else.
     *
     * `createMock()` allows a method to be configured only once, so a variant
     * with different grants needs a dedicated controller rather than
     * re-stubbing the permissive mock created in setUp().
     */
    private function createControllerGranting(VaultPermission ...$granted): AjaxController
    {
        $accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $accessControlService
            ->method('isGranted')
            ->willReturnCallback(
                static fn (VaultPermission $permission): bool => \in_array($permission, $granted, true),
            );

        return new AjaxController($this->vaultService, $accessControlService, $this->configuration);
    }

    /**
     * Build a controller whose configuration reports the hardened profile.
     */
    private function createControllerForHardenedProfile(): AjaxController
    {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration
            ->method('getSecurityProfile')
            ->willReturn(SecurityProfile::Hardened);

        return new AjaxController($this->vaultService, $this->accessControlService, $configuration);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function createRequestWithJsonBody(array $body): ServerRequestInterface&MockObject
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getQueryParams')->willReturn([]);
        $request->method('getParsedBody')->willReturn($body);

        return $request;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function createPostRequestWithBody(array $body): ServerRequestInterface&MockObject
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getParsedBody')->willReturn($body);

        return $request;
    }

    private function createSecretDetails(string $identifier, int $version = 1): SecretDetails
    {
        return new SecretDetails(
            uid: 1,
            identifier: $identifier,
            description: 'Test secret',
            ownerUid: 1,
            groups: [],
            context: 'default',
            frontendAccessible: false,
            version: $version,
            createdAt: 1704067200,
            updatedAt: 1704067200,
            expiresAt: null,
            lastRotatedAt: null,
            readCount: 0,
            lastReadAt: null,
            metadata: [],
            scopePid: 0,
        );
    }
}
