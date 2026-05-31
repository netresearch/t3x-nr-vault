<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Exception;
use JsonException;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\SecretExpiredException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Core\Http\JsonResponse;

/**
 * AJAX controller for vault backend operations.
 *
 * Provides JSON endpoints for:
 * - Revealing secrets (FormEngine and list view)
 * - Rotating secrets (list view modal)
 */
#[AsController]
final readonly class AjaxController
{
    public function __construct(
        private VaultServiceInterface $vaultService,
        private AccessControlServiceInterface $accessControlService,
    ) {}

    /**
     * Reveal a secret value.
     *
     * Accepts POST requests with a JSON body containing `identifier`.
     * Admin-only and server-side re-checked (see SEC-ACCESS-6).
     *
     * @return ResponseInterface JSON response with secret or error
     */
    public function revealAction(ServerRequestInterface $request): ResponseInterface
    {
        // SEC-ACCESS-6: defense-in-depth — do not rely solely on the route's
        // `methods => ['POST']` / `access => admin` config. Re-assert the POST
        // method (mirroring rotateAction) and re-check admin server-side, so
        // authorization holds even if the route config is later loosened.
        if ($request->getMethod() !== 'POST') {
            return $this->jsonError('Method not allowed', 405);
        }

        if (!$this->accessControlService->isCurrentActorAdmin()) {
            return $this->jsonError('Access denied', 403);
        }

        $identifier = $this->getIdentifierFromRequest($request);

        if ($identifier === '') {
            return $this->jsonError('No identifier provided', 400);
        }

        try {
            $secret = $this->vaultService->retrieve($identifier);

            // retrieve() returns null when secret not found
            if ($secret === null) {
                return $this->jsonError('Secret not found', 404);
            }

            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new JsonResponse([
                'success' => true,
                'secret' => $secret,
            ]);
        } catch (AccessDeniedException) {
            return $this->jsonError('Access denied', 403);
        } catch (SecretExpiredException) {
            return $this->jsonError('Secret has expired', 410);
        } catch (EncryptionException) {
            return $this->jsonError('Decryption failed', 500);
        } catch (Exception) {
            return $this->jsonError('Failed to retrieve secret', 500);
        }
    }

    /**
     * Rotate a secret value (store a new value for existing identifier).
     *
     * Accepts POST requests with JSON body containing:
     * - identifier: string - The secret identifier
     * - secret: string - The new secret value
     *
     * @return ResponseInterface JSON response with success status
     */
    public function rotateAction(ServerRequestInterface $request): ResponseInterface
    {
        // Only accept POST
        if ($request->getMethod() !== 'POST') {
            return $this->jsonError('Method not allowed', 405);
        }

        // SEC-ACCESS-6: defense-in-depth admin re-check (see revealAction).
        if (!$this->accessControlService->isCurrentActorAdmin()) {
            return $this->jsonError('Access denied', 403);
        }

        $body = $this->getJsonBody($request);
        $identifier = isset($body['identifier']) && \is_string($body['identifier']) ? $body['identifier'] : '';
        $newSecret = isset($body['secret']) && \is_string($body['secret']) ? $body['secret'] : '';

        if ($identifier === '') {
            return $this->jsonError('No identifier provided', 400);
        }

        if ($newSecret === '') {
            return $this->jsonError('No secret value provided', 400);
        }

        try {
            // Rotate the secret (will throw SecretNotFoundException if it doesn't exist)
            $this->vaultService->rotate($identifier, $newSecret);

            // Get updated metadata
            $updatedMetadata = $this->vaultService->getMetadata($identifier);

            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new JsonResponse([
                'success' => true,
                'message' => 'Secret rotated successfully',
                'version' => $updatedMetadata->version,
            ]);
        } catch (SecretNotFoundException) {
            return $this->jsonError('Secret not found', 404);
        } catch (ValidationException $e) { // @phpstan-ignore catch.neverThrown
            return $this->jsonError('Validation error: ' . $e->getMessage(), 400);
        } catch (AccessDeniedException) {
            return $this->jsonError('Access denied', 403);
        } catch (EncryptionException) {
            return $this->jsonError('Encryption failed', 500);
        } catch (Exception) {
            return $this->jsonError('Failed to rotate secret', 500);
        }
    }

    /**
     * Build a uniform JSON error envelope.
     *
     * Centralises the `{success: false, error: ...}` shape so every failure
     * path is byte-identical and the single `JsonResponse` PHPStan suppression
     * lives in one place rather than at every call site.
     */
    private function jsonError(string $message, int $status): ResponseInterface
    {
        /** @phpstan-ignore new.internalClass, method.internalClass */
        return new JsonResponse([
            'success' => false,
            'error' => $message,
        ], $status);
    }

    /**
     * Extract identifier from POST request body.
     */
    private function getIdentifierFromRequest(ServerRequestInterface $request): string
    {
        $body = $this->getJsonBody($request);

        return isset($body['identifier']) && \is_string($body['identifier']) ? $body['identifier'] : '';
    }

    /**
     * Parse JSON body from request.
     *
     * @return array<string, mixed>
     */
    private function getJsonBody(ServerRequestInterface $request): array
    {
        $parsedBody = $request->getParsedBody();
        if (\is_array($parsedBody)) {
            /** @var array<string, mixed> $parsedBody */
            return $parsedBody;
        }

        $body = (string) $request->getBody();
        if ($body === '') {
            return [];
        }

        try {
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

            if (\is_array($decoded)) {
                /** @var array<string, mixed> $decoded */
                return $decoded;
            }

            return [];
        } catch (JsonException) {
            return [];
        }
    }
}
