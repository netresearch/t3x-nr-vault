<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Netresearch\NrVault\Controller\SecretsController;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Messaging\FlashMessageService;

/**
 * What `SecretsController::toggleAction()` answers once the mutation itself
 * has moved into `VaultService::setEnabled()`.
 *
 * The controller keeps two jobs, and both are observable here: it decides
 * which state the button is asking for (the service sets an absolute state; a
 * toggle is a UI gesture), and it answers in the shape the caller expects —
 * JSON with a status code for the AJAX branch, a flash message plus a redirect
 * for the plain form post.
 *
 * The round trip matters most: disabling and re-enabling the same secret
 * through the endpoint is exactly the path that used to be a one-way door,
 * because the record left every query the second half needed.
 */
#[CoversClass(SecretsController::class)]
final class SecretsControllerToggleTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    protected function setUp(): void
    {
        parent::setUp();

        // `toggleAction()` resolves the language service for its flash
        // messages before it reaches any gate, and nothing in a bare
        // functional bootstrap populates $GLOBALS['LANG'].
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);
    }

    #[Test]
    public function theAjaxBranchDisablesAndReportsTheNewState(): void
    {
        $identifier = $this->seedEnabledSecret();

        $response = $this->toggle($identifier, ajax: true);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(
            ['success' => true, 'hidden' => true],
            $this->decodedStateOf($response),
            'The JSON must report the state the secret now has.',
        );
        self::assertSame(1, $this->currentHiddenState($identifier));
    }

    /**
     * The round trip. A second call on the same secret must find it and flip
     * it back — the assertion the one-way door failed, because the disabled
     * record was invisible to the lookup the toggle resolves through.
     */
    #[Test]
    public function aSecondCallReEnablesTheSameSecret(): void
    {
        $identifier = $this->seedEnabledSecret();

        $this->toggle($identifier, ajax: true);
        $response = $this->toggle($identifier, ajax: true);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(
            ['success' => true, 'hidden' => false],
            $this->decodedStateOf($response),
        );
        self::assertSame(
            0,
            $this->currentHiddenState($identifier),
            'A disabled secret must be reachable by the endpoint that re-enables it.',
        );
    }

    #[Test]
    public function theBrowserBranchRedirectsAndQueuesASuccessMessage(): void
    {
        $identifier = $this->seedEnabledSecret();

        $response = $this->toggle($identifier, ajax: false);

        self::assertSame(302, $response->getStatusCode());
        self::assertNotSame('', $response->getHeaderLine('location'));
        self::assertNotSame(
            [],
            $this->get(FlashMessageService::class)->getMessageQueueByIdentifier()->getAllMessagesAndFlush(),
            'The plain form post must report the outcome as a flash message.',
        );
        self::assertSame(1, $this->currentHiddenState($identifier));
    }

    #[Test]
    public function theAjaxBranchAnswers404ForAnUnknownSecret(): void
    {
        $response = $this->toggle('no_such_secret', ajax: true);

        self::assertSame(404, $response->getStatusCode());
        self::assertSame(
            ['success' => false],
            ['success' => $this->decodeBody($response)['success'] ?? null],
        );
    }

    #[Test]
    public function theAjaxBranchAnswers400WithoutAnIdentifier(): void
    {
        $identifier = $this->seedEnabledSecret();

        $response = $this->toggle('', ajax: true);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame(
            0,
            $this->currentHiddenState($identifier),
            'A request without an identifier must not touch any secret.',
        );
    }

    private function toggle(string $identifier, bool $ajax): ResponseInterface
    {
        return $this->get(SecretsController::class)->toggleAction($this->toggleRequest($identifier, $ajax));
    }

    private function toggleRequest(string $identifier, bool $ajax): ServerRequestInterface
    {
        /** @phpstan-ignore new.internalClass, method.internalClass */
        $request = new ServerRequest('https://example.com/module/admin/vault/secrets/toggle', 'POST');

        // Core marks its own ServerRequest @internal, but the withers being
        // called are PSR-7 contract.
        /** @phpstan-ignore method.internalClass */
        $request = $request->withParsedBody(['identifier' => $identifier]);

        /** @phpstan-ignore method.internalClass */
        return $ajax ? $request->withHeader('Accept', 'application/json') : $request;
    }

    /**
     * The two fields the ESM module reads. Compared as one array so a change
     * to either shows up as a single, readable diff.
     *
     * @return array{success: mixed, hidden: mixed}
     */
    private function decodedStateOf(ResponseInterface $response): array
    {
        $decoded = $this->decodeBody($response);

        return [
            'success' => $decoded['success'] ?? null,
            'hidden' => $decoded['hidden'] ?? null,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeBody(ResponseInterface $response): array
    {
        $decoded = json_decode((string) $response->getBody(), true);
        self::assertIsArray($decoded, 'The AJAX branch must answer with a JSON object.');

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    private function seedEnabledSecret(): string
    {
        $identifier = 'toggle_' . bin2hex(random_bytes(4));

        $this->getConnectionPool()
            ->getConnectionForTable(self::SECRET_TABLE)
            ->insert(self::SECRET_TABLE, [
                'pid' => 0,
                'identifier' => $identifier,
                'owner_uid' => 1,
                'hidden' => 0,
            ]);

        return $identifier;
    }

    private function currentHiddenState(string $identifier): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        return (int) $queryBuilder
            ->select('hidden')
            ->from(self::SECRET_TABLE)
            ->where($queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)))
            ->executeQuery()
            ->fetchOne();
    }
}
