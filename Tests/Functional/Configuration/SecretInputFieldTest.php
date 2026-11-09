<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Configuration;

use Netresearch\NrVault\Form\Element\VaultSecretInputElement;
use Netresearch\NrVault\Hook\SecretTcaHook;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Controller\RecordListDownloadController;
use TYPO3\CMS\Backend\Form\FormDataCompiler;
use TYPO3\CMS\Backend\Form\FormDataGroup\TcaDatabaseRecord;
use TYPO3\CMS\Backend\Form\NodeFactory;
use TYPO3\CMS\Backend\Utility\BackendUtility;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Site\Entity\NullSite;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * The form-only column `secret_input` of tx_nrvault_secret.
 *
 * It has no database column: the editor types the plaintext into it and
 * SecretTcaHook moves the value into the vault. The Records module builds its
 * SELECT from BackendUtility::getAllowedFieldsForTable(), which leaves out
 * only `type => none` fields, so a column-less field of any other type turns
 * "Download all columns" into an SQL error (Unknown column 'secret_input').
 * These tests pin both halves: the record list never selects the field, and
 * the form still renders the vault input whose value DataHandler stores.
 */
#[CoversClass(SecretTcaHook::class)]
#[CoversClass(VaultSecretInputElement::class)]
final class SecretInputFieldTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE = 'tx_nrvault_secret';

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users.csv';

    protected function setUp(): void
    {
        parent::setUp();
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->create('default');
    }

    /**
     * The request the Records module sends for "Download" with "all columns".
     */
    #[Test]
    public function recordListDownloadWithAllColumnsSucceeds(): void
    {
        $identifier = $this->createSecret('download-plaintext-' . bin2hex(random_bytes(4)));

        $request = $this->backendRequest('/typo3/record/download', 'POST')
            ->withAttribute('site', new NullSite())
            ->withParsedBody([
                'id'         => 0,
                'table'      => self::TABLE,
                'format'     => 'csv',
                'allColumns' => 1,
                'rawValues'  => 1,
            ]);

        // Core marks the controller @internal; this test drives the request
        // the Records module sends to it, which is what fails in production.
        /** @phpstan-ignore classConstant.internalClass, method.internalClass */
        $response = $this->get(RecordListDownloadController::class)->handleDownloadRequest($request);

        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        self::assertStringContainsString($identifier, $body);
        self::assertStringNotContainsString('secret_input', $body);
        self::assertStringNotContainsString('download-plaintext-', $body);
    }

    /**
     * Both variants feed a SELECT in DatabaseRecordList: with the user check
     * for the visible columns and the column selector, without it for the
     * field list and the sort check.
     */
    #[Test]
    #[DataProvider('accessCheckProvider')]
    public function allowedFieldsOfSecretTableCanBeSelected(bool $checkUserAccess): void
    {
        $identifier = $this->createSecret('select-plaintext');

        /** @phpstan-ignore staticMethod.internal */
        $fields = BackendUtility::getAllowedFieldsForTable(self::TABLE, $checkUserAccess);

        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::TABLE);
        $rows         = $queryBuilder
            ->select(...$fields)
            ->from(self::TABLE)
            ->executeQuery()
            ->fetchAllAssociative();

        self::assertCount(1, $rows);
        self::assertSame($identifier, $rows[0]['identifier'] ?? null);
        self::assertNotContains('secret_input', $fields);
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function accessCheckProvider(): iterable
    {
        yield 'with user access check' => [true];
        yield 'without user access check' => [false];
    }

    /**
     * FormEngine still renders the vault input for secret_input, and the value
     * submitted under the name it renders ends up in the vault.
     */
    #[Test]
    public function formRendersVaultInputWhoseValueDataHandlerStores(): void
    {
        $formData = GeneralUtility::makeInstance(FormDataCompiler::class)->compile(
            [
                'request'    => $this->backendRequest('/typo3/record/edit', 'GET'),
                'command'    => 'new',
                'tableName'  => self::TABLE,
                'vanillaUid' => 0,
            ],
            GeneralUtility::makeInstance(TcaDatabaseRecord::class),
        );

        $processedTca = $formData['processedTca'] ?? null;
        self::assertIsArray($processedTca);
        $columns = $processedTca['columns'] ?? null;
        self::assertIsArray($columns);
        $secretInput = $columns['secret_input'] ?? null;
        self::assertIsArray($secretInput);
        $config = $secretInput['config'] ?? null;
        self::assertIsArray($config);
        self::assertSame('vaultSecretInput', $config['renderType'] ?? null);

        $options               = $formData;
        $options['fieldName']  = 'secret_input';
        $options['renderType'] = 'singleFieldContainer';
        $result                = $this->get(NodeFactory::class)->create($options)->render();
        $html                  = $result['html'] ?? '';
        self::assertIsString($html);
        self::assertStringContainsString('data-vault-is-new="1"', $html);

        self::assertSame(1, preg_match('/<input[^>]*\bname="(data\[tx_nrvault_secret\]\[(NEW[^\]]+)\]\[secret_input\])"/', $html, $match));
        $newId = $match[2];

        $identifier  = 'form_secret_' . bin2hex(random_bytes(4));
        $plaintext   = 'form-plaintext-' . bin2hex(random_bytes(4));
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                self::TABLE => [
                    $newId => [
                        'pid'          => 0,
                        'identifier'   => $identifier,
                        'secret_input' => $plaintext,
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        /** @phpstan-ignore property.internal */
        self::assertSame([], $dataHandler->errorLog);
        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier));
    }

    private function backendRequest(string $path, string $method): ServerRequestInterface
    {
        // Core marks its own ServerRequest and the application-type constant
        // @internal and offers no public equivalent for a backend request.
        /** @phpstan-ignore new.internalClass, method.internalClass */
        $request = new ServerRequest('https://localhost' . $path, $method);

        /** @phpstan-ignore method.internalClass, classConstant.internal */
        return $request->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_BE);
    }

    private function createSecret(string $plaintext): string
    {
        $identifier  = 'list_secret_' . bin2hex(random_bytes(4));
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                self::TABLE => [
                    'NEW1' => [
                        'pid'          => 0,
                        'identifier'   => $identifier,
                        'secret_input' => $plaintext,
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();
        /** @phpstan-ignore property.internal */
        self::assertSame([], $dataHandler->errorLog);

        return $identifier;
    }
}
