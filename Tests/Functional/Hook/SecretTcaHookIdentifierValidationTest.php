<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Hook\SecretTcaHook;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Identifiers the vault cannot represent are REFUSED, not rewritten.
 *
 * The gap this pins: the TCA column carried `eval => trim,alphanum_x`, and no
 * code path compared the submitted identifier against `IdentifierValidator`.
 * DataHandler's `checkValue()` therefore stripped whatever the pattern
 * disliked and stored the remainder — `<script>alert(1)</script>` became a
 * live secret called `scriptalert1script`. Nothing failed, nothing was logged,
 * and the editor was never told: the record simply existed under a name nobody
 * had chosen, unfindable by the one they typed.
 *
 * The refusal is a pre-process one, like the `secret.create` gate next to it:
 * `processDatamap_preProcessFieldArray()` nulls the by-ref field array, which
 * makes core skip the record before `insertDB()`. These tests drive the REAL
 * DataHandler, so "no row exists" is produced by core rather than asserted
 * against a mock — and they check both names, the submitted one and the
 * sanitized one the old behaviour would have left behind.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookIdentifierValidationTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Storage page the editor may write content to. */
    private const STORAGE_PID = 1;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_create_permission.csv';

    protected ?int $backendUserUid = null;

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function rejectedIdentifierProvider(): iterable
    {
        // The finding, verbatim: markup that alphanum_x used to strip down to
        // `scriptalert1script`.
        yield 'script tag' => ['<script>alert(1)</script>', 'scriptalert1script'];
        // An attribute-breaking payload; alphanum_x would have kept `abcimgsrcx`.
        yield 'attribute break-out' => ['abc"><img src=x>', 'abcimgsrcx'];
        // Hyphens passed alphanum_x but were never valid vault identifiers —
        // the two rules disagreed, and the TCA one won silently.
        yield 'hyphen' => ['my-api-key', 'my-api-key'];
        // Below MIN_LENGTH.
        yield 'too short' => ['ab', 'ab'];
        // Must start with a letter.
        yield 'leading digit' => ['1secret', '1secret'];
        // Path traversal: alphanum_x would have produced `etcpasswd`.
        yield 'path traversal' => ['../../etc/passwd', 'etcpasswd'];
    }

    #[Test]
    #[DataProvider('rejectedIdentifierProvider')]
    public function rejectedIdentifierStoresNothingUnderEitherName(
        string $submitted,
        string $sanitized,
    ): void {
        $this->setUpBackendUser(1);

        $dataHandler = $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => $submitted,
            'secret_input' => 'must-not-be-stored',
        ]);

        self::assertNull(
            $this->findRecord($submitted),
            'The submitted identifier must not be stored.',
        );
        self::assertNull(
            $this->findRecord($sanitized),
            'Nor may a sanitized variant be stored — that is the defect: a record '
            . 'under a name the editor never chose.',
        );
        self::assertSame(
            0,
            $this->countRows(),
            'A refused create must leave the table exactly as it was.',
        );

        self::assertStringContainsString(
            'identifier is invalid',
            $this->errorLogText($dataHandler),
            'FormEngine must tell the editor that the identifier was the problem.',
        );
    }

    /**
     * A refusal is an access decision and belongs in the tamper-evident log,
     * the same shape every other refusal in this hook writes.
     */
    #[Test]
    public function rejectedIdentifierIsAudited(): void
    {
        $this->setUpBackendUser(1);
        $payload = '<script>alert(1)</script>';

        $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => $payload,
        ]);

        self::assertSame(
            1,
            $this->countAuditEntries($payload, AuditAction::AccessDenied->value, false),
            'The refused identifier must be audited as access_denied.',
        );
        self::assertSame(
            0,
            $this->countAuditEntries($payload, AuditAction::Create->value, true),
            'A refused create must never produce a success create entry in the HMAC chain.',
        );
    }

    /**
     * The gate must not break the thing it guards.
     */
    #[Test]
    public function acceptedIdentifierStillCreatesTheRecord(): void
    {
        $this->setUpBackendUser(1);
        $identifier = 'valid_identifier_' . bin2hex(random_bytes(4));

        $dataHandler = $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => $identifier,
            'secret_input' => 'a-real-value',
        ]);

        self::assertIsArray(
            $this->findRecord($identifier),
            'A valid identifier must still create. DataHandler log: ' . $this->errorLogText($dataHandler),
        );
    }

    /**
     * `eval => trim` still applies: the editor's stray whitespace is not what
     * the rule is about, and rejecting " valid_id " would be a regression.
     */
    #[Test]
    public function surroundingWhitespaceIsTrimmedRatherThanRejected(): void
    {
        $this->setUpBackendUser(1);
        $identifier = 'padded_identifier_' . bin2hex(random_bytes(4));

        $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => '  ' . $identifier . '  ',
            'secret_input' => 'a-real-value',
        ]);

        self::assertIsArray($this->findRecord($identifier));
    }

    /**
     * Records already stored under an identifier this rule now rejects keep
     * working. The gate judges a SUBMITTED value on a new record; it must not
     * turn a legacy row into something that can neither be edited nor removed.
     */
    #[Test]
    public function legacyRecordWithNowInvalidIdentifierStaysEditable(): void
    {
        $this->setUpBackendUser(1);
        $legacy = 'legacy-invalid-identifier';
        $uid = $this->insertLegacyRecord($legacy);

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [self::SECRET_TABLE => [$uid => ['description' => 'Edited after the rule changed']]],
            [],
        );
        $dataHandler->process_datamap();

        $record = $this->findRecord($legacy);
        self::assertIsArray(
            $record,
            'The legacy row must survive the edit. DataHandler log: ' . $this->errorLogText($dataHandler),
        );
        self::assertSame('Edited after the rule changed', $record['description']);
    }

    #[Test]
    public function legacyRecordWithNowInvalidIdentifierStaysDeletable(): void
    {
        $this->setUpBackendUser(1);
        $legacy = 'legacy-deletable-identifier';
        $uid = $this->insertLegacyRecord($legacy);

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start([], [self::SECRET_TABLE => [$uid => ['delete' => 1]]]);
        $dataHandler->process_cmdmap();

        self::assertNull(
            $this->findRecord($legacy),
            'A legacy row must remain removable. DataHandler log: ' . $this->errorLogText($dataHandler),
        );
    }

    /**
     * Run one NEW-record datamap through the real DataHandler.
     *
     * @param array<string, mixed> $fieldArray
     */
    private function processCreate(array $fieldArray): DataHandler
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start([self::SECRET_TABLE => ['NEW1' => $fieldArray]], []);
        $dataHandler->process_datamap();

        return $dataHandler;
    }

    /**
     * Write a row straight to the table, bypassing DataHandler — the state an
     * installation upgraded from the sanitizing behaviour is actually in.
     */
    private function insertLegacyRecord(string $identifier): int
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            'pid' => self::STORAGE_PID,
            'identifier' => $identifier,
            'description' => 'Stored before the identifier rule was enforced',
            'owner_uid' => 1,
            'crdate' => time(),
            'tstamp' => time(),
        ]);

        return (int) $connection->lastInsertId();
    }

    /**
     * Finds the row regardless of its delete/disable state — a refused create
     * must not be hidden behind a restriction, it must not exist.
     *
     * @return array<string, mixed>|null
     */
    private function findRecord(string $identifier): ?array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $row = $queryBuilder
            ->select('uid', 'identifier', 'description', 'deleted')
            ->from(self::SECRET_TABLE)
            ->where($queryBuilder->expr()->eq(
                'identifier',
                $queryBuilder->createNamedParameter($identifier),
            ))
            ->executeQuery()
            ->fetchAssociative();

        if ($row === false) {
            return null;
        }

        return (int) $row['deleted'] === 1 ? null : $row;
    }

    private function countRows(): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $count = $queryBuilder->count('uid')->from(self::SECRET_TABLE)->executeQuery()->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }

    private function countAuditEntries(string $identifier, string $action, bool $success): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)),
                $queryBuilder->expr()->eq(
                    'success',
                    $queryBuilder->createNamedParameter($success ? 1 : 0, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }

    private function errorLogText(DataHandler $dataHandler): string
    {
        /** @phpstan-ignore property.internal */
        $errorLog = $dataHandler->errorLog;

        $lines = [];
        foreach ($errorLog as $line) {
            if (\is_scalar($line)) {
                $lines[] = (string) $line;
            }
        }

        return implode("\n", $lines);
    }
}
