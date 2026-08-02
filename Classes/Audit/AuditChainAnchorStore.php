<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use InvalidArgumentException;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use SensitiveParameter;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Stores the MAC-signed audit chain tip anchor in the CORE table
 * `sys_registry`, reached ONLY through our own Doctrine QueryBuilder.
 *
 * Why `sys_registry` and not a table of our own: a new table in
 * `ext_tables.sql` reopens the window between "extension files updated" and
 * "database:updateschema run". Failing closed in that window takes every vault
 * read down (`VaultService::retrieve()` logs without a try/catch); failing
 * open makes the control attacker-selectable by `DROP TABLE`. `sys_registry`
 * ships in core's own `ext_tables.sql`, so it exists in every installation
 * before nr_vault is installed — no schema change, no upgrade window, no
 * trade-off to make.
 *
 * Why never `TYPO3\CMS\Core\Registry`: its `get()` routes through
 * `loadEntriesByNamespace()`, which `unserialize()`s every row of the
 * namespace with no `allowed_classes` — an object-injection sink fed by bytes
 * a DB-write attacker controls. This class does one `SELECT`, one anchored
 * `preg_match()` and one `hash_equals()`; a regex cannot emit a PHP object.
 * `Tests/Architecture/ArchitectureTest::testAuditAnchorNeverUsesCoreRegistry()`
 * turns a maintainer "tidying" this into the Registry API into a build failure.
 */
final readonly class AuditChainAnchorStore implements AuditChainAnchorStoreInterface
{
    private const REGISTRY_TABLE = 'sys_registry';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /**
     * The anchor gets its OWN namespace, never `tx_nrvault`: the anchor value
     * is deliberately raw (not PHP-serialized — see the class docblock), while
     * core's `Registry::get()` unserializes EVERY row of a namespace it loads.
     * Other extension state (break-glass session, sink delivery state) lives
     * in the `tx_nrvault` namespace via the core Registry API; sharing a
     * namespace with the raw anchor makes every one of those reads throw a
     * DeserializerException.
     */
    private const ENTRY_NAMESPACE = 'tx_nrvault_audit_anchor';

    private const ENTRY_KEY = 'auditChainTip';

    private const FORMAT_PREFIX = 'nrvault-audit-tip.v1';

    /**
     * Anchored, total pattern — the only accepted shape. No optional parts, no
     * unbounded quantifiers, nothing that could match a `serialize()` payload.
     */
    private const VALUE_PATTERN = '/^nrvault-audit-tip\.v1\|(\d{1,19})\|([0-9a-f]{64})\|(\d{1,10})\|([0-9a-f]{64})$/';

    private const HASH_PATTERN = '/^[0-9a-f]{64}$/';

    /**
     * HKDF info string. Deliberately distinct from the chain key's
     * `nr-vault-audit-hmac-v1` (see
     * {@see AuditLogService::deriveHmacKeyFromMasterKey()}), so an anchor MAC
     * and a row hash are not interchangeable.
     */
    private const HKDF_INFO = 'nr-vault-audit-anchor-v1';

    public function __construct(
        private ConnectionPool $connectionPool,
        private MasterKeyProviderInterface $masterKeyProvider,
        private ExtensionConfigurationInterface $extensionConfiguration,
    ) {}

    public function isEnabled(): bool
    {
        return $this->extensionConfiguration->getAuditHmacEpoch() >= 1;
    }

    public function sharesConnection(Connection $auditConnection): bool
    {
        return $this->connectionPool->getConnectionForTable(self::REGISTRY_TABLE) === $auditConnection;
    }

    public function advance(
        Connection $connection,
        AuditChainAnchor $tip,
        #[SensitiveParameter]
        ?string $masterKey = null,
    ): void {
        if (!$this->isEnabled() || !$this->sharesConnection($connection)) {
            return;
        }

        $anchorKey = $this->deriveAnchorKey($masterKey);

        try {
            $raw = $this->readRaw($connection);
            if ($raw === null) {
                if ($this->refusesImplicitArming()) {
                    // No anchor row, and the operator has asserted this install
                    // is armed. Minting a fresh anchor here would attest that
                    // whatever the chain has been cut down to is genuine —
                    // strictly worse than having no anchor at all. Arming again
                    // is an explicit operator action: {@see self::arm()} /
                    // `vault:audit --reset-anchor`.
                    return;
                }
            } else {
                $stored = $this->parse($raw, $anchorKey);
                if (!$stored instanceof AuditChainAnchor) {
                    // Corrupted or foreign-MAC anchor: leave it. Repairing it
                    // here would hand an attacker who truncates AND corrupts a
                    // clean verdict back on the next append.
                    return;
                }

                if (!$this->assertionStillHolds($connection, $stored)) {
                    // The anchor is already violated. It must NOT be advanced
                    // past the violation: otherwise an attacker truncates, then
                    // lets ordinary traffic regrow the log beyond the anchored
                    // uid, and the anchor quietly re-arms on the shortened
                    // chain. Once violated the anchor stands as evidence until
                    // an operator clears it with `vault:audit --reset-anchor`,
                    // which records the reset in the chain itself.
                    return;
                }

                if ($stored->uid >= $tip->uid) {
                    // Forward-only. Guards against out-of-order writers such as
                    // the lock-free demo seeder. This is a CORRECTNESS property,
                    // not a security control — an attacker writing raw SQL never
                    // passes through this code.
                    return;
                }
            }

            $this->write($connection, $this->encode($tip, $anchorKey), $raw !== null);
        } finally {
            sodium_memzero($anchorKey);
        }
    }

    public function reseal(
        Connection $connection,
        #[SensitiveParameter]
        ?string $masterKey = null,
    ): void {
        if (!$this->isEnabled() || !$this->sharesConnection($connection)) {
            return;
        }

        $tip = $this->fetchTip($connection);
        if (!$tip instanceof AuditChainAnchor) {
            // Empty chain: keep whatever is stored. Deleting the anchor here
            // would be a downgrade an attacker could induce by wiping the table.
            return;
        }

        $anchorKey = $this->deriveAnchorKey($masterKey);

        try {
            $raw = $this->readRaw($connection);
            if ($raw === null && $this->refusesImplicitArming()) {
                // Same rule as advance(): a re-seal re-signs an anchor, it does
                // not create one on a chain the operator has declared anchored.
                return;
            }

            $stored = $raw === null ? null : $this->parse($raw, $anchorKey);
            if ($stored instanceof AuditChainAnchor) {
                if ($stored->uid === $tip->uid && hash_equals($stored->entryHash, $tip->entryHash)) {
                    // Already asserts exactly this tip. The stored `tstamp` differs
                    // on every call (it is minted here), so the comparison is on
                    // (uid, entry_hash) — comparing raw bytes would rewrite the row
                    // on every re-seal for no reason.
                    return;
                }

                if (!$this->anchoredRowStillExists($connection, $stored->uid) || $tip->uid < $stored->uid) {
                    // A re-seal re-signs the SAME rows under a new key or a new
                    // epoch; it is not licence to sign a shorter chain. All three
                    // legitimate paths preserve uids (they only rewrite
                    // `entry_hash`/`previous_hash` `WHERE uid = …`), so neither
                    // condition can fire on them — and both fire on a truncation.
                    //
                    // Unlike advance(), this cannot compare the anchored HASH:
                    // rewriting exactly that hash is what a re-seal does. Existence
                    // plus uid monotonicity is the strongest assertion that
                    // survives a legitimate re-seal.
                    return;
                }
            }

            $this->write($connection, $this->encode($tip, $anchorKey), $raw !== null);
        } finally {
            sodium_memzero($anchorKey);
        }
    }

    public function arm(
        Connection $connection,
        #[SensitiveParameter]
        ?string $masterKey = null,
    ): bool {
        if (!$this->isEnabled() || !$this->sharesConnection($connection)) {
            return false;
        }

        $tip = $this->fetchTip($connection);
        if (!$tip instanceof AuditChainAnchor) {
            return false;
        }

        $anchorKey = $this->deriveAnchorKey($masterKey);

        try {
            $this->write($connection, $this->encode($tip, $anchorKey), $this->readRaw($connection) !== null);
        } finally {
            sodium_memzero($anchorKey);
        }

        return true;
    }

    public function reset(Connection $connection): void
    {
        if (!$this->sharesConnection($connection)) {
            return;
        }

        $connection->delete(
            self::REGISTRY_TABLE,
            ['entry_namespace' => self::ENTRY_NAMESPACE, 'entry_key' => self::ENTRY_KEY],
        );
    }

    public function load(Connection $auditConnection): AuditChainAnchorLoad
    {
        if (!$this->isEnabled()) {
            return new AuditChainAnchorLoad(AuditChainAnchorStatus::Disabled);
        }

        if (!$this->sharesConnection($auditConnection)) {
            return new AuditChainAnchorLoad(AuditChainAnchorStatus::Unanchored);
        }

        $raw = $this->readRaw($auditConnection);
        if ($raw === null) {
            return new AuditChainAnchorLoad(AuditChainAnchorStatus::Unanchored);
        }

        $anchorKey = $this->deriveAnchorKey(null);

        try {
            $anchor = $this->parse($raw, $anchorKey);
        } finally {
            sodium_memzero($anchorKey);
        }

        if (!$anchor instanceof AuditChainAnchor) {
            return new AuditChainAnchorLoad(AuditChainAnchorStatus::Unreadable, null, $raw);
        }

        return new AuditChainAnchorLoad(AuditChainAnchorStatus::Ok, $anchor, $raw);
    }

    /**
     * Derive the anchor MAC key. Separate HKDF info string from the chain key,
     * so a row hash can never be replayed as an anchor MAC or vice versa.
     */
    private function deriveAnchorKey(#[SensitiveParameter] ?string $masterKey): string
    {
        if ($masterKey !== null) {
            return hash_hkdf('sha256', $masterKey, 32, self::HKDF_INFO);
        }

        $providerKey = $this->masterKeyProvider->getMasterKey();

        try {
            return hash_hkdf('sha256', $providerKey, 32, self::HKDF_INFO);
        } finally {
            sodium_memzero($providerKey);
        }
    }

    private function encode(AuditChainAnchor $tip, #[SensitiveParameter] string $anchorKey): string
    {
        if ($tip->uid < 1 || preg_match(self::HASH_PATTERN, $tip->entryHash) !== 1 || $tip->tstamp < 0) {
            // Fail loudly rather than store bytes our own reader would reject:
            // callers wrap this into AuditWriteException, so the audit write
            // (and with it the audited operation) fails closed.
            throw new InvalidArgumentException(
                'Refusing to anchor a tip that does not match the anchor value format.',
                1753900002,
            );
        }

        return \sprintf(
            '%s|%d|%s|%d|%s',
            self::FORMAT_PREFIX,
            $tip->uid,
            $tip->entryHash,
            $tip->tstamp,
            $this->mac($tip, $anchorKey),
        );
    }

    /**
     * Parse and authenticate a stored value. Returns null on ANY deviation —
     * wrong format, wrong MAC. The regex runs before the MAC so a hostile
     * payload never reaches anything but `preg_match()`.
     */
    private function parse(string $raw, #[SensitiveParameter] string $anchorKey): ?AuditChainAnchor
    {
        if (preg_match(self::VALUE_PATTERN, $raw, $matches) !== 1) {
            return null;
        }

        $anchor = new AuditChainAnchor((int) $matches[1], $matches[2], (int) $matches[3]);

        return hash_equals($this->mac($anchor, $anchorKey), $matches[4]) ? $anchor : null;
    }

    private function mac(AuditChainAnchor $anchor, #[SensitiveParameter] string $anchorKey): string
    {
        return hash_hmac(
            'sha256',
            json_encode([
                'v' => 1,
                'uid' => $anchor->uid,
                'entry_hash' => $anchor->entryHash,
                'tstamp' => $anchor->tstamp,
            ], JSON_THROW_ON_ERROR),
            $anchorKey,
        );
    }

    /**
     * Read the stored bytes. `null` means — and means ONLY — that no anchor
     * ROW exists.
     *
     * The distinction is load-bearing in both directions, so this reads the row
     * rather than the value (`fetchAssociative()`, not `fetchOne()`):
     *
     *  - `UPDATE sys_registry SET entry_value = NULL …` must not read back as
     *    "never anchored". If it did, an attacker could blank the anchor
     *    without deleting the row and let the next ordinary audit write mint a
     *    fresh, correctly signed anchor on a truncated chain. A present row
     *    with an unusable value is returned as `''`, which no pattern accepts,
     *    so it lands in the "corrupted anchor — leave it alone" branch of
     *    `advance()` and is reported `Unreadable` (an ERROR) by the verifier.
     *  - `write()` picks INSERT vs UPDATE from this result. Treating a nulled
     *    row as absent would attempt an INSERT against the
     *    `entry_identifier` unique key and fail every audit write from then on.
     *
     * `entry_value` is a `mediumblob` (`bytea` on PostgreSQL), so the driver
     * may hand back a stream instead of a string.
     */
    private function readRaw(Connection $connection): ?string
    {
        $queryBuilder = $connection->createQueryBuilder();
        $queryBuilder->getRestrictions()->removeAll();

        $row = $queryBuilder
            ->select('entry_value')
            ->from(self::REGISTRY_TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'entry_namespace',
                    $queryBuilder->createNamedParameter(self::ENTRY_NAMESPACE),
                ),
                $queryBuilder->expr()->eq(
                    'entry_key',
                    $queryBuilder->createNamedParameter(self::ENTRY_KEY),
                ),
            )
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        if ($row === false) {
            return null;
        }

        $value = $row['entry_value'] ?? null;

        if (\is_resource($value)) {
            $contents = stream_get_contents($value);

            return \is_string($contents) ? $contents : '';
        }

        return \is_string($value) ? $value : '';
    }

    /**
     * Whether creating a NEW anchor out of an absent one is refused.
     *
     * `auditAnchorRequired` is the operator's assertion that this installation
     * is already anchored — and it lives in a settings FILE, so a database-write
     * attacker cannot flip it. Under that assertion an absent anchor is not the
     * pre-anchor bootstrap case; it is an anchor that was removed. Signing a
     * fresh one there is the worst available outcome: the shortened tip becomes
     * a MAC-attested tip, and the install reports `Ok` forever.
     *
     * The refusal is UNCONDITIONAL — it deliberately does not probe the audit
     * table first. An earlier revision only refused when a row existed BELOW the
     * tip being anchored, to keep a genuinely fresh chain bootstrapping under
     * the flag. That probe cannot work, because the state it must observe is
     * exactly the state the attacker deletes: at the moment `advance()` runs,
     * `insertAndUpdateHash()` has just written the ONE row the chain has, so a
     * fully emptied log (`DELETE FROM tx_nrvault_audit_log` with no `WHERE`) is
     * indistinguishable from a fresh installation. The uid gap cannot stand in
     * for it either — the walk starts at `previousUid = -1`, so a chain that now
     * begins at uid 7 has no leading gap. Deleting MORE rows is easier than
     * deleting some, so any emptiness probe hands the attacker the cheaper path.
     *
     * Nothing legitimate needs implicit arming while the flag is set: the flag
     * means "this installation is already anchored", and its documented enable
     * point is "after the first audit write following the upgrade". Bootstrap
     * therefore stays possible in exactly two shapes, so the flag can never
     * wedge an installation:
     *
     *  - the flag is off (the shipped default) — the documented upgrade path is
     *    "let the next audit write arm the anchor, then enable the flag";
     *  - explicitly, through {@see self::arm()} — `vault:audit --reset-anchor`,
     *    which records the reset in the chain itself.
     */
    private function refusesImplicitArming(): bool
    {
        return $this->extensionConfiguration->isAuditAnchorRequired();
    }

    /**
     * Bind `entry_value` as a LOB, exactly as core's own `Registry::set()`
     * does — that is what makes the `mediumblob`/`bytea` column work on
     * PostgreSQL.
     */
    private function write(Connection $connection, string $value, bool $exists): void
    {
        if ($exists) {
            $connection->update(
                self::REGISTRY_TABLE,
                ['entry_value' => $value],
                ['entry_namespace' => self::ENTRY_NAMESPACE, 'entry_key' => self::ENTRY_KEY],
                ['entry_value' => Connection::PARAM_LOB],
            );

            return;
        }

        $connection->insert(
            self::REGISTRY_TABLE,
            [
                'entry_namespace' => self::ENTRY_NAMESPACE,
                'entry_key' => self::ENTRY_KEY,
                'entry_value' => $value,
            ],
            ['entry_value' => Connection::PARAM_LOB],
        );
    }

    /**
     * Whether the stored anchor's own assertion — "row `uid` still exists and
     * still carries `entryHash`" — is still true.
     *
     * One primary-key lookup per audit write, and it is what makes the control
     * monotone: a violated anchor is never overtaken by ordinary traffic.
     */
    private function assertionStillHolds(Connection $connection, AuditChainAnchor $stored): bool
    {
        $queryBuilder = $connection->createQueryBuilder();
        $hash = $queryBuilder
            ->select('entry_hash')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'uid',
                    $queryBuilder->createNamedParameter($stored->uid, Connection::PARAM_INT),
                ),
            )
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return \is_string($hash) && hash_equals($stored->entryHash, $hash);
    }

    /**
     * Whether the row the stored anchor points at is still there.
     *
     * Existence only — {@see self::assertionStillHolds()} additionally compares
     * the hash, which a re-seal legitimately rewrites.
     */
    private function anchoredRowStillExists(Connection $connection, int $uid): bool
    {
        $queryBuilder = $connection->createQueryBuilder();
        $hash = $queryBuilder
            ->select('entry_hash')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'uid',
                    $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT),
                ),
            )
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return \is_string($hash);
    }

    /**
     * Current tip of the audit chain on the caller's connection, read inside
     * the caller's lock/transaction. `reseal()` re-reads it rather than taking
     * it as an argument because `AuditChainRekeyServiceInterface::rekeyChain()`
     * returns `int`, and widening that is a public-API change.
     */
    private function fetchTip(Connection $connection): ?AuditChainAnchor
    {
        $row = $connection->createQueryBuilder()
            ->select('uid', 'entry_hash')
            ->from(self::AUDIT_TABLE)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        if ($row === false) {
            return null;
        }

        $uid = is_numeric($row['uid'] ?? null) ? (int) $row['uid'] : 0;
        $entryHash = \is_string($row['entry_hash'] ?? null) ? $row['entry_hash'] : '';

        if ($uid < 1 || preg_match(self::HASH_PATTERN, $entryHash) !== 1) {
            return null;
        }

        return new AuditChainAnchor($uid, $entryHash, time());
    }
}
