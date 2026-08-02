<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfiguration;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Crypto\MasterKeyProviderFactoryInterface;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;
use Netresearch\NrVault\Service\VaultHealthServiceInterface;

/**
 * The master key: is one configured, permitted, reachable, and protected on disk?
 *
 * This is the check whose failure means the vault is not a vault. Everything
 * else degrades gracefully; a master key that cannot be read makes every stored
 * secret unrecoverable, and a master key the web server group can read makes the
 * envelope encryption decorative.
 *
 * The liveness probe is delegated to {@see VaultHealthServiceInterface} rather
 * than re-implemented, so the CLI gate and the module's health banner cannot
 * disagree about whether encryption works — and so this check inherits that
 * service's rule of never letting a raw exception message (which can carry the
 * key file path) reach the caller.
 *
 * For the same reason no finding here carries the key path. Only the octal file
 * mode travels in `details`: the JSON report is written to CI logs, and a log
 * line naming the master-key location is a gift to anyone reading build output.
 */
final readonly class MasterKeyProviderCheck implements ReadinessCheckInterface
{
    /**
     * The provider that derives the master key from TYPO3's own encryption key.
     *
     * Also the extension's zero-config default, which is why "the provider is
     * `typo3`" and "no provider was chosen" are the same observation.
     */
    private const PROVIDER_TYPO3 = 'typo3';

    private const PROVIDER_FILE = 'file';

    public function __construct(
        private ExtensionConfigurationInterface $configuration,
        private MasterKeyProviderFactoryInterface $providerFactory,
        private VaultHealthServiceInterface $healthService,
    ) {}

    public function getId(): string
    {
        return 'provider';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    public function run(DoctorContext $context): array
    {
        $configured = $this->configuration->getMasterKeyProvider();

        $findings = [
            $this->checkConfigured($context, $configured),
            $this->checkKnown($configured),
            ...$this->checkLiveness($configured),
        ];

        if ($configured === self::PROVIDER_FILE) {
            $findings[] = $this->checkKeyFilePermissions();
        }

        return $findings;
    }

    /**
     * Is a provider chosen, and is that provider permitted under the target
     * profile?
     *
     * One control rather than two because the failing case is the same one: the
     * TYPO3 encryption key is both the unconfigured default and the value the
     * hardened profile forbids. Splitting them would report the identical
     * observation twice.
     */
    private function checkConfigured(DoctorContext $context, string $configured): Finding
    {
        $id = 'provider.configured';

        if (trim($configured) === '') {
            return Finding::critical(
                id: $id,
                summary: 'No master-key provider is configured.',
                risk: 'The vault cannot derive a master key, so no secret can be stored or read.',
                remediation: 'Set the "masterKeyProvider" extension setting to file or env, then run '
                    . 'vendor/bin/typo3 vault:init.',
                docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
                details: ['provider' => ''],
            );
        }

        if ($configured !== self::PROVIDER_TYPO3) {
            return Finding::pass(
                id: $id,
                summary: \sprintf('Master-key provider "%s" is explicitly configured.', $configured),
                docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
                details: ['provider' => $configured],
            );
        }

        // The TYPO3 provider is in use — the extension default, i.e. also the
        // state of an installation where nobody made a choice.
        if ($context->isHardened()) {
            return Finding::critical(
                id: $id,
                summary: 'The hardened profile forbids the "typo3" master-key provider, but it is in use.',
                risk: 'Vault secrets share their key with $GLOBALS[TYPO3_CONF_VARS][SYS][encryptionKey], '
                    . 'which lives in a file every deployment copies and which other extensions also read. '
                    . 'One leaked configuration file loses every secret in the vault.',
                remediation: 'Configure an external provider ("file" or "env") and re-encrypt with '
                    . 'vendor/bin/typo3 vault:rotate-master-key. The provider factory refuses to boot the '
                    . 'hardened profile on "typo3", so this must be fixed before the vault will run at all.',
                docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
                details: ['provider' => $configured, 'profile' => $context->profile->value],
            );
        }

        return Finding::warning(
            id: $id,
            summary: 'The master key is derived from the TYPO3 encryption key (zero-configuration default).',
            risk: 'The vault shares its key with the rest of the installation: anyone who can read '
                . 'the system configuration can decrypt every secret, and rotating the TYPO3 '
                . 'encryption key silently makes the vault unreadable.',
            remediation: 'For anything holding third-party credentials, move to the "file" or "env" '
                . 'provider and re-encrypt with vendor/bin/typo3 vault:rotate-master-key.',
            docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
            details: ['provider' => $configured],
        );
    }

    /**
     * Can the factory actually build the configured provider?
     *
     * Deliberately generic: the finding names whatever identifier is configured
     * without a hard-coded list of valid ones, so a provider shipped by a later
     * release (or by a consuming extension) that is configured on an installation
     * which does not have it reports as "unknown here" rather than as a passing
     * control.
     */
    private function checkKnown(string $configured): Finding
    {
        $id = 'provider.known';

        try {
            $this->providerFactory->create();
        } catch (ConfigurationException $e) {
            return Finding::critical(
                id: $id,
                summary: \sprintf('The configured master-key provider "%s" cannot be built.', $configured),
                risk: 'Every vault operation fails at the crypto boundary. The message is: ' . $e->getMessage(),
                remediation: 'Correct the "masterKeyProvider" extension setting, or install the extension '
                    . 'that supplies this provider.',
                docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
                details: ['provider' => $configured],
            );
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf('Master-key provider "%s" resolves.', $configured),
            docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
            details: ['provider' => $configured],
        );
    }

    /**
     * Is a key present, and does it actually decrypt?
     *
     * Two controls from one probe: `provider.available` answers "is there a key
     * source at all", `provider.master_key_readable` answers "can we read a
     * non-empty key out of it". They fail independently — a present but truncated
     * key file passes the first and fails the second.
     *
     * @return list<Finding>
     */
    private function checkLiveness(string $configured): array
    {
        $status = $this->healthService->checkHealth();
        $resolved = $status->masterKeyProvider;

        if (!$status->masterKeyAvailable) {
            $available = Finding::critical(
                id: 'provider.available',
                summary: 'No master-key provider is available at runtime.',
                risk: 'Secrets cannot be read. Existing ciphertext stays in the database but is '
                    . 'unusable until the key source is restored.',
                remediation: 'Run vendor/bin/typo3 vault:init to verify the configuration, then check '
                    . 'the TYPO3 log — the provider records why it is unavailable there (the reason can '
                    . 'name the key path, so it is logged rather than shown here).',
                docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
                details: ['configuredProvider' => $configured, 'resolvedProvider' => $resolved],
            );
        } elseif ($resolved !== '' && $resolved !== $configured) {
            // Standard-profile auto-detection found a usable key somewhere other
            // than the configured source. The vault works, but it is not working
            // the way the configuration says it does — and a later hardening
            // switch turns that into an outage, because the hardened factory does
            // not auto-detect.
            $available = Finding::warning(
                id: 'provider.available',
                summary: \sprintf(
                    'The configured provider is "%s" but the runtime resolved "%s" by auto-detection.',
                    $configured,
                    $resolved,
                ),
                risk: 'Secrets are protected by a different key source than the configuration states, '
                    . 'so key rotation and backup procedures written against the configuration will miss '
                    . 'the key actually in use. Switching to the hardened profile removes auto-detection '
                    . 'and turns this into an immediate outage.',
                remediation: \sprintf(
                    'Either make "%s" usable, or set "masterKeyProvider" to "%s" to match reality.',
                    $configured,
                    $resolved,
                ),
                docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
                details: ['configuredProvider' => $configured, 'resolvedProvider' => $resolved],
            );
        } else {
            $available = Finding::pass(
                id: 'provider.available',
                summary: \sprintf('Master-key provider "%s" is available.', $resolved),
                docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
                details: ['resolvedProvider' => $resolved],
            );
        }

        $readable = $status->encryptionWorking
            ? Finding::pass(
                id: 'provider.master_key_readable',
                summary: 'The master key was read and envelope encryption is operational.',
                docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
            )
            : Finding::critical(
                id: 'provider.master_key_readable',
                summary: 'The master key could not be read.',
                risk: 'Every store, retrieve and rotate operation fails. Secrets already in the '
                    . 'database cannot be decrypted while this persists.',
                remediation: 'Check the key source exists, is readable by the web server / CLI user, and '
                    . 'holds a 32-byte key (raw or base64). The provider logs the specific reason via '
                    . 'PSR-3; it is not repeated here because it can contain the key path.',
                docsUrl: DocsLink::MASTER_KEY_PROVIDERS,
                details: ['resolvedProvider' => $resolved],
            );

        return [$available, $readable];
    }

    /**
     * Is the key file readable by anyone other than its owner?
     *
     * File-provider only. The resolution mirrors
     * {@see \Netresearch\NrVault\Crypto\FileMasterKeyProvider}: the configured
     * source when it is a real path, otherwise the auto-generated development
     * path the provider falls back to.
     */
    private function checkKeyFilePermissions(): Finding
    {
        $id = 'provider.key_permissions';
        $path = $this->resolveKeyFilePath();

        if ($path === null) {
            return Finding::warning(
                id: $id,
                summary: 'The master-key file permissions could not be inspected because no key file exists '
                    . 'at the configured or fallback path.',
                risk: 'A key file that is not there cannot be protected, and the file provider will fail '
                    . 'on the next read.',
                remediation: 'Set "masterKeySource" to the absolute path of the key file, or generate one '
                    . 'with vendor/bin/typo3 vault:init.',
                docsUrl: DocsLink::MASTER_KEY_FILE,
            );
        }

        clearstatcache(true, $path);
        $perms = fileperms($path);

        if ($perms === false) {
            return Finding::warning(
                id: $id,
                summary: 'The master-key file exists but its permissions could not be read.',
                risk: 'The file may be group- or world-readable without this check noticing.',
                remediation: 'Inspect the file mode manually; it must be 0400 or 0600 and owned by the '
                    . 'user the web server and CLI run as.',
                docsUrl: DocsLink::MASTER_KEY_FILE,
            );
        }

        $mode = $perms & 0o777;
        $octal = \sprintf('0%o', $mode);

        // Group or other holding read, write or execute. Read is the one that
        // loses the secrets; write and execute are included because a mode that
        // loose is never intentional.
        if (($mode & 0o077) !== 0) {
            return Finding::critical(
                id: $id,
                summary: \sprintf('The master-key file is accessible beyond its owner (mode %s).', $octal),
                risk: 'Any local account in the file\'s group — on shared hosting, every other site on '
                    . 'the box — can read the key and decrypt every secret in the vault. Envelope '
                    . 'encryption provides no protection once the master key is readable.',
                remediation: 'chmod 0400 the key file and chown it to the user the web server and CLI '
                    . 'run as. If the key was ever group-readable, treat it as compromised: generate a '
                    . 'new one and run vendor/bin/typo3 vault:rotate-master-key.',
                docsUrl: DocsLink::MASTER_KEY_FILE,
                details: ['mode' => $octal],
            );
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf('The master-key file is owner-only (mode %s).', $octal),
            docsUrl: DocsLink::MASTER_KEY_FILE,
            details: ['mode' => $octal],
        );
    }

    /**
     * The key file the file provider would actually read, or null when neither
     * candidate exists.
     */
    private function resolveKeyFilePath(): ?string
    {
        $source = trim($this->configuration->getMasterKeySource());
        if (
            $source !== ''
            && $source !== ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE
            && is_file($source)
        ) {
            return $source;
        }

        $autoPath = $this->configuration->getAutoKeyPath();

        return is_file($autoPath) ? $autoPath : null;
    }
}
