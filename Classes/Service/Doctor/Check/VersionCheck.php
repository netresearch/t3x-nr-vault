<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;
use Throwable;
use TYPO3\CMS\Core\Information\Typo3Version;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;

/**
 * Which versions are actually running?
 *
 * Basic sanity, and the report's provenance line. Two things a reader of a
 * `vault:doctor` report from three months ago needs: which extension version
 * produced it, and whether it was running on a core it declares support for.
 *
 * Deliberately not a compatibility resolver. Composer already refused to install
 * an unsupported combination, so the only way to reach a version mismatch here is
 * a hand-assembled deployment — rare, but exactly the situation where every other
 * control's result becomes unreliable, so it is worth naming.
 */
final readonly class VersionCheck implements ReadinessCheckInterface
{
    private const EXTENSION_KEY = 'nr_vault';

    public function __construct(
        private Typo3Version $typo3Version,
    ) {}

    public function getId(): string
    {
        return 'version';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    public function run(DoctorContext $context): array
    {
        $emConf = $this->readEmConf();
        $extensionVersion = \is_string($emConf['version'] ?? null) ? $emConf['version'] : '';

        return [
            $this->checkExtensionVersion($extensionVersion),
            $this->checkTypo3Supported($emConf, $extensionVersion),
        ];
    }

    private function checkExtensionVersion(string $extensionVersion): Finding
    {
        $id = 'version.extension';

        if ($extensionVersion === '') {
            return Finding::warning(
                id: $id,
                summary: 'The extension version could not be read from ext_emconf.php.',
                risk: 'A readiness report that cannot state which version produced it is not evidence: '
                    . 'a reviewer cannot tell whether the controls it lists are the ones that release '
                    . 'actually implements.',
                remediation: 'Restore ext_emconf.php from the release artefact — an installation missing '
                    . 'it is incomplete in other ways too.',
            );
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf('nr_vault %s is installed.', $extensionVersion),
            details: ['extensionVersion' => $extensionVersion],
        );
    }

    /**
     * Does the running core fall inside the range the extension declares?
     *
     * @param array<mixed> $emConf
     */
    private function checkTypo3Supported(array $emConf, string $extensionVersion): Finding
    {
        $id = 'version.typo3_supported';
        $running = $this->typo3Version->getVersion();
        $constraint = $this->extractTypo3Constraint($emConf);

        if ($constraint === '') {
            return Finding::warning(
                id: $id,
                summary: \sprintf(
                    'TYPO3 %s is running, but the extension declares no TYPO3 version constraint.',
                    $running,
                ),
                risk: 'Nothing states which cores this build was tested against, so an incompatibility '
                    . 'would surface as a runtime error in the crypto or audit path rather than at '
                    . 'install time.',
                remediation: 'Restore the constraints block in ext_emconf.php from the release artefact.',
                details: ['typo3Version' => $running],
            );
        }

        $range = Typo3VersionRange::fromConstraint($constraint);

        if (!$range instanceof Typo3VersionRange) {
            return Finding::warning(
                id: $id,
                summary: \sprintf(
                    'The declared TYPO3 constraint "%s" is not a parseable version range.',
                    $constraint,
                ),
                risk: 'Compatibility cannot be confirmed from the extension metadata.',
                remediation: 'Express the constraint as "<min>-<max>", e.g. 13.4.0-14.99.99.',
                details: ['typo3Version' => $running, 'constraint' => $constraint],
            );
        }

        $details = [
            'typo3Version' => $running,
            'constraint' => (string) $range,
            'extensionVersion' => $extensionVersion,
        ];

        if (!$range->contains($running)) {
            return Finding::warning(
                id: $id,
                summary: \sprintf(
                    'TYPO3 %s is outside the range nr_vault declares support for (%s).',
                    $running,
                    (string) $range,
                ),
                risk: 'The extension is running on an untested core. Crypto and audit code paths depend '
                    . 'on core APIs that change between major versions, so a silent behaviour change '
                    . 'there is a correctness risk in exactly the code that must not be wrong.',
                remediation: 'Upgrade nr_vault to a release that supports this core, or run the core '
                    . 'version this release declares. Let composer resolve it rather than installing by '
                    . 'hand.',
                details: $details,
            );
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf('TYPO3 %s is within the supported range (%s).', $running, (string) $range),
            details: $details,
        );
    }

    /**
     * @param array<mixed> $emConf
     */
    private function extractTypo3Constraint(array $emConf): string
    {
        $constraints = $emConf['constraints'] ?? null;
        if (!\is_array($constraints)) {
            return '';
        }

        $depends = $constraints['depends'] ?? null;
        if (!\is_array($depends)) {
            return '';
        }

        $typo3 = $depends['typo3'] ?? null;

        return \is_string($typo3) ? $typo3 : '';
    }

    /**
     * Read this extension's own `ext_emconf.php`.
     *
     * Included in an isolated closure scope rather than read with a parser: the
     * file is a PHP array literal by TYPO3 convention, and `include` is how the
     * core itself reads it.
     *
     * Every failure — no package manager (which is the case in a unit-test
     * process), missing file, unexpected contents — degrades to an empty array, so
     * the findings above report the problem instead of an exception taking the
     * whole readiness run into `check.crashed`. Version metadata is the one area
     * where being unable to look is genuinely only worth a warning.
     *
     * `array<mixed>` rather than `array<string, mixed>` on purpose: the contents
     * come from an `include`, so nothing here can prove the key type. Every read
     * above narrows the value it needs.
     *
     * @return array<mixed>
     */
    private function readEmConf(): array
    {
        try {
            $path = ExtensionManagementUtility::extPath(self::EXTENSION_KEY) . 'ext_emconf.php';
        } catch (Throwable) {
            return [];
        }

        if (!is_file($path) || !is_readable($path)) {
            return [];
        }

        $emConf = (static function (string $file, string $extensionKey): mixed {
            $_EXTKEY = $extensionKey;
            /** @var array<string, mixed> $EM_CONF */
            $EM_CONF = [];
            include $file;

            return $EM_CONF[$_EXTKEY] ?? null;
        })($path, self::EXTENSION_KEY);

        return \is_array($emConf) ? $emConf : [];
    }
}
