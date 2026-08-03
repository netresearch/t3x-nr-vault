<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\Doctor\Check\CliAccessCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(CliAccessCheck::class)]
final class CliAccessCheckTest extends TestCase
{
    use DoctorFindingTrait;

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = $this->check(false);

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    /**
     * Off is the default and the safe state — and there is then no group scope
     * nor operation allowlist to assess, so those two controls are dropped
     * rather than emitted as vacuous passes. The legacy-CLI control stays,
     * because that setting is not part of the `allowCliAccess` grant.
     */
    #[Test]
    public function disabledCliAccessEmitsOnlyTheAccessAndLegacyControls(): void
    {
        $findings = $this->check(false)->run($this->doctorContext(SecurityProfile::Hardened));

        self::assertSame(
            ['cli.access', 'cli.frontend_placeholder_legacy'],
            $this->findingIds($findings),
        );
        self::assertTrue($findings[0]->isPass());
    }

    #[Test]
    public function enabledCliAccessEmitsAllFourControls(): void
    {
        $findings = $this->check(true, [42])->run($this->doctorContext(SecurityProfile::Standard));

        self::assertSame(
            ['cli.access', 'cli.access_groups', 'cli.allowed_operations', 'cli.frontend_placeholder_legacy'],
            $this->findingIds($findings),
        );
    }

    /**
     * A deployment pipeline that stores credentials needs this switch, so calling
     * it a defect under the standard profile would be noise.
     */
    #[Test]
    public function enabledCliAccessPassesUnderTheStandardProfile(): void
    {
        $finding = $this->findingById(
            $this->check(true, [42])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.access',
        );

        self::assertTrue($finding->isPass());
    }

    #[Test]
    public function enabledCliAccessIsCriticalUnderTheHardenedProfile(): void
    {
        // The hardened profile promises attributability; an unattributed CLI
        // actor breaks that promise, so this blocks (exit code 2), it does
        // not merely warn.
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check(true, [42])->run($this->doctorContext(SecurityProfile::Hardened)),
            'cli.access',
        );

        self::assertStringContainsString('TechnicalActorContext', $finding->remediation);
    }

    #[Test]
    public function theDefaultOperationAllowlistPasses(): void
    {
        $finding = $this->findingById(
            $this->check(true, [42])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.allowed_operations',
        );

        self::assertTrue($finding->isPass());
        self::assertSame('', $finding->details['highRisk']);
        self::assertSame('secret.use,secret.create,secret.rotate', $finding->details['cliAllowedOperations']);
    }

    /**
     * The pass must not call the remainder "low-risk". `secret.create` makes the
     * CLI actor the owner of what it creates and `secret.rotate` substitutes a
     * credential live consumers already hold — the enum says so itself. The pass
     * asserts "nothing here needs an explicit opt-in", not "this is harmless".
     */
    #[Test]
    public function theOperationAllowlistPassDoesNotCallTheDefaultsLowRisk(): void
    {
        $finding = $this->findingById(
            $this->check(true, [42])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.allowed_operations',
        );

        self::assertStringNotContainsStringIgnoringCase('low-risk', $finding->summary);
        self::assertStringContainsString('explicit opt-in', $finding->summary);
        self::assertStringContainsString('the audit trail cannot name', $finding->summary);
        // Every configured operation stays named in the summary, so the report
        // shows the grant rather than only its size.
        self::assertStringContainsString('secret.use, secret.create, secret.rotate', $finding->summary);
        self::assertStringContainsString('3 automation operation(s)', $finding->summary);
    }

    #[Test]
    public function highRiskOperationsInTheAllowlistAreAWarning(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(true, [42], ['secret.use', 'secret.reveal', 'master_key.rotate'])
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.allowed_operations',
        );

        self::assertSame('secret.reveal,master_key.rotate', $finding->details['highRisk']);
    }

    /**
     * The bug this covers: both permissions are in `VaultPermission::cases()`, so
     * they never counted as unknown either — an allowlist containing them
     * satisfied `$risky === [] && $unknown === []` and reported a clean pass.
     *
     * @param list<string> $operations Configured `cliAllowedOperations`
     * @param string $expectedHighRisk Expected `details['highRisk']`
     */
    #[Test]
    #[DataProvider('optInOperationProvider')]
    public function anOperationThatNeedsAnExplicitOptInIsAWarning(
        array $operations,
        string $expectedHighRisk,
    ): void {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(true, [42], $operations)->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.allowed_operations',
        );

        self::assertSame($expectedHighRisk, $finding->details['highRisk']);
        self::assertSame('', $finding->details['unknown']);
        self::assertStringContainsString('grants high-risk operation(s) ' . str_replace(',', ', ', $expectedHighRisk), $finding->summary);
    }

    /**
     * @return iterable<string, array{list<string>, string}>
     */
    public static function optInOperationProvider(): iterable
    {
        yield 'manage_policy alone' => [
            ['secret.use', 'secret.manage_policy'],
            'secret.manage_policy',
        ];
        yield 'audit.view alone' => [
            ['secret.use', 'audit.view'],
            'audit.view',
        ];
        yield 'both, reported in configured order' => [
            ['secret.use', 'audit.view', 'secret.manage_policy'],
            'audit.view,secret.manage_policy',
        ];
        yield 'both alongside a previously listed one' => [
            ['secret.manage_policy', 'audit.view', 'secret.delete'],
            'secret.manage_policy,audit.view,secret.delete',
        ];
    }

    /**
     * An operator cannot act on "this is high-risk" — the risk text has to say
     * what each of the two newly named permissions actually opens.
     */
    #[Test]
    public function theRiskTextExplainsWhyPolicyManagementAndAuditViewingAreHighRisk(): void
    {
        $finding = $this->findingById(
            $this->check(true, [42], ['secret.manage_policy', 'audit.view'])
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.allowed_operations',
        );

        // manage_policy: the permission that governs the permissions.
        self::assertStringContainsString('allowed_groups', $finding->risk);
        self::assertStringContainsString('write_groups', $finding->risk);
        self::assertStringContainsString('widen its own per-secret reach', $finding->risk);
        // audit.view: no secret access, but the credential topology.
        self::assertStringContainsString('credential topology', $finding->risk);
        self::assertStringContainsString('reconnaissance', $finding->risk);
    }

    /**
     * The narrower route out is a named grant plus a technical actor, not a
     * wider allowlist — and the two controls that legitimately want these
     * permissions have to be named, or the remediation reads as "never grant
     * them" for workflows that genuinely need them.
     */
    #[Test]
    public function theOperationRemediationNamesTheTechnicalActorRouteForScheduledControls(): void
    {
        $finding = $this->findingById(
            $this->check(true, [42], ['audit.view'])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.allowed_operations',
        );

        self::assertStringContainsString('vault:audit-verify', $finding->remediation);
        self::assertStringContainsString('orphan cleanup', $finding->remediation);
        self::assertStringContainsString('technical actor', $finding->remediation);
    }

    /**
     * Guards the pairing the bug came from: a permission may be high-risk or
     * merely known, never neither by accident. Every high-risk token the check
     * carries must be a real `VaultPermission` case (otherwise it is dead
     * configuration that can never match), and the two permissions this change
     * adds must actually be classified.
     */
    #[Test]
    public function everyHighRiskTokenIsARealPermissionAndTheTwoNewOnesAreClassified(): void
    {
        $known = array_map(
            static fn (VaultPermission $permission): string => $permission->value,
            VaultPermission::cases(),
        );

        $reported = [];
        foreach ($known as $permission) {
            $finding = $this->findingById(
                $this->check(true, [42], [$permission])->run($this->doctorContext(SecurityProfile::Standard)),
                'cli.allowed_operations',
            );

            self::assertSame('', $finding->details['unknown'], $permission . ' must be a known value');
            if ($finding->details['highRisk'] !== '') {
                self::assertSame($permission, $finding->details['highRisk']);
                $reported[] = $permission;
            }
        }

        self::assertSame(
            [
                'secret.reveal',
                'secret.delete',
                'secret.manage_policy',
                'audit.view',
                'audit.export',
                'master_key.rotate',
                'vault.configure',
            ],
            $reported,
        );
    }

    #[Test]
    public function unknownAllowlistValuesAreAWarning(): void
    {
        // A typo silently revokes the grant the operator believes exists.
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(true, [42], ['secret.use', 'secret.rotat'])
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.allowed_operations',
        );

        self::assertSame('secret.rotat', $finding->details['unknown']);
    }

    #[Test]
    public function anEmptyGroupListWhileCliAccessIsOnIsAWarning(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(true, [])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.access_groups',
        );

        self::assertSame(0, $finding->details['cliAccessGroupCount']);
    }

    /**
     * `getCliAccessGroups()` maps unparseable configuration values to 0, and group
     * uid 0 does not exist — counting those would report a scoped grant where the
     * configuration actually holds junk.
     */
    #[Test]
    public function groupUidZeroDoesNotCountAsAScopedGrant(): void
    {
        $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(true, [0, 0])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.access_groups',
        );
    }

    #[Test]
    public function aScopedGroupListPasses(): void
    {
        $finding = $this->findingById(
            $this->check(true, [3, 7])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.access_groups',
        );

        self::assertTrue($finding->isPass());
        self::assertSame(2, $finding->details['cliAccessGroupCount']);
    }

    /**
     * The default: the CLI enforces the same allow-set as a frontend request.
     */
    #[Test]
    #[DataProvider('cliAccessStateProvider')]
    public function theStrictDefaultPassesUnderBothProfiles(bool $cliAccessAllowed): void
    {
        foreach (SecurityProfile::cases() as $profile) {
            $finding = $this->findingById(
                $this->check($cliAccessAllowed, [42], legacyCli: false)->run($this->doctorContext($profile)),
                'cli.frontend_placeholder_legacy',
            );

            self::assertTrue($finding->isPass(), $profile->value . ' must pass with the flag off');
            self::assertFalse($finding->details['frontendPlaceholderLegacyCli']);
        }
    }

    /**
     * The trap this control exists for: `frontendPlaceholderLegacyCli` is NOT
     * gated by `allowCliAccess`. `FrontendPlaceholderPolicy::isLegacyContext()`
     * consults only its own flag, so the bypass is fully live on a default
     * installation with CLI access off — and a finding appended to the
     * "CLI access is on" branch alone would be skipped on exactly those
     * installations.
     */
    #[Test]
    #[DataProvider('cliAccessStateProvider')]
    public function theLegacyOptInIsAWarningUnderTheStandardProfileRegardlessOfCliAccess(
        bool $cliAccessAllowed,
    ): void {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check($cliAccessAllowed, [42], legacyCli: true)
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.frontend_placeholder_legacy',
        );

        self::assertTrue($finding->details['frontendPlaceholderLegacyCli']);
        // The concrete path, not a generic "less strict" phrasing: scheduler:run
        // authenticates the _cli_ admin, so the admin bypass already grants the
        // read and this allow-set is the only remaining gate.
        self::assertStringContainsString('scheduler:run', $finding->risk);
        self::assertStringContainsString('_cli_', $finding->risk);
    }

    #[Test]
    #[DataProvider('cliAccessStateProvider')]
    public function theLegacyOptInIsCriticalUnderTheHardenedProfileRegardlessOfCliAccess(
        bool $cliAccessAllowed,
    ): void {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check($cliAccessAllowed, [42], legacyCli: true)
                ->run($this->doctorContext(SecurityProfile::Hardened)),
            'cli.frontend_placeholder_legacy',
        );

        self::assertTrue($finding->details['frontendPlaceholderLegacyCli']);
    }

    /**
     * Escalating must keep every text field, so a `--profile=hardened` dry run
     * is comparable to the live report line for line.
     */
    #[Test]
    public function theHardenedEscalationKeepsTheStandardWording(): void
    {
        $standard = $this->findingById(
            $this->check(false, legacyCli: true)->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.frontend_placeholder_legacy',
        );
        $hardened = $this->findingById(
            $this->check(false, legacyCli: true)->run($this->doctorContext(SecurityProfile::Hardened)),
            'cli.frontend_placeholder_legacy',
        );

        self::assertSame($standard->summary, $hardened->summary);
        self::assertSame($standard->risk, $hardened->risk);
        self::assertSame($standard->remediation, $hardened->remediation);
        self::assertSame($standard->docsUrl, $hardened->docsUrl);
        self::assertNotSame($standard->severity, $hardened->severity);
    }

    /**
     * The remediation has to name the narrower fix (publish the identifier) and
     * the pin, not just "turn it off" — an operator who only flips the setting
     * leaves it flippable from the backend Settings module.
     */
    #[Test]
    public function theLegacyRemediationNamesThePublishingRouteAndThePin(): void
    {
        $finding = $this->findingById(
            $this->check(false, legacyCli: true)->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.frontend_placeholder_legacy',
        );

        self::assertStringContainsString('frontendResolvableIdentifiers', $finding->remediation);
        self::assertStringContainsString('allowIdentifier()', $finding->remediation);
        self::assertStringContainsString('additional.php', $finding->remediation);
    }

    #[Test]
    public function theLegacyFindingLinksToTheSettingsOwnConfval(): void
    {
        $finding = $this->findingById(
            $this->check(false, legacyCli: true)->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.frontend_placeholder_legacy',
        );

        self::assertStringContainsString('ext-nrvault-frontendPlaceholderLegacyCli', $finding->docsUrl);
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function cliAccessStateProvider(): iterable
    {
        yield 'allowCliAccess off (the default branch)' => [false];
        yield 'allowCliAccess on' => [true];
    }

    /**
     * @param list<int> $groups
     * @param list<string> $operations
     */
    private function check(
        bool $allowed,
        array $groups = [],
        array $operations = ['secret.use', 'secret.create', 'secret.rotate'],
        bool $legacyCli = false,
    ): CliAccessCheck {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('isCliAccessAllowed')->willReturn($allowed);
        $configuration->method('getCliAccessGroups')->willReturn($groups);
        $configuration->method('getCliAllowedOperations')->willReturn($operations);
        $configuration->method('isFrontendPlaceholderLegacyCliEnabled')->willReturn($legacyCli);

        return new CliAccessCheck($configuration);
    }
}
