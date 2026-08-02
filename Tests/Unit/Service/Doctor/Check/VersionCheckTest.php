<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\Check\VersionCheck;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionMethod;
use TYPO3\CMS\Core\Information\Typo3Version;

/**
 * A unit process has no package manager, so `ExtensionManagementUtility::extPath()`
 * cannot resolve and `ext_emconf.php` is unreadable here. That is exactly the
 * degraded path the `run()` tests below assert: version metadata is the one area
 * where being unable to look must warn rather than crash, because a
 * `check.crashed` critical over unreadable provenance data would block a
 * deployment for nothing.
 *
 * That degraded path also means `run()` can only ever reach one branch per
 * control in a unit process. The two controls are therefore also exercised
 * directly, with the emconf array they would have read, so the judgement each one
 * makes — supported core, unsupported core, unparseable or absent constraint — is
 * pinned here rather than only through a functional bootstrap. Reflection is the
 * price of keeping them private; the alternative, installing a package manager
 * into the static `ExtensionManagementUtility` seam, cannot be undone afterwards
 * and would leak into every later test in the process.
 *
 * The end-to-end happy path — real emconf, real core version, both controls
 * passing — is covered by `Tests/Functional/Command/VaultDoctorCommandTest`, where
 * a real bootstrap exists. The range comparison itself is covered exhaustively by
 * {@see Typo3VersionRangeTest}.
 */
#[CoversClass(VersionCheck::class)]
final class VersionCheckTest extends TestCase
{
    use DoctorFindingTrait;

    /**
     * The id is what a crash of this check is reported under (`check.crashed`
     * carries it) and what a CI gate allow-lists, so it is external API.
     */
    #[Test]
    public function isIdentifiedAsTheVersionCheck(): void
    {
        self::assertSame('version', (new VersionCheck(new Typo3Version()))->getId());
    }

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = new VersionCheck(new Typo3Version());

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    #[Test]
    public function emitsBothVersionControls(): void
    {
        $findings = (new VersionCheck(new Typo3Version()))
            ->run($this->doctorContext(SecurityProfile::Standard));

        self::assertSame(
            ['version.extension', 'version.typo3_supported'],
            $this->findingIds($findings),
        );
    }

    #[Test]
    public function anUnreadableEmConfWarnsRatherThanCrashing(): void
    {
        $findings = (new VersionCheck(new Typo3Version()))
            ->run($this->doctorContext(SecurityProfile::Hardened));

        $this->assertFindingSeverity(FindingSeverity::Warning, $findings, 'version.extension');
        $this->assertFindingSeverity(FindingSeverity::Warning, $findings, 'version.typo3_supported');
    }

    /**
     * Even in the degraded path the running core version has to reach the report:
     * it is the provenance line a reader of a three-month-old report needs.
     */
    #[Test]
    public function theRunningCoreVersionIsReportedEvenWithoutEmConf(): void
    {
        $finding = $this->findingById(
            (new VersionCheck(new Typo3Version()))->run($this->doctorContext(SecurityProfile::Standard)),
            'version.typo3_supported',
        );

        self::assertSame((new Typo3Version())->getVersion(), $finding->details['typo3Version']);
    }

    #[Test]
    public function aReadableExtensionVersionPassesAndIsNamedInTheReport(): void
    {
        $finding = $this->extensionVersionFinding('1.4.0');

        self::assertSame(FindingSeverity::Pass, $finding->severity);
        self::assertStringContainsString('1.4.0', $finding->summary);
        self::assertSame('1.4.0', $finding->details['extensionVersion']);
    }

    #[Test]
    public function aCoreInsideTheDeclaredRangePasses(): void
    {
        $finding = $this->typo3SupportedFinding(
            $this->emConfDeclaring('13.4.0-14.99.99'),
            running: '14.3.5',
        );

        self::assertSame(FindingSeverity::Pass, $finding->severity);
        self::assertSame('14.3.5', $finding->details['typo3Version']);
        self::assertSame('13.4.0-14.99.99', $finding->details['constraint']);
        self::assertSame('1.4.0', $finding->details['extensionVersion']);
    }

    /**
     * Both bounds are inclusive: a core sitting exactly on the declared minimum
     * or maximum is a supported installation, and reporting it as untested would
     * make the control cry wolf on the two versions most likely to be running.
     */
    #[Test]
    #[DataProvider('coreOnABoundProvider')]
    public function aCoreOnEitherBoundIsSupported(string $running): void
    {
        $finding = $this->typo3SupportedFinding($this->emConfDeclaring('13.4.0-14.99.99'), $running);

        self::assertSame(FindingSeverity::Pass, $finding->severity);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function coreOnABoundProvider(): iterable
    {
        yield 'exactly the minimum' => ['13.4.0'];
        yield 'exactly the maximum' => ['14.99.99'];
    }

    /**
     * The hand-assembled deployment the check exists for. It warns rather than
     * fails: composer already refused this combination, so reaching it means the
     * installation was assembled by hand — worth naming, not worth blocking on.
     */
    #[Test]
    public function aCoreOutsideTheDeclaredRangeWarns(): void
    {
        $finding = $this->assertWarningWithRemediation(
            $this->typo3SupportedFinding($this->emConfDeclaring('13.4.0-14.99.99'), running: '12.4.8'),
        );

        self::assertStringContainsString('12.4.8', $finding->summary);
        self::assertStringContainsString('13.4.0-14.99.99', $finding->summary);
        self::assertSame('12.4.8', $finding->details['typo3Version']);
    }

    /**
     * A composer-style caret constraint is not the `<min>-<max>` form
     * `ext_emconf.php` uses, so compatibility is unknown — which must read as
     * "could not be confirmed", never as a silent pass.
     */
    #[Test]
    public function anUnparseableConstraintWarnsAndQuotesWhatItRead(): void
    {
        $finding = $this->assertWarningWithRemediation(
            $this->typo3SupportedFinding($this->emConfDeclaring('^13.4'), running: '14.3.5'),
        );

        self::assertStringContainsString('^13.4', $finding->summary);
        self::assertSame('^13.4', $finding->details['constraint']);
        self::assertSame('14.3.5', $finding->details['typo3Version']);
    }

    /**
     * Every shape an `include`d emconf can hand back that is not a TYPO3
     * constraint string collapses to the same "no constraint declared" warning —
     * the check reads a data file it cannot type-check, so each level of the
     * lookup has to survive junk without an exception.
     *
     * @param array<mixed> $emConf
     */
    #[Test]
    #[DataProvider('emConfWithoutAConstraintProvider')]
    public function anEmConfWithoutAUsableConstraintWarns(array $emConf): void
    {
        $finding = $this->assertWarningWithRemediation(
            $this->typo3SupportedFinding($emConf, running: '14.3.5'),
        );

        self::assertStringContainsString('no TYPO3 version constraint', $finding->summary);
        self::assertSame('14.3.5', $finding->details['typo3Version']);
        self::assertArrayNotHasKey('constraint', $finding->details);
    }

    /**
     * @return iterable<string, array{array<mixed>}>
     */
    public static function emConfWithoutAConstraintProvider(): iterable
    {
        yield 'empty emconf' => [[]];
        yield 'constraints is not an array' => [['constraints' => 'depends']];
        yield 'no depends block' => [['constraints' => ['conflicts' => []]]];
        yield 'depends is not an array' => [['constraints' => ['depends' => 'typo3']]];
        yield 'no typo3 dependency' => [['constraints' => ['depends' => ['php' => '8.2.0-8.5.99']]]];
        yield 'typo3 dependency is not a string' => [['constraints' => ['depends' => ['typo3' => ['13.4.0']]]]];
    }

    /**
     * @return array<mixed>
     */
    private function emConfDeclaring(string $constraint): array
    {
        return [
            'version' => '1.4.0',
            'constraints' => ['depends' => ['typo3' => $constraint]],
        ];
    }

    private function assertWarningWithRemediation(Finding $finding): Finding
    {
        self::assertSame(FindingSeverity::Warning, $finding->severity);
        self::assertNotSame('', $finding->risk, $finding->id . ' must state the risk');
        self::assertNotSame('', $finding->remediation, $finding->id . ' must state a remediation');

        return $finding;
    }

    private function extensionVersionFinding(string $extensionVersion): Finding
    {
        $finding = (new ReflectionMethod(VersionCheck::class, 'checkExtensionVersion'))
            ->invoke(new VersionCheck(new Typo3Version()), $extensionVersion);

        self::assertInstanceOf(Finding::class, $finding);

        return $finding;
    }

    /**
     * @param array<mixed> $emConf
     */
    private function typo3SupportedFinding(array $emConf, string $running): Finding
    {
        $typo3Version = self::createStub(Typo3Version::class);
        $typo3Version->method('getVersion')->willReturn($running);

        $finding = (new ReflectionMethod(VersionCheck::class, 'checkTypo3Supported'))
            ->invoke(new VersionCheck($typo3Version), $emConf, '1.4.0');

        self::assertInstanceOf(Finding::class, $finding);

        return $finding;
    }
}
