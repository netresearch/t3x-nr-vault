<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api;

use Netresearch\NrVault\Tests\Unit\Api\Support\ExtensionPointCatalogue;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

/**
 * Holds the extension-point promise to something that runs, not only to the
 * text of api-surface.txt.
 *
 * Tests/Unit/Api/ExtensionPoints/ holds one sample implementation per
 * interface marked `#[ExtensionPoint]`, each written the way a consuming
 * extension writes one — against the published interface and nothing else.
 * A method added to such an interface, or a signature changed on one, makes
 * its sample fail to load: PHP stops the unit run with "Class … contains 1
 * abstract method" or "Declaration of … must be compatible with …", and
 * PHPStan reports the same file. That is the break every real implementation
 * would hit, reproduced where CI sees it.
 *
 * The documented list in Documentation/Developer/Api.rst is checked against
 * the attribute as well, so the promise integrators read and the one the code
 * enforces cannot drift apart.
 */
#[CoversNothing] // the subjects are interfaces and documentation
final class ExtensionPointContractTest extends TestCase
{
    private const API_DOCUMENTATION = __DIR__ . '/../../../Documentation/Developer/Api.rst';

    #[Test]
    public function everyExtensionPointHasASampleImplementation(): void
    {
        $implemented = [];
        foreach (ExtensionPointCatalogue::sampleImplementations() as $sample) {
            $implemented = [...$implemented, ...(new ReflectionClass($sample))->getInterfaceNames()];
        }

        $missing = array_values(array_diff(ExtensionPointCatalogue::markedInterfaces(), $implemented));

        self::assertSame(
            [],
            $missing,
            'Every #[ExtensionPoint] interface needs a sample implementation in Tests/Unit/Api/ExtensionPoints/, '
            . 'written against the published interface only.',
        );
    }

    #[Test]
    public function everySampleImplementsAnExtensionPoint(): void
    {
        foreach (ExtensionPointCatalogue::sampleImplementations() as $sample) {
            self::assertNotSame(
                [],
                array_intersect((new ReflectionClass($sample))->getInterfaceNames(), ExtensionPointCatalogue::markedInterfaces()),
                $sample . ' implements no #[ExtensionPoint] interface. Only extension points are supported for '
                . 'implementation outside the package, so only they get a sample.',
            );
        }
    }

    /**
     * @param class-string $sample
     */
    #[Test]
    #[DataProvider('sampleProvider')]
    public function aSampleLoadsAgainstTheCurrentInterface(string $sample): void
    {
        $instance = (new ReflectionClass($sample))->newInstance();

        foreach (array_intersect(class_implements($instance), ExtensionPointCatalogue::markedInterfaces()) as $interface) {
            self::assertInstanceOf($interface, $instance);
        }
    }

    /**
     * @return iterable<string, array{class-string}>
     */
    public static function sampleProvider(): iterable
    {
        foreach (ExtensionPointCatalogue::sampleImplementations() as $sample) {
            yield (new ReflectionClass($sample))->getShortName() => [$sample];
        }
    }

    #[Test]
    public function theDocumentationListsExactlyTheExtensionPoints(): void
    {
        $documentation = file_get_contents(self::API_DOCUMENTATION);
        self::assertIsString($documentation);

        $start = strpos($documentation, '.. _api-extension-points:');
        self::assertIsInt($start, 'Api.rst has lost its extension-points section.');
        $end = strpos($documentation, "\n.. _api-", $start + 1);
        $section = substr($documentation, $start, $end === false ? null : $end - $start);

        preg_match_all('/``(Netresearch\\\\NrVault\\\\[A-Za-z\\\\]+Interface)``/', $section, $matches);
        $documented = array_values(array_unique($matches[1]));
        sort($documented);

        self::assertSame(
            ExtensionPointCatalogue::markedInterfaces(),
            $documented,
            'The extension points listed in Documentation/Developer/Api.rst differ from the interfaces marked '
            . '#[ExtensionPoint]. Integrators rely on that list: change both together.',
        );
    }
}
