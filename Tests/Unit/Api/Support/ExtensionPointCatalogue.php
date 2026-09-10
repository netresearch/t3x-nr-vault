<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\Support;

use FilesystemIterator;
use Netresearch\NrVault\Attribute\ExtensionPoint;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use SplFileInfo;

/**
 * Finds the interfaces under Classes/ that carry `#[ExtensionPoint]`, and the
 * sample implementations under Tests/Unit/Api/ExtensionPoints/.
 *
 * Only files that mention the attribute are loaded, so a class that cannot be
 * autoloaded on the running TYPO3 major (the upgrade-wizard shell of the other
 * one) never gets in the way — and a marked interface is found whatever it is
 * called.
 */
final class ExtensionPointCatalogue
{
    private const CLASSES_DIR = __DIR__ . '/../../../../Classes';

    private const SAMPLES_DIR = __DIR__ . '/../ExtensionPoints';

    private const CLASSES_NAMESPACE = 'Netresearch\\NrVault\\';

    private const SAMPLES_NAMESPACE = 'Netresearch\\NrVault\\Tests\\Unit\\Api\\ExtensionPoints\\';

    /**
     * @return list<class-string>
     */
    public static function markedInterfaces(): array
    {
        $marked = [];

        foreach (self::phpFilesUnder(self::CLASSES_DIR) as $file) {
            $source = file_get_contents($file->getPathname());
            if ($source === false || !str_contains($source, 'ExtensionPoint]')) {
                continue;
            }

            $fqcn = self::CLASSES_NAMESPACE . self::relativeClassName($file, self::CLASSES_DIR);
            if (!interface_exists($fqcn)) {
                continue;
            }

            if ((new ReflectionClass($fqcn))->getAttributes(ExtensionPoint::class) !== []) {
                $marked[] = $fqcn;
            }
        }

        sort($marked);

        return $marked;
    }

    /**
     * @return list<class-string>
     */
    public static function sampleImplementations(): array
    {
        $samples = [];

        foreach (self::phpFilesUnder(self::SAMPLES_DIR) as $file) {
            $fqcn = self::SAMPLES_NAMESPACE . self::relativeClassName($file, self::SAMPLES_DIR);
            if (class_exists($fqcn)) {
                $samples[] = $fqcn;
            }
        }

        sort($samples);

        return $samples;
    }

    /**
     * @return iterable<SplFileInfo>
     */
    private static function phpFilesUnder(string $directory): iterable
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if ($file instanceof SplFileInfo && $file->getExtension() === 'php') {
                yield $file;
            }
        }
    }

    /**
     * `<dir>/Crypto/FooInterface.php` → `Crypto\FooInterface`.
     */
    private static function relativeClassName(SplFileInfo $file, string $directory): string
    {
        return str_replace('/', '\\', substr($file->getPathname(), \strlen($directory) + 1, -4));
    }
}
