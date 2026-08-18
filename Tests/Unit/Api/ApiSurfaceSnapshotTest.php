<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api;

use FilesystemIterator;
use Netresearch\NrVault\Tests\Unit\Api\Support\ApiSurfaceDiff;
use Netresearch\NrVault\Tests\Unit\Api\Support\ApiSurfaceRenderer;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use ReflectionIntersectionType;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionParameter;
use ReflectionProperty;
use ReflectionType;
use ReflectionUnionType;
use SplFileInfo;
use Throwable;

/**
 * Freezes the rendered public surface of this package in `api-surface.txt`
 * (issue #306).
 *
 * nr-vault has no `@api` marker convention; its public surface is defined by
 * its own doctrine instead — "prefer `*Interface.php` seams at public
 * boundaries" (AGENTS.md), and at least one downstream repo feature-detects
 * on interface names (`instanceof CancellableHttpClientInterface`). The
 * frozen set is therefore derived mechanically, with no marker to forget:
 *
 * 1. **Seed**: every interface, enum and `Throwable` subclass under
 *    `Classes/`. Interfaces are the consumer contract; enum backing values
 *    are shared vocabulary (the `AuditAction` values are bound into audit
 *    rows); exception classes are what callers `catch`.
 * 2. **Closure**: every own-namespace type a frozen signature mentions —
 *    method parameters and returns, public property types, and public
 *    constructor parameters — is frozen too, recursively. That pulls in the
 *    value objects consumers receive and construct (`OAuthConfig`,
 *    `SecretDetails`, …) without hand-maintaining a list.
 *
 * A change to any of these signatures then has to be an explicit commit — a
 * visible `api-surface.txt` diff — rather than a side effect. The failure
 * message is classified by ApiSurfaceDiff: additive (a new class, method,
 * property) may simply be regenerated; breaking (removed or changed) is a
 * decision, per AGENTS.md's "Ask First" rule for interface signatures.
 *
 * To update intentionally: delete `api-surface.txt`, run the unit suite
 * twice (first run regenerates the file and fails, second is green), and
 * commit the regenerated file together with a CHANGELOG entry.
 */
#[CoversNothing]
final class ApiSurfaceSnapshotTest extends TestCase
{
    private const CLASSES_DIR = __DIR__ . '/../../../Classes';

    private const SNAPSHOT_PATH = __DIR__ . '/api-surface.txt';

    private const NAMESPACE_PREFIX = 'Netresearch\\NrVault\\';

    #[Test]
    public function renderedPublicSurfaceMatchesTheCommittedSnapshot(): void
    {
        $classes = $this->discoverSurfaceClasses();
        self::assertNotSame([], $classes, 'No interfaces, enums or exception classes found under Classes/ — the discovery rule is broken.');

        $rendered = (new ApiSurfaceRenderer())->render($classes);

        if (!is_file(self::SNAPSHOT_PATH)) {
            file_put_contents(self::SNAPSHOT_PATH, $rendered);
            self::fail(\sprintf(
                'Snapshot regenerated at %s — inspect the diff and commit it. '
                . 'A removed or changed line is a break and needs a CHANGELOG entry.',
                self::SNAPSHOT_PATH,
            ));
        }

        $expected = file_get_contents(self::SNAPSHOT_PATH);
        self::assertNotFalse($expected);

        $diff = ApiSurfaceDiff::between($expected, $rendered);

        self::assertSame(
            $expected,
            $rendered,
            "The rendered public surface differs from Tests/Unit/Api/api-surface.txt.\n\n"
            . $diff->describe(),
        );
    }

    // ==================== discovery ====================

    /**
     * The seed set (interfaces, enums, Throwables) plus the closure over
     * own-namespace types their frozen signatures mention.
     *
     * @return list<class-string>
     */
    private function discoverSurfaceClasses(): array
    {
        $renderer = new ApiSurfaceRenderer();
        $included = [];
        $queue = $this->discoverSeedClasses();

        while ($queue !== []) {
            $fqcn = array_shift($queue);
            if (isset($included[$fqcn])) {
                continue;
            }

            $included[$fqcn] = true;

            foreach ($this->mentionedOwnTypes(new ReflectionClass($fqcn), $renderer) as $type) {
                if (!isset($included[$type])) {
                    $queue[] = $type;
                }
            }
        }

        $classes = array_keys($included);
        sort($classes);

        /** @var list<class-string> $classes */
        return $classes;
    }

    /**
     * @return list<class-string>
     */
    private function discoverSeedClasses(): array
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(self::CLASSES_DIR, FilesystemIterator::SKIP_DOTS),
        );

        $classes = [];
        foreach ($iterator as $file) {
            if (!$file instanceof SplFileInfo) {
                continue;
            }

            if ($file->getExtension() !== 'php') {
                continue;
            }

            $relative = substr($file->getPathname(), \strlen(self::CLASSES_DIR) + 1, -4);
            $fqcn = self::NAMESPACE_PREFIX . str_replace('/', '\\', $relative);

            try {
                $loadable = class_exists($fqcn) || interface_exists($fqcn) || trait_exists($fqcn) || enum_exists($fqcn);
            } catch (Throwable) {
                // The autoload attempt THREW — a parent or interface comes
                // from a package this matrix leg does not ship (observed on
                // TYPO3 ^13.4: AuditHmacMigrationWizard implements
                // TYPO3\CMS\Core\Upgrades\UpgradeWizardInterface, which
                // exists under that name only on 14.x). Such a class cannot
                // be part of THIS leg's surface. If a class that qualifies
                // for the snapshot ever splits by TYPO3 version, the leg
                // missing it fails the snapshot comparison with a visible
                // `removed` diff instead of a fatal here.
                continue;
            }

            // A clean FALSE (no throw) means the file's PSR-4 name resolves
            // to nothing anywhere — that is a broken discovery rule, not a
            // matrix difference, and stays a hard failure.
            self::assertTrue(
                $loadable,
                \sprintf('File under Classes/ does not autoload as %s — the PSR-4 discovery rule is broken.', $fqcn),
            );

            if (interface_exists($fqcn) || enum_exists($fqcn) || is_a($fqcn, Throwable::class, true)) {
                $classes[] = $fqcn;
            }
        }

        sort($classes);

        /** @var list<class-string> $classes */
        return $classes;
    }

    // ==================== closure ====================

    /**
     * Own-namespace class names mentioned in the class's frozen signatures:
     * declared public methods (parameters and return), declared public
     * property types, and the public constructor's parameters. Mirrors
     * exactly what ApiSurfaceRenderer renders for the class.
     *
     * @param ReflectionClass<object> $reflection
     *
     * @return list<class-string>
     */
    private function mentionedOwnTypes(ReflectionClass $reflection, ApiSurfaceRenderer $renderer): array
    {
        $types = [];

        foreach ($renderer->declaredPublicMethods($reflection) as $method) {
            $types = [...$types, ...$this->typesOfMethod($method)];
        }

        foreach ($renderer->declaredPublicProperties($reflection) as $property) {
            $types = [...$types, ...$this->typesOfProperty($property)];
        }

        $constructor = $renderer->declaredPublicConstructor($reflection);
        if ($constructor instanceof ReflectionMethod) {
            foreach ($constructor->getParameters() as $parameter) {
                $types = [...$types, ...$this->typesOfParameter($parameter)];
            }
        }

        $own = array_values(array_unique(array_filter(
            $types,
            static fn (string $name): bool => str_starts_with($name, self::NAMESPACE_PREFIX),
        )));

        /** @var list<class-string> $own */
        return $own;
    }

    /**
     * @return list<string>
     */
    private function typesOfMethod(ReflectionMethod $method): array
    {
        $types = [];
        foreach ($method->getParameters() as $parameter) {
            $types = [...$types, ...$this->typesOfParameter($parameter)];
        }

        return [...$types, ...$this->namedClassTypes($method->getReturnType())];
    }

    /**
     * @return list<string>
     */
    private function typesOfParameter(ReflectionParameter $parameter): array
    {
        return $this->namedClassTypes($parameter->getType());
    }

    /**
     * @return list<string>
     */
    private function typesOfProperty(ReflectionProperty $property): array
    {
        return $this->namedClassTypes($property->getType());
    }

    /**
     * @return list<string>
     */
    private function namedClassTypes(?ReflectionType $type): array
    {
        if ($type instanceof ReflectionNamedType) {
            return $type->isBuiltin() ? [] : [$type->getName()];
        }

        if ($type instanceof ReflectionUnionType || $type instanceof ReflectionIntersectionType) {
            $names = [];
            foreach ($type->getTypes() as $part) {
                $names = [...$names, ...$this->namedClassTypes($part)];
            }

            return $names;
        }

        return [];
    }
}
