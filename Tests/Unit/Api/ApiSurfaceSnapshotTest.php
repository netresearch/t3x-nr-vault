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
use Netresearch\NrVault\Tests\Unit\Api\Support\ExtensionPointCatalogue;
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
 *    `Classes/`, plus every class under `Classes/Domain/Dto/`. Interfaces
 *    are the consumer contract; enum backing values are shared vocabulary
 *    (the `AuditAction` values are bound into audit rows, and the renderer
 *    freezes the values, not just the case names); exception classes are
 *    what callers `catch`; the DTO directory is seeded wholesale because
 *    several DTOs travel only through docblock-typed arrays
 *    (`VaultServiceInterface::list()` returns `list<SecretMetadata>` as
 *    native `array`), which the reflection-based closure cannot see.
 * 2. **Closure**: every own-namespace type a frozen signature mentions as a
 *    NATIVE type — method parameters and returns, public property types,
 *    and public constructor parameters — is frozen too, recursively. That
 *    pulls in the value objects consumers receive and construct
 *    (`OAuthConfig`, …) without hand-maintaining a list. Types that appear
 *    only in docblocks are outside the closure's sight — the Dto seeding
 *    above is the compensation, so a new consumer-facing DTO belongs in
 *    that directory.
 * 3. **Implementer docblocks**: for an interface marked `#[ExtensionPoint]`
 *    only, every own-namespace type its phpdoc names — `@param`, `@return`,
 *    `@throws` — is frozen as well, and then closed over like any other. An
 *    implementation is written against the published interface and nothing
 *    else, so a type that interface names is part of what its author must be
 *    able to rely on, whether the name sits in a native position or in a
 *    docblock. `ReadinessCheckInterface::run()` is declared `array` and names
 *    its element type in `@return list<Finding>` alone, so `Finding` — a class
 *    every implementation constructs — sat outside the frozen surface (#357).
 *    The rule stops at extension points on purpose: applying it to the calling
 *    interfaces would pull internals in without that justification.
 *
 * A change to any of these signatures then has to be an explicit commit — a
 * visible `api-surface.txt` diff — rather than a side effect. The failure
 * message is classified by ApiSurfaceDiff: additive (a new class, method,
 * property) may simply be regenerated; breaking (removed or changed, or a
 * method added to an interface marked `#[ExtensionPoint]`, which breaks
 * every implementation) is a decision, per AGENTS.md's "Ask First" rule for
 * interface signatures. The mark is rendered into the declaration line, so
 * the snapshot freezes which interfaces are extension points as well.
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
        $queue = [...$this->discoverSeedClasses(), ...$this->implementerFacingDocblockTypes()];

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
                // from a package this matrix leg does not ship (by design on
                // TYPO3 ^13.4: the upgrade-wizard shell AuditHmacMigrationWizard
                // implements TYPO3\CMS\Core\Upgrades\UpgradeWizardInterface,
                // which 13.4 does not have; its 13.4 sibling
                // AuditHmacMigrationWizardV13 is the one registered there).
                // Such a class cannot
                // be part of THIS leg's surface. If a SEED class ever splits
                // by TYPO3 version, the leg missing it fails the snapshot
                // comparison with a visible `removed` diff instead of a
                // fatal here; a closure-reached type that splits would still
                // error loudly at its ReflectionClass construction — loud,
                // just without the diff diagnosis. This catch also swallows
                // a ParseError in a seed file: such a file is skipped here
                // and caught by the lint job instead.
                continue;
            }

            // A clean FALSE (no throw) means the file's PSR-4 name resolves
            // to nothing anywhere — that is a broken discovery rule, not a
            // matrix difference, and stays a hard failure.
            self::assertTrue(
                $loadable,
                \sprintf('File under Classes/ does not autoload as %s — the PSR-4 discovery rule is broken.', $fqcn),
            );

            if (
                interface_exists($fqcn)
                || enum_exists($fqcn)
                || is_a($fqcn, Throwable::class, true)
                || str_starts_with($fqcn, self::NAMESPACE_PREFIX . 'Domain\\Dto\\')
            ) {
                $classes[] = $fqcn;
            }
        }

        sort($classes);

        /** @var list<class-string> $classes */
        return $classes;
    }

    // ==================== implementer docblocks ====================

    /**
     * Own-namespace types named only in the phpdoc of an extension point.
     *
     * The closure follows NATIVE types, and a native `array` says nothing
     * about what it contains — which is exactly how the element type of
     * `ReadinessCheckInterface::run()` escaped the snapshot. Seeding these
     * keeps the promise the extension-point mark makes: everything an
     * implementer has to name is frozen.
     *
     * @return list<class-string>
     */
    private function implementerFacingDocblockTypes(): array
    {
        $types = [];

        foreach (ExtensionPointCatalogue::markedInterfaces() as $interface) {
            $reflection = new ReflectionClass($interface);
            $imports = $this->importsOf($reflection);

            foreach ($reflection->getMethods() as $method) {
                foreach ($this->docblockTypeNames($method->getDocComment()) as $name) {
                    $resolved = $this->resolveOwnType($name, $reflection->getNamespaceName(), $imports);
                    if ($resolved !== null) {
                        $types[] = $resolved;
                    }
                }
            }
        }

        return array_values(array_unique($types));
    }

    /**
     * Every bare identifier in the type expression of a `@param`, `@return`
     * or `@throws`: `list<Finding>` yields `list` and `Finding`.
     *
     * The capture runs to the end of the line (or the parameter variable), so
     * a `@return string e.g., "local"` contributes its prose words too. That
     * is deliberate and harmless: {@see resolveOwnType()} keeps only names
     * that resolve to a class in this package, and a prose word does not.
     * Stopping at the type expression instead would need a phpdoc parser to
     * get `array<string, Finding>` right.
     *
     * @return list<string>
     */
    private function docblockTypeNames(string|false $docComment): array
    {
        if ($docComment === false) {
            return [];
        }

        preg_match_all('/@(?:param|return|throws)\s+([^\n$]*)/', $docComment, $matches);

        $names = [];
        foreach ($matches[1] as $expression) {
            preg_match_all('/[A-Za-z_\\\\][A-Za-z0-9_\\\\]*/', $expression, $identifiers);
            $names = [...$names, ...$identifiers[0]];
        }

        return $names;
    }

    /**
     * `use A\B\C;` / `use A\B\C as D;` from the file the class is declared in,
     * as alias => fully qualified name — what a short docblock name resolves
     * against.
     *
     * @param ReflectionClass<object> $reflection
     *
     * @return array<string, string>
     */
    private function importsOf(ReflectionClass $reflection): array
    {
        $file = $reflection->getFileName();
        if ($file === false) {
            return [];
        }

        $source = file_get_contents($file);
        if ($source === false) {
            return [];
        }

        preg_match_all(
            '/^use\s+([A-Za-z0-9_\\\\]+)(?:\s+as\s+([A-Za-z0-9_]+))?\s*;/m',
            $source,
            $matches,
            PREG_SET_ORDER,
        );

        $imports = [];
        foreach ($matches as $match) {
            $fqcn = $match[1];
            $alias = ($match[2] ?? '') !== ''
                ? $match[2]
                : substr((string) strrchr('\\' . $fqcn, '\\'), 1);
            $imports[$alias] = $fqcn;
        }

        return $imports;
    }

    /**
     * A docblock identifier to the class in this package it names, or null for
     * a builtin, a foreign class, a prose word or anything that does not exist.
     *
     * @param array<string, string> $imports
     *
     * @return class-string|null
     */
    private function resolveOwnType(string $name, string $namespace, array $imports): ?string
    {
        $candidate = match (true) {
            str_starts_with($name, '\\') => substr($name, 1),
            isset($imports[$name]) => $imports[$name],
            default => $namespace . '\\' . $name,
        };

        if (!str_starts_with($candidate, self::NAMESPACE_PREFIX)) {
            return null;
        }

        try {
            $exists = class_exists($candidate) || interface_exists($candidate) || enum_exists($candidate);
        } catch (Throwable) {
            // Same matrix-split rationale as the seed loop above.
            return null;
        }

        /** @var class-string $candidate */
        return $exists ? $candidate : null;
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
