<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderRegistry;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Tests\Unit\Crypto\Fixtures\FirstThirdPartyMasterKeyProvider;
use Netresearch\NrVault\Tests\Unit\Crypto\Fixtures\SecondThirdPartyMasterKeyProvider;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(MasterKeyProviderRegistry::class)]
final class MasterKeyProviderRegistryTest extends TestCase
{
    #[Test]
    public function getReturnsTheProviderRegisteredUnderTheIdentifier(): void
    {
        $file = $this->providerNamed('file');
        $custom = $this->providerNamed('acme_kms');

        $subject = new MasterKeyProviderRegistry([$file, $custom]);

        self::assertSame($file, $subject->get('file'));
        self::assertSame($custom, $subject->get('acme_kms'));
    }

    #[Test]
    public function getThrowsTheUnknownProviderExceptionForAnIdentifierNobodyClaims(): void
    {
        $subject = new MasterKeyProviderRegistry([$this->providerNamed('file')]);

        // Unchanged from before the registry existed: an identifier no provider
        // answers to is still ConfigurationException::invalidProvider().
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1703800015);
        $this->expectExceptionMessageToContain('Unknown master key provider: kms');

        $subject->get('kms');
    }

    #[Test]
    public function aThirdPartyProviderMayNotShadowABuiltInIdentifier(): void
    {
        // The attack this guard exists for: an installed extension claims
        // "file" and thereby decides which key source protects the vault.
        $subject = new MasterKeyProviderRegistry([
            $this->providerNamed('file'),
            $this->conflictingProviderNamed('file'),
        ]);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1789430001);
        $this->expectExceptionMessageToContain('claimed by two providers');

        $subject->get('file');
    }

    #[Test]
    public function twoThirdPartyProvidersCollidingWithEachOtherAreRefusedToo(): void
    {
        $subject = new MasterKeyProviderRegistry([
            $this->providerNamed('kms'),
            $this->conflictingProviderNamed('kms'),
        ]);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1789430001);

        $subject->get('kms');
    }

    #[Test]
    public function theExceptionNamesBothCollidingProviderClasses(): void
    {
        $registered = $this->providerNamed('file');
        $conflicting = $this->conflictingProviderNamed('file');

        // Precondition, not decoration: with one class on both sides the two
        // assertions below would check the same string and the test would pass
        // even if the message named a single provider.
        self::assertNotSame($registered::class, $conflicting::class);

        $subject = new MasterKeyProviderRegistry([$registered, $conflicting]);

        try {
            $subject->get('file');
            self::fail('Expected the colliding registration to be refused.');
        } catch (ConfigurationException $e) {
            self::assertStringContainsString($registered::class, $e->getMessage());
            self::assertStringContainsString($conflicting::class, $e->getMessage());
        }
    }

    #[Test]
    public function aCollisionRefusesEveryLookup_notOnlyTheCollidingIdentifier(): void
    {
        // Fail closed on the whole registry: while two providers disagree about
        // who owns an identifier, "which key source is in use?" has no answer,
        // and serving the unrelated names would hide that from the operator.
        $subject = new MasterKeyProviderRegistry([
            $this->providerNamed('env'),
            $this->providerNamed('kms'),
            $this->conflictingProviderNamed('kms'),
        ]);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1789430001);

        $subject->get('env');
    }

    #[Test]
    public function aProviderWithABlankIdentifierIsRefused(): void
    {
        // "" is what masterKeyProvider holds before anybody configures it, so a
        // provider answering to it would be selected by an unconfigured install.
        $subject = new MasterKeyProviderRegistry([$this->providerNamed('  ')]);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1789430002);
        $this->expectExceptionMessageToContain('blank identifier');

        $subject->get('file');
    }

    #[Test]
    public function hasReportsRegistrationWithoutConstructingAnException(): void
    {
        $subject = new MasterKeyProviderRegistry([$this->providerNamed('transit')]);

        self::assertTrue($subject->has('transit'));
        self::assertFalse($subject->has('kms'));
    }

    #[Test]
    public function getIdentifiersListsEveryRegisteredProvider(): void
    {
        $subject = new MasterKeyProviderRegistry([
            $this->providerNamed('typo3'),
            $this->providerNamed('file'),
            $this->providerNamed('acme_kms'),
        ]);

        self::assertSame(['typo3', 'file', 'acme_kms'], $subject->getIdentifiers());
    }

    #[Test]
    public function assertNoIdentifierConflictsPassesOnADistinctSet(): void
    {
        $subject = new MasterKeyProviderRegistry([
            $this->providerNamed('file'),
            $this->providerNamed('acme_kms'),
        ]);

        $subject->assertNoIdentifierConflicts();

        // Reaching here is the assertion; make it explicit for the reader.
        self::assertSame(['file', 'acme_kms'], $subject->getIdentifiers());
    }

    #[Test]
    public function assertNoIdentifierConflictsThrowsOnACollision(): void
    {
        $subject = new MasterKeyProviderRegistry([
            $this->providerNamed('file'),
            $this->conflictingProviderNamed('file'),
        ]);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1789430001);

        $subject->assertNoIdentifierConflicts();
    }

    #[Test]
    public function anEmptyRegistryResolvesNothingRatherThanReturningADefault(): void
    {
        $subject = new MasterKeyProviderRegistry([]);

        self::assertSame([], $subject->getIdentifiers());

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1703800015);

        $subject->get('typo3');
    }

    /**
     * A provider written against the published interface only, the way a
     * consuming extension writes one.
     *
     * A named fixture class rather than an anonymous one: PHP compiles a single
     * class per anonymous-class DECLARATION site, so every call to a factory
     * method returning `new class` hands back the same class name, and a test
     * comparing two of them by class would compare one string to itself. Use
     * {@see conflictingProviderNamed()} for the other side of a collision.
     */
    private function providerNamed(string $identifier): MasterKeyProviderInterface
    {
        return new FirstThirdPartyMasterKeyProvider($identifier);
    }

    /**
     * A second provider, from a genuinely different class, for the cases that
     * model two extensions claiming one identifier.
     */
    private function conflictingProviderNamed(string $identifier): MasterKeyProviderInterface
    {
        return new SecondThirdPartyMasterKeyProvider($identifier);
    }
}
