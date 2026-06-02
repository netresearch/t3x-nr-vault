<?php

declare(strict_types=1);

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

namespace Netresearch\NrVault\Tests\Architecture;

use GuzzleHttp\Client;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Command\VaultRotateMasterKeyCommand;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthToken;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\Detection\Severity;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPat\Selector\Selector;
use PHPat\Test\Builder\BuildStep;
use PHPat\Test\PHPat;

/**
 * Architecture tests for nr-vault extension.
 *
 * Enforces clean architecture boundaries and security patterns.
 *
 * Layer dependency rules (allowed dependencies flow downward):
 *
 *   Controller/Command (presentation)
 *          ↓
 *      Service (application)
 *          ↓
 *   Domain/Adapter (core)
 *          ↓
 *   Crypto/Security (infrastructure)
 *          ↓
 *   Exception/Event (shared kernel)
 */
final class ArchitectureTest
{
    private const NAMESPACE_CRYPTO = 'Netresearch\NrVault\Crypto';

    private const NAMESPACE_SERVICE = 'Netresearch\NrVault\Service';

    private const NAMESPACE_CONTROLLER = 'Netresearch\NrVault\Controller';

    private const NAMESPACE_COMMAND = 'Netresearch\NrVault\Command';

    private const NAMESPACE_HOOK = 'Netresearch\NrVault\Hook';

    private const SELECTOR_INTERFACE_REGEX = '/.*Interface$/';

    // =========================================================================
    // IMMUTABILITY RULES - Security-critical classes must be immutable
    // =========================================================================

    /**
     * Events must be readonly for immutability.
     *
     * PSR-14 events should never be modified after creation.
     */
    public function testEventsMustBeReadonly(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault\Event'))
            ->shouldBeReadonly()
            ->because('events must be immutable for security and predictability');
    }

    /**
     * Audit log entries must be readonly.
     *
     * Audit data must never be modified after creation for integrity.
     */
    public function testAuditLogEntryMustBeReadonly(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::classname(AuditLogEntry::class))
            ->shouldBeReadonly()
            ->because('audit entries must be immutable for tamper-evidence');
    }

    /**
     * OAuth value objects must be readonly.
     *
     * Token and config objects should be immutable.
     */
    public function testOAuthValueObjectsMustBeReadonly(): BuildStep
    {
        return PHPat::rule()
            ->classes(
                Selector::classname(OAuthConfig::class),
                Selector::classname(OAuthToken::class),
            )
            ->shouldBeReadonly()
            ->because('OAuth value objects must be immutable');
    }

    /**
     * HTTP client must be readonly (immutable/fluent pattern).
     */
    public function testVaultHttpClientMustBeReadonly(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::classname(VaultHttpClient::class))
            ->shouldBeReadonly()
            ->because('HTTP client uses immutable fluent pattern');
    }

    // =========================================================================
    // FINALITY RULES - Security classes must not be extended
    // =========================================================================

    /**
     * Exceptions must be final.
     *
     * Prevents exception hierarchy manipulation attacks.
     */
    public function testExceptionsMustBeFinal(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault\Exception'))
            ->shouldBeFinal()
            ->because('exceptions should not be extended for security');
    }

    /**
     * Crypto implementations must be final.
     *
     * Prevents override attacks on cryptographic operations.
     */
    public function testCryptoImplementationsMustBeFinal(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace(self::NAMESPACE_CRYPTO))
            ->excluding(Selector::classname(self::SELECTOR_INTERFACE_REGEX, true))
            ->shouldBeFinal()
            ->because('crypto implementations must not be overridden');
    }

    /**
     * Security implementations must be final.
     */
    public function testSecurityImplementationsMustBeFinal(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault\Security'))
            ->excluding(Selector::classname(self::SELECTOR_INTERFACE_REGEX, true))
            ->shouldBeFinal()
            ->because('security implementations must not be overridden');
    }

    // =========================================================================
    // INTERFACE RULES - Ensure proper abstractions
    // =========================================================================

    /**
     * Services must implement an interface.
     *
     * Enables dependency injection and testing.
     */
    public function testServicesMustImplementInterface(): BuildStep
    {
        return PHPat::rule()
            ->classes(
                Selector::classname('/^Netresearch\\\\NrVault\\\\.*Service$/', true),
            )
            ->excluding(
                Selector::classname(self::SELECTOR_INTERFACE_REGEX, true),
                Selector::classname('/.*Factory$/', true),
            )
            ->shouldImplement()
            ->classes(Selector::classname(self::SELECTOR_INTERFACE_REGEX, true))
            ->because('services should be injected via interfaces for testability');
    }

    /**
     * Only `SecureHttpClientFactory` may instantiate Guzzle's HTTP client.
     *
     * Architectural lock-in for the SSRF / DNS-rebinding / no-redirect
     * defences: every outbound HTTP path in the extension MUST construct
     * its client via `SecureHttpClientFactory::create()` so the
     * `ssrf-dns-pin` middleware, the proxy/TLS config, and the
     * `allow_redirects: false` default all apply.
     *
     * `OAuthTokenManager` previously defaulted its `$httpClient` parameter
     * to `new GuzzleHttp\Client(...)` and silently bypassed every guard.
     * PR #145 removed that default; this rule prevents the gap from
     * re-opening — and catches any other module that quietly stands up
     * a fresh client (e.g. an experiment, a debug script, copy-pasta
     * from upstream).
     *
     * @see https://github.com/netresearch/t3x-nr-vault/pull/145
     */
    public function testOnlySecureHttpClientFactoryInstantiatesGuzzleClient(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault'))
            ->excluding(
                Selector::classname(SecureHttpClientFactory::class),
                Selector::inNamespace('Netresearch\NrVault\Tests'),
            )
            ->shouldNot()
            ->dependOn()
            ->classes(Selector::classname(Client::class))
            ->because(
                'all outbound HTTP must flow through SecureHttpClientFactory; '
                . 'instantiating GuzzleHttp\Client directly bypasses SSRF + '
                . 'DNS-rebinding + no-redirect defences (PR #145)',
            );
    }

    /**
     * Adapters must implement VaultAdapterInterface.
     */
    public function testAdaptersMustImplementInterface(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault\Adapter'))
            ->excluding(Selector::classname(self::SELECTOR_INTERFACE_REGEX, true))
            ->shouldImplement()
            ->classes(Selector::classname(VaultAdapterInterface::class))
            ->because('adapters must follow the adapter contract');
    }

    // =========================================================================
    // LAYER DEPENDENCY RULES - Enforce clean architecture
    // =========================================================================

    /**
     * Services must not depend on Controllers.
     *
     * Services are application layer, controllers are presentation.
     */
    public function testServicesDoNotDependOnControllers(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace(self::NAMESPACE_SERVICE))
            ->shouldNotDependOn()
            ->classes(Selector::inNamespace(self::NAMESPACE_CONTROLLER))
            ->because('services should be independent of the presentation layer');
    }

    /**
     * Services must not depend on Commands.
     *
     * CLI commands are presentation layer.
     */
    public function testServicesDoNotDependOnCommands(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace(self::NAMESPACE_SERVICE))
            ->shouldNotDependOn()
            ->classes(Selector::inNamespace(self::NAMESPACE_COMMAND))
            ->because('services should be independent of CLI commands');
    }

    /**
     * Domain layer must not depend on infrastructure.
     *
     * Domain models should be pure and framework-independent.
     */
    public function testDomainDoesNotDependOnInfrastructure(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault\Domain'))
            ->shouldNotDependOn()
            ->classes(
                Selector::inNamespace(self::NAMESPACE_CONTROLLER),
                Selector::inNamespace(self::NAMESPACE_COMMAND),
                Selector::inNamespace(self::NAMESPACE_HOOK),
                Selector::inNamespace('Netresearch\NrVault\Form'),
                Selector::inNamespace('Netresearch\NrVault\Task'),
            )
            ->because('domain layer must be isolated from infrastructure concerns');
    }

    /**
     * Crypto layer must be isolated.
     *
     * Cryptographic operations must not depend on HTTP, presentation, or hooks.
     */
    public function testCryptoIsIsolated(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace(self::NAMESPACE_CRYPTO))
            ->shouldNotDependOn()
            ->classes(
                Selector::inNamespace('Netresearch\NrVault\Http'),
                Selector::inNamespace(self::NAMESPACE_CONTROLLER),
                Selector::inNamespace(self::NAMESPACE_COMMAND),
                Selector::inNamespace(self::NAMESPACE_HOOK),
                Selector::inNamespace('Netresearch\NrVault\Form'),
                Selector::inNamespace('Netresearch\NrVault\Audit'),
                Selector::inNamespace(self::NAMESPACE_SERVICE),
            )
            ->because('crypto operations must be independent of application context');
    }

    /**
     * Security layer must not depend on HTTP.
     *
     * Access control should work regardless of request context.
     */
    public function testSecurityDoesNotDependOnHttp(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault\Security'))
            ->shouldNotDependOn()
            ->classes(
                Selector::inNamespace('Netresearch\NrVault\Http'),
                Selector::inNamespace(self::NAMESPACE_CONTROLLER),
            )
            ->because('security layer must be context-independent');
    }

    /**
     * Hooks must not depend on Controllers.
     *
     * TYPO3 hooks should call services, not controllers.
     */
    public function testHooksDoNotDependOnControllers(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace(self::NAMESPACE_HOOK))
            ->shouldNotDependOn()
            ->classes(Selector::inNamespace(self::NAMESPACE_CONTROLLER))
            ->because('hooks should use services, not controllers');
    }

    /**
     * Commands must not depend on Controllers.
     *
     * CLI and web are separate presentation channels.
     */
    public function testCommandsDoNotDependOnControllers(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace(self::NAMESPACE_COMMAND))
            ->shouldNotDependOn()
            ->classes(Selector::inNamespace(self::NAMESPACE_CONTROLLER))
            ->because('CLI commands should not use web controllers');
    }

    /**
     * Commands must not reach across the service layer into the
     * persistence repository — except the one blessed bulk operation.
     *
     * `VaultRotateMasterKeyCommand` legitimately bypasses `VaultService`
     * to re-wrap every secret's DEK in a single transaction without
     * per-secret ACL/audit (an admin re-keying the whole store); going
     * through `VaultService::retrieve/store` would be wrong there. That
     * one bypass is documented and allow-listed here (mirroring the
     * `SecureHttpClientFactory` Guzzle-lock allow-one pattern), so any
     * NEW command that injects the repository fails CI.
     *
     * The rule targets both the `Domain\Repository` namespace (the
     * concrete `SecretRepository`) AND the `SecretRepositoryInterface`
     * by classname, because PHPat does not reliably trip on
     * constructor-injected *interface* dependencies via the namespace
     * selector alone (see the OverviewController -> Crypto miss noted in
     * the architecture review). Naming the interface explicitly closes
     * that gap, since the blessed command injects the interface, not the
     * concrete class.
     */
    public function testCommandsDoNotDependOnRepository(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace(self::NAMESPACE_COMMAND))
            ->excluding(Selector::classname(VaultRotateMasterKeyCommand::class))
            ->shouldNot()
            ->dependOn()
            ->classes(
                Selector::inNamespace('Netresearch\NrVault\Domain\Repository'),
                Selector::classname(SecretRepositoryInterface::class),
            )
            ->because(
                'commands must go through the service layer; only the '
                . 'blessed VaultRotateMasterKeyCommand may drive the '
                . 'repository directly for bulk master-key rotation',
            );
    }

    /**
     * Controllers must not depend on Crypto directly.
     *
     * Controllers should use services which handle crypto.
     */
    public function testControllersDoNotDependOnCrypto(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace(self::NAMESPACE_CONTROLLER))
            ->shouldNotDependOn()
            ->classes(Selector::inNamespace(self::NAMESPACE_CRYPTO))
            ->because('controllers should use services for crypto operations');
    }

    /**
     * Configuration must not depend on Services.
     *
     * Configuration is low-level infrastructure.
     */
    public function testConfigurationDoesNotDependOnServices(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault\Configuration'))
            ->shouldNotDependOn()
            ->classes(
                Selector::inNamespace(self::NAMESPACE_SERVICE),
                Selector::inNamespace(self::NAMESPACE_CONTROLLER),
                Selector::inNamespace(self::NAMESPACE_COMMAND),
            )
            ->because('configuration should be low-level infrastructure');
    }

    /**
     * EventListeners must not depend on Controllers or Commands.
     *
     * Event handlers should only use services.
     */
    public function testEventListenersDoNotDependOnPresentation(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault\EventListener'))
            ->shouldNotDependOn()
            ->classes(
                Selector::inNamespace(self::NAMESPACE_CONTROLLER),
                Selector::inNamespace(self::NAMESPACE_COMMAND),
            )
            ->because('event listeners should use services, not presentation layer');
    }

    /**
     * Utilities must not depend on Services.
     *
     * Utilities should be stateless helper functions.
     */
    public function testUtilitiesDoNotDependOnServices(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault\Utility'))
            ->shouldNotDependOn()
            ->classes(
                Selector::inNamespace(self::NAMESPACE_CONTROLLER),
                Selector::inNamespace(self::NAMESPACE_COMMAND),
                Selector::inNamespace(self::NAMESPACE_HOOK),
            )
            ->because('utilities should be stateless helpers');
    }

    // =========================================================================
    // ENUM RULES - Ensure enums are used properly
    // =========================================================================

    /**
     * Enums must be in appropriate namespaces.
     *
     * Severity enum is a value object in Service\Detection.
     * SecretPlacement enum is a value object in Http.
     */
    public function testEnumsMustBeFinal(): BuildStep
    {
        return PHPat::rule()
            ->classes(
                Selector::classname(Severity::class),
                Selector::classname(SecretPlacement::class),
            )
            ->shouldBeFinal()
            ->because('enums are implicitly final but this documents intent');
    }

    // =========================================================================
    // TEST CONVENTION RULES - Ensure tests use the shared infrastructure
    // =========================================================================

    /**
     * Unit-test support classes (traits, fixtures, the project base) must
     * live under the dedicated `Tests\Unit\*` sub-namespaces.
     *
     * PHPat cannot directly express "every *Test must extend TestCase" (the
     * rule set exposes no `shouldExtend()` for concrete classes beyond
     * inheritance hierarchies); that invariant is enforced by the
     * lightweight static scanner at `Tests/scripts/check-test-base-class.php`,
     * wired into `composer ci:test:php:arch`. This rule covers the
     * complementary half: the shared infrastructure must not leak into
     * production code.
     */
    public function testSharedTestInfrastructureDoesNotLeakIntoProduction(): BuildStep
    {
        return PHPat::rule()
            ->classes(Selector::inNamespace('Netresearch\NrVault'))
            ->excluding(Selector::inNamespace('Netresearch\NrVault\Tests'))
            ->shouldNotDependOn()
            ->classes(
                Selector::inNamespace('Netresearch\NrVault\Tests\Unit\Traits'),
                Selector::inNamespace('Netresearch\NrVault\Tests\Unit\Fixtures'),
                Selector::classname(TestCase::class),
                Selector::classname(AbstractVaultFunctionalTestCase::class),
            )
            ->because('test-only helpers must not bleed into production code paths');
    }
}
