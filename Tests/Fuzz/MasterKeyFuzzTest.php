<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EnvironmentMasterKeyProvider;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Exception\MasterKeyException;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;

/**
 * Fuzz tests for master-key provider input robustness.
 *
 * Properties under test:
 * - Malformed key file contents (truncated, empty, BOM, CRLF, binary, invalid base64)
 *   MUST throw MasterKeyException — NEVER silently derive a weak key.
 * - Key file with wrong byte length (anything != 32) must throw.
 * - Environment variable with non-base64 / non-hex / wrong-length contents must throw.
 * - Unreadable / missing / empty-path must throw a clean exception.
 * - 30+ adversarial inputs exercised via DataProvider seeded from PHPUNIT_SEED.
 */
#[CoversClass(FileMasterKeyProvider::class)]
#[CoversClass(EnvironmentMasterKeyProvider::class)]
final class MasterKeyFuzzTest extends TestCase
{
    private int $seed;

    protected function setUp(): void
    {
        parent::setUp();
        $this->seed = (int) ($_ENV['PHPUNIT_SEED'] ?? crc32(__FILE__));
        mt_srand($this->seed);

        // Register the `vfs://keys/` root so later `vfsStream::url('keys/...')`
        // calls resolve to a live in-memory directory. Without the setup
        // call, `file_put_contents('vfs://keys/master.key')` fails with
        // "No such file or directory" on CI (the setup was implicit in the
        // author's local libvfsstream build — never rely on that).
        vfsStream::setup('keys');

        // Ensure each test starts with a clean cached key state
        FileMasterKeyProvider::clearCachedKey();
        EnvironmentMasterKeyProvider::clearCachedKey();
    }

    protected function tearDown(): void
    {
        FileMasterKeyProvider::clearCachedKey();
        EnvironmentMasterKeyProvider::clearCachedKey();

        parent::tearDown();
    }

    // -----------------------------------------------------------------------
    // Data providers — file inputs
    // -----------------------------------------------------------------------

    /**
     * Malformed file contents that MUST NOT be accepted as a valid master key.
     *
     * @return array<string, array{string}>
     */
    public static function invalidFileContentProvider(): array
    {
        $seed = (int) ($_ENV['PHPUNIT_SEED'] ?? crc32(__FILE__));
        mt_srand($seed);

        $cases = [
            'empty' => [''],
            'single space' => [' '],
            'single newline' => ["\n"],
            'crlf only' => ["\r\n"],
            'whitespace only' => ["   \t\r\n  "],
            'bom then short key' => ["\xEF\xBB\xBFshort"],
            'bom then 31 bytes' => ["\xEF\xBB\xBF" . str_repeat('a', 31)],
            'bom then 32 bytes' => ["\xEF\xBB\xBF" . str_repeat('a', 32)],
            'truncated 16 bytes' => [str_repeat('a', 16)],
            'truncated 31 bytes' => [str_repeat('a', 31)],
            'overflow 33 bytes' => [str_repeat('a', 33)],
            'overflow 64 bytes hex' => [str_repeat('0123456789abcdef', 4)],
            'overflow 128 bytes' => [str_repeat('x', 128)],
            'invalid base64 chars' => ['!!!not-base64!!!-' . str_repeat('x', 16)],
            'base64 wrong length' => [base64_encode(str_repeat('a', 16))],
            'base64 wrong length 64' => [base64_encode(str_repeat('a', 64))],
            'base64 with newline prefix' => ["\n" . base64_encode(str_repeat('a', 16))],
            'hex string 64 chars no decode' => [bin2hex(str_repeat('a', 32))],
            'only null bytes 16' => [str_repeat("\x00", 16)],
            'only null bytes 33' => [str_repeat("\x00", 33)],
            'binary noise 10 bytes' => ["\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"],
            'utf8 multibyte filling to 30' => [str_repeat('ä', 15)], // 30 bytes
            'json fragment' => ['{"key":"abc"}'],
            'pem header' => ["-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"],
        ];

        // Add 15 random-length random-byte cases — all non-32-byte.
        for ($i = 0; $i < 15; $i++) {
            $len = mt_rand(1, 200);
            // Ensure we don't accidentally hit the valid 32-byte length
            if ($len === 32) {
                $len = 31;
            }
            do {
                $bytes = random_bytes($len);
                // FileMasterKeyProvider trim()s file content before the length
                // check, so a blob with whitespace-class lead/trail bytes can
                // shrink to a VALID 32-byte key (e.g. 33 bytes ending in \n).
                // Regenerate until the trimmed form stays invalid.
            } while (\strlen(trim($bytes)) === 32);
            $cases["random_bytes_{$i}_len{$len}"] = [$bytes];
        }

        return $cases;
    }

    /**
     * Invalid environment variable contents. Raw binary keys are intentionally
     * NOT fuzzed here because putenv() mangles null bytes and non-ASCII — a
     * realistic env deployment always uses base64 or hex encoding.
     *
     * @return array<string, array{string}>
     */
    public static function invalidEnvValueProvider(): array
    {
        return [
            'short 10 chars' => ['short'],
            'short 31 chars' => [str_repeat('a', 31)],
            'too long 33 chars' => [str_repeat('a', 33)],
            'invalid base64' => ['!!!---not-base64===' . str_repeat('x', 20)],
            'base64 short' => [base64_encode(str_repeat('a', 16))],
            'base64 overflow' => [base64_encode(str_repeat('a', 64))],
            'hex no decode 64 chars' => [bin2hex(random_bytes(32))], // 64 chars ≠ 32 bytes raw
            'control chars no NUL' => [str_repeat("\x01", 16)],
            'json' => ['{"key":"something"}'],
            'pem fragment' => ['-----BEGIN PRIVATE KEY-----'],
        ];
    }

    // -----------------------------------------------------------------------
    // FileMasterKeyProvider tests
    // -----------------------------------------------------------------------

    #[Test]
    #[DataProvider('invalidFileContentProvider')]
    public function invalidFileContentIsRejected(string $content): void
    {
        $path = vfsStream::url('keys/master.key');
        file_put_contents($path, $content);

        $config = $this->createConfig($path);
        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $provider->getMasterKey();
    }

    #[Test]
    public function validBinaryKeyIsAccepted(): void
    {
        $validKey = random_bytes(32);
        $path = vfsStream::url('keys/master.key');
        file_put_contents($path, $validKey);

        $config = $this->createConfig($path);
        $provider = new FileMasterKeyProvider($config);

        self::assertSame($validKey, $provider->getMasterKey());
    }

    #[Test]
    public function validBase64EncodedKeyIsAccepted(): void
    {
        $validKey = random_bytes(32);
        $path = vfsStream::url('keys/master.key');
        file_put_contents($path, base64_encode($validKey));

        $config = $this->createConfig($path);
        $provider = new FileMasterKeyProvider($config);

        self::assertSame($validKey, $provider->getMasterKey());
    }

    #[Test]
    public function validBase64WithTrailingNewlineIsAccepted(): void
    {
        $validKey = random_bytes(32);
        $path = vfsStream::url('keys/master.key');
        // Text editor-style trailing newline
        file_put_contents($path, base64_encode($validKey) . "\n");

        $config = $this->createConfig($path);
        $provider = new FileMasterKeyProvider($config);

        self::assertSame($validKey, $provider->getMasterKey());
    }

    #[Test]
    public function missingFileThrowsCleanException(): void
    {
        $config = $this->createConfig(vfsStream::url('keys/does-not-exist.key'));
        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $provider->getMasterKey();
    }

    #[Test]
    public function unreadableFileThrowsCleanException(): void
    {
        $path = vfsStream::url('keys/locked.key');
        file_put_contents($path, random_bytes(32));
        // vfsStream honors chmod — remove all read permissions
        chmod($path, 0o000);

        $config = $this->createConfig($path);
        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);

        try {
            $provider->getMasterKey();
        } finally {
            // Restore for cleanup
            chmod($path, 0o600);
        }
    }

    #[Test]
    public function emptyConfiguredPathThrowsCleanException(): void
    {
        $config = $this->createConfig('');
        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $provider->getMasterKey();
    }

    #[Test]
    public function keyFileWithWrongByteLengthAlwaysThrows(): void
    {
        // Explicit parametric coverage of the 32-byte boundary
        foreach ([0, 1, 15, 16, 31, 33, 48, 64, 128, 1024] as $length) {
            FileMasterKeyProvider::clearCachedKey();
            $path = vfsStream::url("keys/len-{$length}.key");
            file_put_contents($path, str_repeat("\x01", $length));

            $config = $this->createConfig($path);
            $provider = new FileMasterKeyProvider($config);

            try {
                $provider->getMasterKey();
                self::fail("Key file of length {$length} was accepted — expected MasterKeyException");
            } catch (MasterKeyException) {
                // expected
            }
        }

        self::assertTrue(true, 'All non-32-byte lengths rejected');
    }

    // -----------------------------------------------------------------------
    // EnvironmentMasterKeyProvider tests
    // -----------------------------------------------------------------------

    #[Test]
    #[DataProvider('invalidEnvValueProvider')]
    public function invalidEnvVarValueIsRejected(string $value): void
    {
        $varName = 'NR_VAULT_TEST_MASTER_KEY_' . bin2hex(random_bytes(4));
        putenv($varName . '=' . $value);

        try {
            $config = $this->createConfig($varName);
            $provider = new EnvironmentMasterKeyProvider($config);

            $this->expectException(MasterKeyException::class);
            $provider->getMasterKey();
        } finally {
            putenv($varName); // unset
        }
    }

    #[Test]
    public function unsetEnvVarThrowsCleanException(): void
    {
        $varName = 'NR_VAULT_TEST_UNSET_' . bin2hex(random_bytes(4));
        // ensure unset
        putenv($varName);

        $config = $this->createConfig($varName);
        $provider = new EnvironmentMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $provider->getMasterKey();
    }

    #[Test]
    public function emptyEnvVarThrowsCleanException(): void
    {
        $varName = 'NR_VAULT_TEST_EMPTY_' . bin2hex(random_bytes(4));
        putenv($varName . '=');

        try {
            $config = $this->createConfig($varName);
            $provider = new EnvironmentMasterKeyProvider($config);

            $this->expectException(MasterKeyException::class);
            $provider->getMasterKey();
        } finally {
            putenv($varName);
        }
    }

    #[Test]
    public function validBase64EnvVarIsAccepted(): void
    {
        $validKey = random_bytes(32);
        $varName = 'NR_VAULT_TEST_OK_' . bin2hex(random_bytes(4));
        putenv($varName . '=' . base64_encode($validKey));

        try {
            $config = $this->createConfig($varName);
            $provider = new EnvironmentMasterKeyProvider($config);

            self::assertSame($validKey, $provider->getMasterKey());
        } finally {
            EnvironmentMasterKeyProvider::clearCachedKey();
            putenv($varName);
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private function createConfig(string $source): ExtensionConfigurationInterface
    {
        /** @var ExtensionConfigurationInterface&Stub $config */
        $config = $this->createStub(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($source);
        // Auto-key fallback must point somewhere that doesn't exist to avoid
        // masking validation failures.
        $config->method('getAutoKeyPath')->willReturn(vfsStream::url('keys/.not-present-auto.key'));

        return $config;
    }
}
