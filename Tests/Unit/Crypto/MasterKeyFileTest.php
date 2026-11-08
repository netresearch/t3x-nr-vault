<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Crypto\MasterKeyFile;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(MasterKeyFile::class)]
final class MasterKeyFileTest extends TestCase
{
    private vfsStreamDirectory $root;

    protected function setUp(): void
    {
        parent::setUp();
        $this->root = vfsStream::setup('keys');
    }

    #[Test]
    public function readsARawKey(): void
    {
        $key = sodium_crypto_secretbox_keygen();

        self::assertSame($key, MasterKeyFile::read($this->keyFile($key)));
    }

    #[Test]
    public function readsABase64KeyWithATrailingNewline(): void
    {
        $key = sodium_crypto_secretbox_keygen();

        self::assertSame($key, MasterKeyFile::read($this->keyFile(base64_encode($key) . "\n")));
    }

    /**
     * A raw key whose last byte is a trim character must not be trimmed to 31 bytes.
     */
    #[Test]
    public function keepsARawKeyEndingInATrimCharacter(): void
    {
        $key = substr(sodium_crypto_secretbox_keygen(), 0, 31) . "\n";

        self::assertSame($key, MasterKeyFile::read($this->keyFile($key)));
    }

    #[Test]
    public function rejectsAMissingFile(): void
    {
        $this->expectException(MasterKeyException::class);

        MasterKeyFile::read(vfsStream::url('keys/missing.key'));
    }

    #[Test]
    public function rejectsAnUnreadableFile(): void
    {
        $path = $this->keyFile(sodium_crypto_secretbox_keygen());
        chmod($path, 0o000);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessageToContain('not readable');

        MasterKeyFile::read($path);
    }

    #[Test]
    public function rejectsAKeyOfTheWrongLength(): void
    {
        $this->expectException(MasterKeyException::class);

        MasterKeyFile::read($this->keyFile('short'));
    }

    private function keyFile(string $content): string
    {
        vfsStream::newFile('master.key')->withContent($content)->at($this->root);

        return vfsStream::url('keys/master.key');
    }
}
