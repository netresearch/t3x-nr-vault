<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

use RuntimeException;
use Testcontainers\Utils\PortGenerator\PortGenerator;

use function sprintf;

/**
 * Asks the operating system for a port nobody is using.
 *
 * The library's own generator draws random ports and never checks them, so a
 * port that is already taken makes the container start fail, and a drawing that
 * repeats on one runner makes it fail every time.
 */
final class FreePortGenerator implements PortGenerator
{
    public function generatePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
        if ($socket === false) {
            throw new RuntimeException(sprintf('Could not reserve a free port: %s', $errorMessage), 1794400105);
        }

        $name = (string) stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }
}
