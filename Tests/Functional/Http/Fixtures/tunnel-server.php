<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/**
 * A raw socket server for StreamingSendTest's proxy case, one connection at a
 * time. Adapted from the review probe of pull request #392.
 *
 * Usage: php tunnel-server.php <portFile> origin
 *        php tunnel-server.php <portFile> proxy <originPort>
 *
 * `origin` is a TLS server with a throwaway self-signed certificate that
 * answers every request with `401` and an `X-Origin` header. `proxy` answers
 * `CONNECT` with `200 Connection established` and an `X-Proxy` header, then
 * relays bytes to the origin. The chosen port is written to `<portFile>` once
 * the socket listens, and every request line it receives is appended to
 * `<portFile>.log`.
 */
$portFile = $argv[1] ?? '';
$mode = $argv[2] ?? '';

$context = stream_context_create();
$transport = 'tcp';
if ($mode === 'origin') {
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($key === false) {
        fwrite(STDERR, "key generation failed\n");
        exit(1);
    }

    $certificatePem = '';
    $keyPem = '';
    $csr = openssl_csr_new(['commonName' => 'tls-origin.test'], $key);
    $certificate = $csr === false || $csr === true ? false : openssl_csr_sign($csr, null, $key, 1);
    if (
        $certificate === false
        || !openssl_x509_export($certificate, $certificatePem)
        || !openssl_pkey_export($key, $keyPem)
        || !is_string($certificatePem)
        || !is_string($keyPem)
    ) {
        fwrite(STDERR, "certificate generation failed\n");
        exit(1);
    }

    $pemFile = $portFile . '.pem';
    file_put_contents($pemFile, $certificatePem . $keyPem);
    $context = stream_context_create(['ssl' => ['local_cert' => $pemFile, 'verify_peer' => false, 'allow_self_signed' => true]]);
    $transport = 'tls';
}

$server = stream_socket_server($transport . '://127.0.0.1:0', $errorCode, $errorMessage, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
if ($server === false) {
    fwrite(STDERR, 'listen failed: ' . $errorMessage . "\n");
    exit(1);
}

$name = (string) stream_socket_get_name($server, false);
file_put_contents($portFile . '.tmp', substr($name, (int) strrpos($name, ':') + 1));
rename($portFile . '.tmp', $portFile);

$readHead = static function ($connection): string {
    $head = '';
    while (!str_contains($head, "\r\n\r\n")) {
        $byte = fread($connection, 1);
        if ($byte === '' || $byte === false) {
            break;
        }

        $head .= $byte;
    }

    return $head;
};

// Runs until the test terminates the process.
while (is_resource($server)) {
    $connection = stream_socket_accept($server, 600);
    if ($connection === false) {
        continue;
    }

    $head = $readHead($connection);
    // One line per request, so a test can prove which server saw what.
    file_put_contents($portFile . '.log', strtok($head, "\r\n") . "\n", FILE_APPEND);

    if ($mode === 'origin') {
        fwrite($connection, "HTTP/1.1 401 Unauthorized\r\nX-Origin: target\r\nContent-Type: text/plain\r\nContent-Length: 17\r\nConnection: close\r\n\r\ntarget said: 401\n");
    } elseif ($mode === 'proxy') {
        $upstream = stream_socket_client('tcp://127.0.0.1:' . (int) ($argv[3] ?? 0), $errorCode, $errorMessage, 5);
        if ($upstream === false) {
            fclose($connection);

            continue;
        }

        fwrite($connection, "HTTP/1.1 200 Connection established\r\nX-Proxy: yes\r\n\r\n");
        stream_set_blocking($connection, false);
        stream_set_blocking($upstream, false);
        $done = false;
        while (!$done) {
            $readable = [$connection, $upstream];
            $write = null;
            $except = null;
            if (stream_select($readable, $write, $except, 10) < 1) {
                break;
            }

            foreach ($readable as $socket) {
                $data = fread($socket, 65536);
                if ($data === '' || $data === false) {
                    $done = $done || feof($socket);

                    continue;
                }

                fwrite($socket === $connection ? $upstream : $connection, $data);
            }
        }

        fclose($upstream);
    }

    fclose($connection);
}
