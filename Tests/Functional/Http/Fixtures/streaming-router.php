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
 * Router for PHP's built-in web server, used by StreamingSendTest for the
 * streaming and the cancellable send.
 *
 * Every route writes to the socket as it goes — output buffering off, one
 * flush per line — so the client can observe when each line was sent. Each
 * line carries the server's own send time in microseconds since the epoch.
 *
 * Routes:
 *   /chunks?count=N&delay_ms=D  N lines, D milliseconds apart
 *   /stall                      one line, then silence for 30 seconds
 *   /silent                     nothing, not even a head, for 10 seconds, then one line
 *   /truncated                  announces 1000 bytes, sends 16, and exits 0.5 s later
 *   /redirect                   302 to /redirect-target
 *   /redirect-target            records that it was reached
 *   /echo-auth                  the Authorization header it received, as a line
 *   /large?mb=N                 N MiB of plain bytes, in 64 KiB writes
 *   /bomb?mb=N                  N MiB of zero bytes, gzip-compressed, sent as
 *                               Content-Encoding: gzip whatever was asked for
 *
 * NR_VAULT_STREAM_HITS names a directory; each route that is reached drops a
 * file there named after itself, so a test can prove a route was never hit.
 */
$requestUri = is_string($_SERVER['REQUEST_URI'] ?? null) ? $_SERVER['REQUEST_URI'] : '/';
$path = (string) parse_url($requestUri, PHP_URL_PATH);
$query = [];
parse_str((string) parse_url($requestUri, PHP_URL_QUERY), $query);

$hitsDirectory = getenv('NR_VAULT_STREAM_HITS');
// The file name comes from this fixed map, never from the request.
$hitNames = [
    '/chunks' => 'chunks',
    '/stall' => 'stall',
    '/silent' => 'silent',
    '/truncated' => 'truncated',
    '/redirect' => 'redirect',
    '/redirect-target' => 'redirect-target',
    '/echo-auth' => 'echo-auth',
    '/large' => 'large',
    '/bomb' => 'bomb',
];
if (is_string($hitsDirectory) && $hitsDirectory !== '' && is_dir($hitsDirectory) && isset($hitNames[$path])) {
    touch($hitsDirectory . '/' . $hitNames[$path]);
}

while (ob_get_level() > 0) {
    ob_end_flush();
}

ob_implicit_flush(true);

// One echo per line: PHP sends each echo argument as its own write, and a
// line split across writes can be split across the client's reads.
$line = static function (string $text): void {
    echo $text . ' sent_us=' . (int) (microtime(true) * 1_000_000) . "\n";
    flush();
};

switch ($path) {
    case '/chunks':
        $count = max(1, (int) ($query['count'] ?? 3));
        $delayMicroseconds = max(0, (int) ($query['delay_ms'] ?? 0)) * 1000;
        header('Content-Type: text/plain');
        for ($i = 1; $i <= $count; ++$i) {
            if ($i > 1) {
                usleep($delayMicroseconds);
            }

            $line('chunk ' . $i);
        }

        return true;
    case '/stall':
        header('Content-Type: text/plain');
        $line('before stall');
        sleep(30);
        $line('after stall');

        return true;
    case '/silent':
        // The built-in server sends the head with the first output, so
        // nothing at all leaves before this sleep ends.
        sleep(10);
        header('Content-Type: text/plain');
        $line('after silence');

        return true;
    case '/truncated':
        header('Content-Type: text/plain');
        header('Content-Length: 1000');
        echo 'sixteen bytes!!!';
        flush();
        // Long enough for the client to have returned at the headers and read
        // the bytes: the failure has to land while the body is being read.
        usleep(500_000);
        exit;

    case '/redirect':
        header('Location: /redirect-target', true, 302);
        echo 'redirecting';

        return true;
    case '/redirect-target':
        header('Content-Type: text/plain');
        echo 'redirect target reached';

        return true;
    case '/echo-auth':
        header('Content-Type: text/plain');
        $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $line('authorization=' . (is_string($authorization) ? $authorization : ''));

        return true;
    case '/large':
        $megabytes = max(1, (int) ($query['mb'] ?? 1));
        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . $megabytes * 1024 * 1024);
        $block = str_repeat('x', 64 * 1024);
        for ($i = 0; $i < $megabytes * 16; ++$i) {
            echo $block;
            flush();
        }

        return true;
    case '/bomb':
        $megabytes = max(1, (int) ($query['mb'] ?? 1));
        $deflate = deflate_init(ZLIB_ENCODING_GZIP, ['level' => 9]);
        if ($deflate === false) {
            http_response_code(500);

            return true;
        }

        $zeros = str_repeat("\0", 1024 * 1024);
        $compressed = '';
        for ($i = 0; $i < $megabytes; ++$i) {
            $compressed .= (string) deflate_add($deflate, $zeros, ZLIB_NO_FLUSH);
        }

        $compressed .= (string) deflate_add($deflate, '', ZLIB_FINISH);
        header('Content-Type: application/octet-stream');
        header('Content-Encoding: gzip');
        header('Content-Length: ' . strlen($compressed));
        echo $compressed;
        flush();

        return true;
    case '/ready':
        header('Content-Type: text/plain');
        echo 'ready';

        return true;
}

http_response_code(404);
echo 'no such route';

return true;
