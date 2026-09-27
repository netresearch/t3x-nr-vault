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
 * Router for PHP's built-in web server, used by StreamingSendTest.
 *
 * Every route writes to the socket as it goes — output buffering off, one
 * flush per line — so the client can observe when each line was sent. Each
 * line carries the server's own send time in microseconds since the epoch.
 *
 * Routes:
 *   /chunks?count=N&delay_ms=D  N lines, D milliseconds apart
 *   /stall                      one line, then silence for 30 seconds
 *   /truncated                  announces 1000 bytes, sends 16, and exits 0.5 s later
 *   /redirect                   302 to /redirect-target
 *   /redirect-target            records that it was reached
 *   /echo-auth                  the Authorization header it received, as a line
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
    '/truncated' => 'truncated',
    '/redirect' => 'redirect',
    '/redirect-target' => 'redirect-target',
    '/echo-auth' => 'echo-auth',
];
if (is_string($hitsDirectory) && $hitsDirectory !== '' && is_dir($hitsDirectory) && isset($hitNames[$path])) {
    touch($hitsDirectory . '/' . $hitNames[$path]);
}

while (ob_get_level() > 0) {
    ob_end_flush();
}

ob_implicit_flush(true);

$line = static function (string $text): void {
    echo $text, ' sent_us=', (int) (microtime(true) * 1_000_000), "\n";
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
    case '/ready':
        header('Content-Type: text/plain');
        echo 'ready';

        return true;
}

http_response_code(404);
echo 'no such route';

return true;
