<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Fixtures;

use GuzzleHttp\Psr7\Response;
use LogicException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * PSR-18 client that answers from a queue and keeps every request it saw.
 *
 * An empty queue is a test failure, not a default answer: a request nobody
 * planned for must not pass silently.
 */
final class RecordingHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    /** @var list<ResponseInterface|Throwable> */
    private array $queue;

    public function __construct(ResponseInterface|Throwable ...$queue)
    {
        $this->queue = array_values($queue);
    }

    /**
     * @param array<array-key, mixed> $body
     */
    public static function json(int $status, array $body): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR));
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        $next = array_shift($this->queue);
        if ($next === null) {
            throw new LogicException('Unplanned request: ' . $request->getMethod() . ' ' . $request->getUri(), 7772755725);
        }

        if ($next instanceof Throwable) {
            throw $next;
        }

        return $next;
    }

    /**
     * @return array<array-key, mixed>
     */
    public function bodyOf(int $index): array
    {
        $decoded = json_decode((string) $this->requests[$index]->getBody(), true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new LogicException('The request body is not a JSON object.', 4695013643);
        }

        return $decoded;
    }
}
