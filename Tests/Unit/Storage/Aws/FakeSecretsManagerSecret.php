<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage\Aws;

use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use LogicException;
use Psr\Http\Message\RequestInterface;

use function count;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;

/**
 * One AWS Secrets Manager secret as a Guzzle handler, so the real SDK and the
 * real store talk to it. It models what the conditional rollback depends on,
 * as the API reference describes it: versions, the AWSCURRENT and AWSPREVIOUS
 * labels, GetSecretValue returning AWSCURRENT, PutSecretValue moving both
 * labels, and UpdateSecretVersionStage failing when the label is attached to a
 * version other than RemoveFromVersionId ("If the label is attached and you
 * either do not specify this parameter, or the version ID does not match, then
 * the operation fails"), and moving AWSPREVIOUS to the version AWSCURRENT was
 * removed from.
 *
 * It replaces moto for this behaviour: moto 5.2.5 does not move the default
 * version on a stage move (#567). The error code of a mismatch is not
 * documented by AWS, so it is a parameter here.
 */
final class FakeSecretsManagerSecret
{
    /** @var array<string, string> Version id => SecretString */
    private array $versions = [];

    /** @var array<string, string> Label => version id */
    private array $labels = [];

    /** @var list<string> */
    private array $targets = [];

    /** @var list<string> */
    private array $denied = [];

    private ?string $concurrentValue = null;

    public function __construct(
        private readonly string $name,
        private readonly string $mismatchCode = 'InvalidParameterException',
    ) {}

    public function __invoke(RequestInterface $request): PromiseInterface
    {
        $target          = substr($request->getHeaderLine('X-Amz-Target'), strlen('secretsmanager.'));
        $this->targets[] = $target;

        /** @var array<string, mixed> $body */
        $body = json_decode((string) $request->getBody(), true, 32, JSON_THROW_ON_ERROR);
        if (($body['SecretId'] ?? null) !== $this->name) {
            return $this->error('ResourceNotFoundException');
        }

        if (in_array($target, $this->denied, true)) {
            return $this->error('AccessDeniedException');
        }

        if ($this->concurrentValue !== null && in_array($target, ['PutSecretValue', 'UpdateSecretVersionStage'], true)) {
            $this->put($this->concurrentValue);
            $this->concurrentValue = null;
        }

        return match ($target) {
            'GetSecretValue'           => $this->getSecretValue(),
            'PutSecretValue'           => $this->putSecretValue($body),
            'UpdateSecretVersionStage' => $this->updateSecretVersionStage($body),
            default                    => throw new LogicException('The fake does not model ' . $target . '.', 1794567002),
        };
    }

    /**
     * @param array<string, mixed> $data
     *
     * @return string The version id
     */
    public function seed(array $data): string
    {
        return $this->put(json_encode($data, JSON_THROW_ON_ERROR));
    }

    /**
     * Answer this action with AccessDeniedException.
     */
    public function deny(string $action): void
    {
        $this->denied[] = $action;
    }

    /**
     * Another writer puts this document right before the next PutSecretValue
     * or UpdateSecretVersionStage that reaches the secret: after any read the
     * caller made, before its write.
     *
     * @param array<string, mixed> $data
     */
    public function concurrentPutBeforeNextWrite(array $data): void
    {
        $this->concurrentValue = json_encode($data, JSON_THROW_ON_ERROR);
    }

    /**
     * @return array<string, mixed>
     */
    public function currentData(): array
    {
        $decoded = json_decode($this->versions[$this->labels['AWSCURRENT']], true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new LogicException('The fake holds a document that is not a JSON object.', 1794567001);
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    public function versionLabelled(string $label): ?string
    {
        return $this->labels[$label] ?? null;
    }

    public function versionCount(): int
    {
        return count($this->versions);
    }

    /**
     * The actions received so far, without the "secretsmanager." prefix.
     *
     * @return list<string>
     */
    public function targets(): array
    {
        return $this->targets;
    }

    private function getSecretValue(): PromiseInterface
    {
        $current = $this->labels['AWSCURRENT'] ?? null;
        if ($current === null) {
            return $this->error('ResourceNotFoundException');
        }

        return $this->json(['Name' => $this->name, 'VersionId' => $current, 'SecretString' => $this->versions[$current], 'VersionStages' => ['AWSCURRENT']]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function putSecretValue(array $body): PromiseInterface
    {
        $value = $body['SecretString'] ?? null;
        if (!is_string($value)) {
            throw new LogicException('PutSecretValue without SecretString.', 1794567003);
        }

        return $this->json(['Name' => $this->name, 'VersionId' => $this->put($value), 'VersionStages' => ['AWSCURRENT']]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function updateSecretVersionStage(array $body): PromiseInterface
    {
        $stage    = $body['VersionStage'] ?? null;
        $moveTo   = $body['MoveToVersionId'] ?? null;
        $remove   = $body['RemoveFromVersionId'] ?? null;
        $attached = is_string($stage) ? ($this->labels[$stage] ?? null) : null;

        if (!is_string($stage) || !is_string($moveTo) || !isset($this->versions[$moveTo])) {
            return $this->error('InvalidParameterException');
        }

        if ($attached !== null && $attached !== $moveTo && $remove !== $attached) {
            return $this->error($this->mismatchCode);
        }

        $this->labels[$stage] = $moveTo;
        if ($stage === 'AWSCURRENT' && $attached !== null && $attached !== $moveTo) {
            $this->labels['AWSPREVIOUS'] = $attached;
        }

        return $this->json(['Name' => $this->name, 'ARN' => 'arn:aws:secretsmanager:eu-central-1:123456789012:secret:' . $this->name]);
    }

    private function put(string $value): string
    {
        $id                  = sprintf('%08d-0000-4000-8000-%012d', count($this->versions) + 1, count($this->versions) + 1);
        $this->versions[$id] = $value;

        if (isset($this->labels['AWSCURRENT'])) {
            $this->labels['AWSPREVIOUS'] = $this->labels['AWSCURRENT'];
        }

        $this->labels['AWSCURRENT'] = $id;

        return $id;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function json(array $body, int $status = 200): PromiseInterface
    {
        return new FulfilledPromise(new Response($status, ['Content-Type' => 'application/x-amz-json-1.1'], json_encode($body, JSON_THROW_ON_ERROR)));
    }

    private function error(string $code): PromiseInterface
    {
        return $this->json(['__type' => $code, 'Message' => 'details that must not surface'], 400);
    }
}
