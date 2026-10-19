<?php

/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Netresearch DTT GmbH
 */
declare(strict_types=1);

namespace MyVendor\MyExtension\MessageHandler;

use MyVendor\MyExtension\Message\IngestMessage;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use RuntimeException;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
final readonly class IngestHandler
{
    /**
     * @param positive-int $technicalBeUserUid
     */
    public function __construct(
        private TechnicalActorContextInterface $technicalActorContext,
        private VaultServiceInterface $vaultService,
        private int $technicalBeUserUid,
    ) {}

    public function __invoke(IngestMessage $message): void
    {
        $apiKey = $this->technicalActorContext->runAs(
            $this->technicalBeUserUid,
            fn (): ?string => $this->vaultService->retrieve('my_ext_embeddings_api_key'),
        );
        if ($apiKey === null) {
            throw new RuntimeException('API key is not configured', 1784000112);
        }

        // Continue the application's message handling with $apiKey.
    }
}
