<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\Aws;

/**
 * What {@see AwsVersionedSecretStoreInterface::restoreToVersionIfCurrent()}
 * did, so the caller can log one message that matches it.
 */
enum AwsRestoreOutcome: string
{
    /**
     * A stage move succeeded, or the permission fallback put the value back.
     */
    case Applied = 'applied';

    /**
     * The move failed twice while the secret was still at our version.
     */
    case NotApplied = 'not-applied';

    /**
     * The move failed and AWSCURRENT showed the version it moves back to. That
     * is what an applied move whose answer was lost shows, and also what a read
     * that lags behind our own write shows; no read can tell them apart.
     */
    case Unconfirmed = 'unconfirmed';

    /**
     * AWSCURRENT is on another version, or the secret is gone.
     */
    case OtherWriter = 'other-writer';
}
