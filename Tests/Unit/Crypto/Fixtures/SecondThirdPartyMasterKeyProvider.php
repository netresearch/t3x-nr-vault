<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto\Fixtures;

/**
 * The second provider in a collision: a different extension claiming an
 * identifier {@see FirstThirdPartyMasterKeyProvider} already holds. Its own
 * class name is what proves the exception names the conflicting side too.
 */
final class SecondThirdPartyMasterKeyProvider extends AbstractThirdPartyMasterKeyProvider {}
