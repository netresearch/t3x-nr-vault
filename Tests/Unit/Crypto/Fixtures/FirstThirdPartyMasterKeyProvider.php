<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto\Fixtures;

/**
 * The provider a test registers first, and the default everywhere a single one
 * is enough. Distinct from {@see SecondThirdPartyMasterKeyProvider} only in
 * class name — which is the point: the collision exception names both classes.
 */
final class FirstThirdPartyMasterKeyProvider extends AbstractThirdPartyMasterKeyProvider {}
