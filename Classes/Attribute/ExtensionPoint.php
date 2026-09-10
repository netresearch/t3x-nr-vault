<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Attribute;

use Attribute;

/**
 * Marks an interface that extensions are invited to IMPLEMENT, not only to
 * call: an extension point of nr-vault.
 *
 * The mark is a compatibility promise, and this attribute is the one place it
 * is recorded. The API snapshot renders it into the frozen surface, the
 * snapshot diff treats a new or changed method on a marked interface as a
 * break, and Documentation/Developer/Api.rst lists exactly the marked
 * interfaces — a unit test holds the three in step.
 *
 * The promise:
 *  - A marked interface gains no method, and none of its methods changes its
 *    signature, outside a major release. Either would break every existing
 *    implementation, however additive it looks to a caller.
 *  - A new capability arrives as a separate interface that an implementation
 *    may additionally implement and a caller feature-detects with
 *    `instanceof` — the way `CancellableHttpClientInterface` joined
 *    `VaultHttpClientInterface`.
 *  - An interface without the mark is for calling. It may gain methods in a
 *    minor release; implementing it outside this package is not supported.
 */
#[Attribute(Attribute::TARGET_CLASS)]
final readonly class ExtensionPoint {}
