<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor;

/**
 * Deep links from a {@see Finding} into the rendered documentation.
 *
 * Centralised as constants rather than inlined per check so a moved section
 * breaks in one place, and so `grep DocsLink Classes/` lists every documentation
 * anchor the diagnostics promise to keep alive. Each constant corresponds to an
 * explicit `.. _label:` target in `Documentation/`; do not point one at a
 * generated heading anchor, which changes whenever the heading text does.
 */
final class DocsLink
{
    public const BASE = 'https://docs.typo3.org/p/netresearch/nr-vault/main/en-us/';

    public const MASTER_KEY_PROVIDERS = self::BASE . 'Configuration/Index.html#configuration-master-key-providers';

    public const MASTER_KEY_FILE = self::BASE . 'Security/Index.html#security-file-storage';

    public const SECURITY_PROFILES = self::BASE . 'Configuration/Index.html#configuration-extension';

    public const ADMIN_OVERRIDE = self::BASE . 'Security/Index.html#security-disable-admin-override';

    public const BREAK_GLASS = self::BASE . 'Security/Index.html#security-break-glass';

    public const AUDIT_LOGGING = self::BASE . 'Security/Index.html#security-audit-logging';

    public const AUDIT_HASH_CHAIN = self::BASE . 'Security/Index.html#security-hash-chain';

    public const AUDIT_SINKS = self::BASE . 'Configuration/Index.html#configuration-audit-sinks';

    public const AUDIT_SINK_SCHEDULING = self::BASE . 'Configuration/Index.html#configuration-audit-sink-scheduling';

    public const ACCESS_CONTROL = self::BASE . 'Configuration/Index.html#configuration-access-control';

    public const DEPLOYMENT_GATE = self::BASE . 'Security/Index.html#security-deployment-gate';

    public const COMMANDS = self::BASE . 'Developer/Commands.html#developer-commands';
}
