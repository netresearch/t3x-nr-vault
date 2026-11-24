<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\QueryRecorder;

use Doctrine\DBAL\Driver\Connection;
use Doctrine\DBAL\Driver\Middleware\AbstractDriverMiddleware;
use SensitiveParameter;

final class QueryRecordingDriver extends AbstractDriverMiddleware
{
    public function connect(#[SensitiveParameter] array $params): Connection
    {
        return new QueryRecordingConnection(parent::connect($params));
    }
}
