<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Seeder;

/**
 * Fixed, deterministic set of demo secrets covering every analytics bucket.
 */
final readonly class DemoDataProvider
{
    /**
     * @return list<DemoSecretSpec>
     */
    public function specs(): array
    {
        return [
            new DemoSecretSpec('stripe_live_key', 'sk_live_demo_4242', 'Stripe live API key', 'payment', 120, 412, 1, 14, 365, false, [
                new DemoEvent('read', 'api', '_cli_', 0, 1),
                new DemoEvent('read', 'api', '_cli_', 0, 3),
                new DemoEvent('read', 'scheduler', '_scheduler_', 0, 7),
                new DemoEvent('rotate', 'backend', 'admin', 1, 14),
            ]),
            new DemoSecretSpec('sendgrid_api', 'SG.demo.token', 'SendGrid transactional mail', 'mail', 90, 210, 2, null, null, false, [
                new DemoEvent('read', 'api', '_cli_', 0, 2),
                new DemoEvent('read', 'cli', '_cli_', 0, 9),
            ]),
            new DemoSecretSpec('stripe_test_old', 'sk_test_demo_old', 'Legacy Stripe test key', 'payment', 214, 0, null, null, null, false, []),
            new DemoSecretSpec('backup_encryption_key', 'demo-backup-key', 'Old backup encryption key', '', 198, 0, null, null, null, false, []),
            new DemoSecretSpec('legacy_webhook_secret', 'whsec_demo', 'Decommissioned webhook secret', 'integration', 260, 6, 140, null, null, false, [
                new DemoEvent('read', 'api', '_cli_', 0, 140),
            ]),
            new DemoSecretSpec('legacy_smtp_password', 'demo-smtp-pass', 'Manual SMTP password', 'mail', 320, 9, 41, null, null, false, [
                new DemoEvent('read', 'backend', 'admin', 1, 41),
                new DemoEvent('read', 'backend', 'editor', 2, 55),
                new DemoEvent('read', 'backend', 'admin', 1, 70),
            ]),
            new DemoSecretSpec('mailchimp_api_v2', 'demo-mc-key', 'Mailchimp (manual use)', 'integration', 240, 3, 67, null, null, false, [
                new DemoEvent('read', 'backend', 'admin', 1, 67),
            ]),
            new DemoSecretSpec('expired_api_token', 'demo-expired', 'Expired integration token', 'integration', 96, 12, 1, null, -5, false, [
                new DemoEvent('read', 'api', '_cli_', 0, 1),
            ]),
            new DemoSecretSpec('temp_migration_token', 'demo-temp', 'Temp migration token', '', 133, 0, null, null, -30, false, []),
            new DemoSecretSpec('old_ftp_credentials', 'demo-ftp', 'Old FTP credentials', 'integration', 410, 54, 3, null, null, false, [
                new DemoEvent('read', 'cli', '_cli_', 0, 3),
                new DemoEvent('read', 'cli', '_cli_', 0, 12),
            ]),
            new DemoSecretSpec('public_maps_key', 'demo-maps', 'Frontend maps key', 'integration', 60, 880, 0, 30, null, true, [
                new DemoEvent('read', 'api', '_cli_', 0, 0),
            ]),
            new DemoSecretSpec('aws_s3_secret', 'demo-aws', 'AWS S3 secret', 'integration', 80, 130, 1, 20, null, false, [
                new DemoEvent('read', 'scheduler', '_scheduler_', 0, 1),
            ]),
            new DemoSecretSpec('redis_password', 'demo-redis', 'Redis password', '', 75, 95, 1, null, null, false, [
                new DemoEvent('read', 'api', '_cli_', 0, 1),
            ]),
            new DemoSecretSpec('jwt_signing_key', 'demo-jwt', 'JWT signing key', 'integration', 50, 300, 0, 10, null, false, [
                new DemoEvent('read', 'api', '_cli_', 0, 0),
            ]),
            new DemoSecretSpec('paypal_client_secret', 'demo-paypal', 'PayPal client secret', 'payment', 110, 70, 2, 25, 365, false, [
                new DemoEvent('read', 'api', '_cli_', 0, 2),
            ]),
            new DemoSecretSpec('smtp_relay_token', 'demo-relay', 'SMTP relay token', 'mail', 45, 60, 1, null, null, false, [
                new DemoEvent('read', 'api', '_cli_', 0, 1),
            ]),
        ];
    }
}
