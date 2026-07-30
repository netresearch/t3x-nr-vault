<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

use Netresearch\NrVault\Utility\LocalisationHelper;
use Psr\Log\LoggerInterface;
use Throwable;
use TYPO3\CMS\Core\Localization\LanguageService;

/**
 * Reports a failed vault operation to the backend user without telling them why
 * it failed.
 *
 * The DataHandler hooks used to interpolate the raw vault exception message into
 * the flash message *and* into the `DataHandler::log()` detail — core replays
 * both to the editor who triggered the save. `SecretNotFoundException` and
 * `AccessDeniedException` are textually distinct, so an editor who controls the
 * submitted `_vault_identifier` could tell "does not exist" from "exists, but you
 * may not touch it" and enumerate secrets outside their ACL (CWE-209).
 *
 * {@see report()} therefore returns one cause-independent sentence carrying a
 * random correlation reference, and writes the cause to the server-side log under
 * that same reference so an administrator can still diagnose the failure.
 *
 * Everything variable goes into the PSR-3 *context* array, never into the message
 * argument: TYPO3's `FileWriter` writes the message verbatim
 * (`fwrite($handle, $message . LF)`) while `json_encode()`-ing the context, so
 * attacker bytes in the message would let a crafted identifier forge whole log
 * records — including a forged record quoting the reference the user was told to
 * report. Context values are additionally stripped of control bytes and
 * length-capped, because not every configured writer encodes context the same way
 * and because an unbounded value would let repeated failed saves inflate the log.
 */
final readonly class VaultFailureReporter
{
    /**
     * Constant, placeholder-free log message.
     *
     * It must stay free of variable data (see the class docblock) and free of
     * `{placeholder}` tokens, which TYPO3's writers interpolate from the context
     * back into the raw message.
     */
    private const LOG_MESSAGE = 'Vault operation failed';

    private const LABEL_KEY = 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:hook.vaultFailure.reference';

    private const FALLBACK_MESSAGE = 'The vault operation could not be completed. Please ask an administrator to check the vault log for reference %s.';

    /** Byte cap applied to every string written into the log context. */
    private const MAX_LOGGED_VALUE_LENGTH = 200;

    public function __construct(
        private LoggerInterface $logger,
    ) {}

    /**
     * Log the cause server-side, return the cause-independent message for the user.
     *
     * @param array<string, string|int|null> $context Where the failure happened (table, field,
     *                                                uid, identifier, operation). Never pass a
     *                                                secret value — record coordinates only.
     *
     * @return string The message to show the backend user; carries only the correlation reference
     */
    public function report(Throwable $error, array $context = []): string
    {
        $reference = bin2hex(random_bytes(8));

        $logContext = ['reference' => $reference];

        foreach ($context as $key => $value) {
            $logContext[$key] = \is_string($value) ? self::sanitiseForLog($value) : $value;
        }

        // Deliberately NOT the 'exception' key: TYPO3's FileWriter folds a
        // Throwable stored there into the unescaped message. Class name and
        // sanitised text only.
        $logContext['exceptionClass'] = $error::class;
        $logContext['error'] = self::sanitiseForLog($error->getMessage());

        $this->logger->error(self::LOG_MESSAGE, $logContext);

        return str_replace('%s', $reference, $this->getMessageTemplate());
    }

    /**
     * Strip control bytes (so no value can start a forged log line) and cap the
     * length (so repeated failures cannot inflate the log), then force valid
     * UTF-8 so the record survives `json_encode()`.
     */
    private static function sanitiseForLog(string $value): string
    {
        // Byte-wise class, deliberately without the /u modifier: it matches C0
        // plus DEL, leaves UTF-8 continuation bytes alone, and cannot fail (and
        // return null) on malformed input the way a /u pattern does.
        $clean = preg_replace('/[[:cntrl:]]/', '', $value) ?? '';

        if (\strlen($clean) > self::MAX_LOGGED_VALUE_LENGTH) {
            $clean = substr($clean, 0, self::MAX_LOGGED_VALUE_LENGTH);
        }

        // Truncation can split a multi-byte sequence, and the raw value may not
        // have been UTF-8 in the first place; either would make json_encode()
        // fail and drop the whole context array. Substitute the invalid bytes.
        return mb_convert_encoding($clean, 'UTF-8', 'UTF-8');
    }

    private function getMessageTemplate(): string
    {
        /** @var mixed $languageService */
        $languageService = $GLOBALS['LANG'] ?? null;

        if (!$languageService instanceof LanguageService) {
            return self::FALLBACK_MESSAGE;
        }

        return LocalisationHelper::translateOrFallback(
            $languageService,
            self::LABEL_KEY,
            self::FALLBACK_MESSAGE,
        );
    }
}
