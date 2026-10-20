<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use PhpCsFixer\Runner\Parallel\ParallelConfigFactory;

$createConfig = require __DIR__ . '/.Build/vendor/netresearch/typo3-ci-workflows/config/php-cs-fixer/config.php';

// The shared rule set plus the rules of this repository that are stricter
// than it: rules the shared set leaves off, and configurations that check
// more than the shared one.
$extraRules = [
    'strict_comparison' => true,
    'strict_param'      => true,

    // The shared set switches these two off; this repository keeps them on.
    'self_accessor'              => true,
    'no_superfluous_phpdoc_tags' => [
        'allow_mixed'       => true,
        'remove_inheritdoc' => true,
    ],

    'class_attributes_separation' => [
        'elements' => [
            'const'    => 'one',
            'method'   => 'one',
            'property' => 'one',
        ],
    ],
    'ordered_class_elements' => [
        'order' => [
            'case', // Enum cases must come first
            'use_trait',
            'constant_public',
            'constant_protected',
            'constant_private',
            'property_public',
            'property_protected',
            'property_private',
            'construct',
            'destruct',
            'magic',
            'phpunit',
            'method_public',
            'method_protected',
            'method_private',
        ],
    ],

    'no_superfluous_elseif'     => true,
    'simplified_if_return'      => true,
    'void_return'               => true,
    'combine_consecutive_issets' => true,
    'combine_consecutive_unsets' => true,
    'return_assignment'         => true,
    'phpdoc_no_empty_return'    => true,
    'method_chaining_indentation' => true,
    'multiline_whitespace_before_semicolons' => ['strategy' => 'no_multi_line'],
    'phpdoc_line_span' => [
        'const'    => 'single',
        'method'   => 'multi',
        'property' => 'single',
    ],
    'unary_operator_spaces'       => ['only_dec_inc' => false],
    'blank_line_before_statement' => [
        'statements' => ['return', 'throw', 'try'],
    ],

    // The fixer's default list after constructs, plus the shared set's
    // "else"/"elseif" before them.
    'single_space_around_construct' => [
        'constructs_preceded_by_a_single_space' => ['as', 'else', 'elseif', 'use_lambda'],
    ],

    // The shared @Symfony token list plus "break" and "return".
    'no_extra_blank_lines' => [
        'tokens' => [
            'attribute', 'break', 'case', 'continue', 'curly_brace_block', 'default', 'extra',
            'parenthesis_brace_block', 'return', 'square_brace_block', 'switch', 'throw', 'use',
        ],
    ],
];

$config = $createConfig(
    "Copyright (c) 2025-2026 Netresearch DTT GmbH\nSPDX-License-Identifier: GPL-2.0-or-later",
    __DIR__,
    $extraRules,
    [
        // Stand-ins for TYPO3's own upgrade API, not code of this extension.
        'Build/phpstan/stubs',
    ],
);

// The manual includes the PHP files under Documentation/ with :lines:
// ranges, and two of them run in functional tests; a header would shift
// every range. A plain 'Documentation' exclude would match at any depth and
// also drop Tests/Functional/Documentation/, so only the top-level
// directory is left out.
$finder = $config->getFinder();
if ($finder instanceof PhpCsFixer\Finder) {
    $finder->notPath('#^Documentation/#');
}

return $config->setParallelConfig(ParallelConfigFactory::detect());
