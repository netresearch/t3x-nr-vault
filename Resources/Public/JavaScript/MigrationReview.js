/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Netresearch DTT GmbH
 */

/**
 * Migration wizard, review step: the "select all" checkbox.
 *
 * Loaded as an ES module through the backend import map (`<f:asset.module>`),
 * not as an inline `<f:asset.script>`: an inline script needs a CSP nonce, and
 * the argument that requests one is `useNonce` on TYPO3 13.4 but deprecated in
 * favour of `csp` on 14.3. A module needs neither on both versions.
 */
class MigrationReview {
    constructor() {
        this.init();
    }

    init() {
        const selectAll = document.getElementById('select-all');
        if (!selectAll) return;

        selectAll.addEventListener('change', () => {
            document.querySelectorAll('.secret-checkbox').forEach((checkbox) => {
                checkbox.checked = selectAll.checked;
            });
        });
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new MigrationReview());
} else {
    new MigrationReview(); // NOSONAR: side-effect entry module — instantiation wires up page event handlers on load
}

export default MigrationReview;
