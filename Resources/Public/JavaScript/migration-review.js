/**
 * "Select all" checkbox on the migration wizard's review step.
 *
 * Loaded as an ES module through the backend import map
 * (`<f:asset.module>`), not as an inline `<f:asset.script>`: an inline script
 * needs a CSP nonce, and the argument that requests one is `useNonce` on
 * TYPO3 13.4 but deprecated in favour of `csp` on 14.3. A module needs neither
 * on both versions.
 */
const selectAll = document.getElementById('select-all');

if (selectAll !== null) {
    selectAll.addEventListener('change', () => {
        document.querySelectorAll('.secret-checkbox').forEach((checkbox) => {
            checkbox.checked = selectAll.checked;
        });
    });
}
