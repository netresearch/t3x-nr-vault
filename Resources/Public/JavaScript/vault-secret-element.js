/**
 * JavaScript module for vault secret TCA form element.
 *
 * Handles:
 * - Reveal existing secrets via AJAX (toggle visibility)
 * - Copy to clipboard functionality
 * - Clear secret
 */
import Modal from '@typo3/backend/modal.js';
import Severity from '@typo3/backend/severity.js';

/**
 * Look up a backend label registered via PageRenderer::addInlineLanguageLabelFile()
 * (locallang_js.xlf), falling back to the English default. Supports {0}, {1}, ...
 * placeholder substitution.
 *
 * @param {string} key
 * @param {string} fallback
 * @param {...string} args
 * @returns {string}
 */
function lang(key, fallback, ...args) {
    let text = (typeof TYPO3 !== 'undefined' && TYPO3.lang && TYPO3.lang[key]) || fallback;
    args.forEach((value, index) => {
        // Use a replacer function so `$`-sequences (e.g. $&, $1) in the value
        // are inserted literally rather than interpreted by String.replace().
        text = text.replace('{' + index + '}', () => value);
    });
    return text;
}

class VaultSecretElement {
    constructor() {
        // No in-memory secret cache: every reveal MUST hit the AJAX endpoint
        // so the server writes an audit row. Copy reads the value from the
        // visible input field (DOM is the source of truth while revealed).
        this.originalButtonContents = new WeakMap();
        this.init();
    }

    init() {
        // Toggle visibility / reveal buttons
        document.querySelectorAll('.t3js-vault-toggle-visibility').forEach(button => {
            button.addEventListener('click', this.handleToggleVisibility.bind(this));
        });

        // Copy buttons
        document.querySelectorAll('.t3js-vault-copy').forEach(button => {
            button.addEventListener('click', this.handleCopy.bind(this));
        });

        // Clear buttons
        document.querySelectorAll('.t3js-vault-clear').forEach(button => {
            button.addEventListener('click', this.handleClear.bind(this));
        });
    }

    /**
     * Get the vault identifier from the input field in the same input-group.
     */
    getIdentifier(button) {
        const inputGroup = button.closest('.input-group');
        const input = inputGroup?.querySelector('input[data-vault-identifier]');
        return input?.dataset.vaultIdentifier || '';
    }

    /**
     * Toggle visibility: first click reveals via AJAX, subsequent clicks toggle show/hide.
     */
    async handleToggleVisibility(event) {
        const button = event.currentTarget;
        const inputGroup = button.closest('.input-group');
        const input = inputGroup.querySelector('input[type="password"], input[type="text"]');
        if (!input) return;

        const identifier = this.getIdentifier(button);

        // If already revealed and showing, hide it
        if (input.dataset.vaultRevealed === '1' && input.type === 'text') {
            input.type = 'password';
            input.value = '';
            input.placeholder = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
            input.dataset.vaultRevealed = '0';
            this.updateIcon(button, 'icon-actions-eye-slash', 'icon-actions-eye');
            this.toggleCopyButton(inputGroup, false);
            return;
        }

        // No identifier means no stored secret — just toggle input type locally
        if (!identifier) {
            input.type = input.type === 'password' ? 'text' : 'password';
            this.updateIcon(button,
                input.type === 'text' ? 'icon-actions-eye' : 'icon-actions-eye-slash',
                input.type === 'text' ? 'icon-actions-eye-slash' : 'icon-actions-eye'
            );
            return;
        }

        // Fetch secret from vault via AJAX
        button.disabled = true;
        this.showSpinner(button);

        try {
            const response = await fetch(TYPO3.settings.ajaxUrls['vault_reveal'], {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier }),
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            if (data.success && data.secret !== undefined) {
                this.restoreButton(button);
                this.showSecret(input, button, inputGroup, data.secret);
            } else {
                throw new Error(data.error || 'Failed to reveal secret');
            }
        } catch (error) {
            console.error('Error revealing secret:', error);
            if (top.TYPO3?.Notification) {
                top.TYPO3.Notification.error(lang('nrvault.error', 'Error'), error.message || lang('nrvault.reveal.failed', 'Failed to reveal secret'));
            }
            this.restoreButton(button);
            button.disabled = false;
        }
    }

    /**
     * Replace button content with a spinner, saving the original nodes.
     */
    showSpinner(button) {
        const savedNodes = Array.from(button.childNodes).map(n => n.cloneNode(true));
        this.originalButtonContents.set(button, savedNodes);
        button.textContent = '';
        const spinner = document.createElement('span');
        spinner.className = 'spinner-border spinner-border-sm';
        spinner.setAttribute('role', 'status');
        button.appendChild(spinner);
    }

    /**
     * Restore button content from saved nodes.
     */
    restoreButton(button) {
        const saved = this.originalButtonContents.get(button);
        if (saved) {
            button.textContent = '';
            saved.forEach(node => button.appendChild(node));
            this.originalButtonContents.delete(button);
        }
    }

    /**
     * Show the revealed secret in the input field.
     */
    showSecret(input, button, inputGroup, secret) {
        input.value = secret;
        input.type = 'text';
        input.dataset.vaultRevealed = '1';
        this.updateIcon(button, 'icon-actions-eye', 'icon-actions-eye-slash');
        this.toggleCopyButton(inputGroup, true);
        button.disabled = false;
    }

    /**
     * Copy secret to clipboard.
     */
    async handleCopy(event) {
        const button = event.currentTarget;
        const inputGroup = button.closest('.input-group');
        const input = inputGroup?.querySelector('input[type="text"], input[type="password"]');

        // Source of truth = the visible DOM input. When revealed, its value
        // holds the plaintext; when hidden, the value is empty (cleared by
        // handleToggleVisibility) so copy refuses.
        const secret = (input && input.type === 'text' && input.dataset.vaultRevealed === '1')
            ? input.value
            : '';
        if (!secret) {
            if (top.TYPO3?.Notification) {
                top.TYPO3.Notification.warning(lang('nrvault.warning', 'Warning'), lang('nrvault.copy.revealFirst', 'Reveal the secret first before copying'));
            }
            return;
        }

        try {
            await navigator.clipboard.writeText(secret);
            if (top.TYPO3?.Notification) {
                top.TYPO3.Notification.success(lang('nrvault.success', 'Success'), lang('nrvault.copy.success', 'Secret copied to clipboard'));
            }

            // Visual feedback
            this.updateIcon(button, 'icon-actions-clipboard', 'icon-actions-check');
            setTimeout(() => {
                this.updateIcon(button, 'icon-actions-check', 'icon-actions-clipboard');
            }, 2000);
        } catch (error) {
            console.error('Failed to copy:', error);
            if (top.TYPO3?.Notification) {
                top.TYPO3.Notification.error(lang('nrvault.error', 'Error'), lang('nrvault.copy.failed', 'Failed to copy to clipboard'));
            }
        }
    }

    handleClear(event) {
        const button = event.currentTarget;
        const inputGroup = button.closest('.input-group');
        const input = inputGroup.querySelector('input');

        Modal.confirm(
            lang('nrvault.delete.title', 'Delete Secret'),
            lang('nrvault.clear.confirm', 'Are you sure you want to clear this secret? This action cannot be undone.'),
            Severity.warning,
            [
                {
                    text: lang('nrvault.cancel', 'Cancel'),
                    active: true,
                    btnClass: 'btn-default',
                    trigger: () => Modal.dismiss(),
                },
                {
                    text: lang('nrvault.delete', 'Delete'),
                    btnClass: 'btn-danger',
                    trigger: () => {
                        Modal.dismiss();
                        this.clearSecret(input, button);
                    },
                },
            ],
        );
    }

    /**
     * Clear the secret value and detach the field from its stored secret.
     */
    clearSecret(input, button) {
        input.value = '';
        input.placeholder = '';
        input.dataset.vaultRevealed = '0';

        // Mark as cleared by removing the checksum
        const checksumField = input.closest('.formengine-field-item')
            ?.parentElement?.querySelector('input[name$="[_vault_checksum]"]');
        if (checksumField) {
            checksumField.value = '';
        }

        button.remove();
    }

    /**
     * Swap icon classes on a button.
     */
    updateIcon(button, removeClass, addClass) {
        const icon = button.querySelector('.t3js-icon');
        if (icon) {
            icon.classList.remove(removeClass);
            icon.classList.add(addClass);
        }
    }

    /**
     * Show or hide the copy button in an input group.
     */
    toggleCopyButton(inputGroup, show) {
        const copyButton = inputGroup.querySelector('.t3js-vault-copy');
        if (copyButton) {
            copyButton.style.display = show ? '' : 'none';
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new VaultSecretElement());
} else {
    new VaultSecretElement();
}

export default VaultSecretElement;
