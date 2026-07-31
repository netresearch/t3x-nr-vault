/**
 * JavaScript module for VaultSecretInputElement.
 *
 * Handles:
 * - Toggle visibility for password fields
 * - Reveal existing secrets via AJAX
 * - Copy to clipboard functionality
 */
import {
    ensureCountdownElement,
    removeCountdownElement,
    startRevealLifecycle,
} from '@netresearch/nr-vault/vault-reveal-lifecycle.js';

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
    let text = (typeof TYPO3 !== 'undefined' && TYPO3.lang?.[key]) || fallback;
    args.forEach((value, index) => {
        // Use a replacer function so `$`-sequences (e.g. $&, $1) in the value
        // are inserted literally rather than interpreted by String.replace().
        text = text.replace('{' + index + '}', () => value);
    });
    return text;
}

class VaultSecretInput {
    constructor() {
        // No in-memory secret cache: every reveal MUST hit the AJAX endpoint
        // so the server writes an audit row. Copy reads the value from the
        // visible input field (DOM is the source of truth while revealed).
        //
        // Server-revealed plaintext is bounded by the shared lifecycle guard
        // (auto-hide + wipe on tab hide / page leave). JS strings cannot be
        // reliably zeroized — this shortens exposure, it does not clear memory.
        this.revealLifecycles = new WeakMap();
        this.init();
    }

    init() {
        // Toggle visibility buttons
        document.querySelectorAll('.t3js-vault-input-toggle').forEach(button => {
            button.addEventListener('click', this.handleToggleVisibility.bind(this));
        });

        // Reveal buttons for existing secrets
        document.querySelectorAll('.t3js-vault-input-reveal').forEach(button => {
            button.addEventListener('click', this.handleReveal.bind(this));
        });

        // Copy buttons
        document.querySelectorAll('.t3js-vault-input-copy').forEach(button => {
            button.addEventListener('click', this.handleCopy.bind(this));
        });
    }

    /**
     * Toggle password/text visibility for input fields.
     */
    handleToggleVisibility(event) {
        const button = event.currentTarget;
        const inputGroup = button.closest('.input-group');
        const input = inputGroup.querySelector('input[type="password"], input[type="text"]');

        if (!input) return;

        if (input.type === 'password') {
            input.type = 'text';
            const icon = button.querySelector('.t3js-icon');
            if (icon) {
                icon.classList.remove('icon-actions-eye');
                icon.classList.add('icon-actions-eye-slash');
            }
        } else {
            input.type = 'password';
            const icon = button.querySelector('.t3js-icon');
            if (icon) {
                icon.classList.remove('icon-actions-eye-slash');
                icon.classList.add('icon-actions-eye');
            }
        }
    }

    /**
     * Reveal an existing secret via AJAX.
     */
    async handleReveal(event) {
        const button = event.currentTarget;
        const identifier = button.dataset.identifier;

        if (!identifier) {
            console.error('No identifier found for reveal');
            return;
        }

        // Show loading state
        button.disabled = true;
        const originalChildren = Array.from(button.childNodes);
        const spinner = document.createElement('span');
        spinner.className = 'spinner-border spinner-border-sm';
        spinner.setAttribute('role', 'status');
        button.replaceChildren(spinner);

        try {
            const response = await fetch(TYPO3.settings.ajaxUrls['vault_reveal'], {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ identifier }),
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            if (data.success && data.secret !== undefined) {
                // Restore icon before showing revealed secret
                button.replaceChildren(...originalChildren);
                // Absent field = permissive (older backend); only an explicit
                // `false` (hardened profile) suppresses copy-to-clipboard.
                this.showRevealedSecret(button, data.secret, data.copyAllowed !== false);
            } else {
                throw new Error(data.error || 'Failed to reveal secret');
            }
        } catch (error) {
            console.error('Error revealing secret:', error);
            if (top.TYPO3?.Notification) {
                top.TYPO3.Notification.error(lang('nrvault.error', 'Error'), error.message || lang('nrvault.reveal.failed', 'Failed to reveal secret'));
            }
            button.replaceChildren(...originalChildren);
            button.disabled = false;
        }
    }

    /**
     * Show the revealed secret value.
     *
     * @param {boolean} copyAllowed `false` in the hardened security profile — the
     *                              clipboard survives the wipe, so no copy button.
     */
    showRevealedSecret(button, secret, copyAllowed) {
        const inputGroup = button.closest('.input-group');
        const displayInput = inputGroup.querySelector('input[data-vault-display]');

        if (displayInput) {
            displayInput.value = secret;
            displayInput.type = 'text';

            // Bound the exposure: auto-hide after the countdown, and wipe at once
            // when the tab is hidden or the page is left.
            const countdown = ensureCountdownElement(inputGroup);
            this.revealLifecycles.set(button, startRevealLifecycle({
                onWipe: () => {
                    this.revealLifecycles.delete(button);
                    this.restoreMasked(button);
                },
                onTick: (secondsLeft) => {
                    countdown.textContent = lang(
                        'nrvault.reveal.autohide.hide',
                        'The value hides automatically in {0} seconds.',
                        String(secondsLeft),
                    );
                },
            }));
        }

        // Update button to hide icon
        const icon = button.querySelector('.t3js-icon');
        if (icon) {
            icon.classList.remove('icon-actions-eye');
            icon.classList.add('icon-actions-eye-slash');
        }

        // Switch to hide mode
        button.classList.remove('t3js-vault-input-reveal');
        button.classList.add('t3js-vault-input-hide');
        button.removeEventListener('click', this.handleReveal);
        button.addEventListener('click', this.handleHide.bind(this));
        button.disabled = false;

        // Show copy button — never in the hardened profile.
        const copyButton = inputGroup.querySelector('.t3js-vault-input-copy');
        if (copyButton) {
            copyButton.style.display = copyAllowed ? '' : 'none';
        }
    }

    /**
     * Hide a revealed secret on user request, going through the lifecycle guard so
     * its timer and global listeners are torn down as well.
     */
    handleHide(event) {
        const button = event.currentTarget;
        const cancel = this.revealLifecycles.get(button);
        if (cancel) {
            this.revealLifecycles.delete(button);
            cancel();
            return;
        }

        this.restoreMasked(button);
    }

    /**
     * Wipe the plaintext out of the display field and restore the masked state.
     * Idempotent — also used as the lifecycle guard's wipe callback.
     */
    restoreMasked(button) {
        const inputGroup = button.closest('.input-group');
        const displayInput = inputGroup.querySelector('input[data-vault-display]');

        if (displayInput) {
            displayInput.value = '••••••••••••';
            displayInput.type = 'password';
        }

        // Update button back to reveal icon
        const icon = button.querySelector('.t3js-icon');
        if (icon) {
            icon.classList.remove('icon-actions-eye-slash');
            icon.classList.add('icon-actions-eye');
        }

        // Switch back to reveal mode
        button.classList.remove('t3js-vault-input-hide');
        button.classList.add('t3js-vault-input-reveal');
        button.removeEventListener('click', this.handleHide);
        button.addEventListener('click', this.handleReveal.bind(this));

        // Hide copy button
        const copyButton = inputGroup.querySelector('.t3js-vault-input-copy');
        if (copyButton) {
            copyButton.style.display = 'none';
        }

        removeCountdownElement(inputGroup);
    }

    /**
     * Copy secret to clipboard.
     */
    async handleCopy(event) {
        const button = event.currentTarget;
        const inputGroup = button.closest('.input-group');
        const displayInput = inputGroup?.querySelector('input[data-vault-display]');

        // Source of truth = the visible DOM input. When revealed, its value
        // holds the plaintext; when hidden (input.type === 'password'), it
        // holds the placeholder dots.
        const secret = (displayInput?.type === 'text')
            ? displayInput.value
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
            const icon = button.querySelector('.t3js-icon');
            if (icon) {
                icon.classList.remove('icon-actions-clipboard');
                icon.classList.add('icon-actions-check');
                setTimeout(() => {
                    icon.classList.remove('icon-actions-check');
                    icon.classList.add('icon-actions-clipboard');
                }, 2000);
            }
        } catch (error) {
            console.error('Failed to copy:', error);
            if (top.TYPO3?.Notification) {
                top.TYPO3.Notification.error(lang('nrvault.error', 'Error'), lang('nrvault.copy.failed', 'Failed to copy to clipboard'));
            }
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new VaultSecretInput());
} else {
    new VaultSecretInput(); // NOSONAR: side-effect entry module — instantiation wires up page event handlers on load
}

export default VaultSecretInput;
