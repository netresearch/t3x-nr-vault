/**
 * Secret reveal and delete functionality for vault view page.
 *
 * Uses TYPO3 v14 native modules: Modal and Notification APIs.
 */
import Modal from '@typo3/backend/modal.js';
import Notification from '@typo3/backend/notification.js';
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

class SecretView {
    constructor() {
        this.revealBtn = document.getElementById('reveal-secret-btn');
        this.copyBtn = document.getElementById('copy-secret-btn');
        this.secretInput = document.getElementById('secret-value-display');
        this.btnText = document.getElementById('reveal-btn-text');
        this.btnIcon = document.getElementById('reveal-btn-icon');
        this.btnSpinner = document.getElementById('reveal-btn-spinner');
        this.isRevealed = false;
        this.secretValue = null;

        this.init();
    }

    init() {
        if (this.revealBtn && this.secretInput) {
            this.revealBtn.addEventListener('click', () => this.handleReveal());
        }

        if (this.copyBtn) {
            this.copyBtn.addEventListener('click', () => this.handleCopy());
        }

        // Delete confirmation with TYPO3 Modal
        document.querySelectorAll('[data-vault-delete]').forEach(button => {
            button.addEventListener('click', (event) => this.handleDelete(event));
        });
    }

    handleReveal() {
        if (this.isRevealed) {
            this.hideSecret();
        } else if (this.secretValue !== null) {
            this.showSecret();
        } else {
            this.fetchAndReveal();
        }
    }

    hideSecret() {
        this.secretInput.type = 'password';
        this.secretInput.value = '••••••••••••••••';
        this.btnText.textContent = lang('nrvault.reveal.action', 'Reveal');
        if (this.copyBtn) {
            this.copyBtn.classList.add('d-none');
        }
        this.isRevealed = false;
    }

    showSecret() {
        this.secretInput.type = 'text';
        this.secretInput.value = this.secretValue;
        this.btnText.textContent = lang('nrvault.reveal.hideAction', 'Hide');
        if (this.copyBtn) {
            this.copyBtn.classList.remove('d-none');
        }
        this.isRevealed = true;
    }

    async fetchAndReveal() {
        const url = this.revealBtn.dataset.revealUrl;
        this.revealBtn.disabled = true;
        this.showLoading(true);

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ identifier: this.revealBtn.dataset.identifier }),
            });
            const data = await response.json();

            if (data.success) {
                this.secretValue = data.secret;
                this.showSecret();
            } else {
                Notification.error(lang('nrvault.error', 'Error'), data.error || lang('nrvault.unknownError', 'An error occurred'), 5);
                this.btnText.textContent = lang('nrvault.reveal.action', 'Reveal');
            }
        } catch (error) {
            Notification.error(lang('nrvault.error', 'Error'), lang('nrvault.reveal.fetchError', 'Error fetching secret: {0}', error.message), 5);
            this.btnText.textContent = lang('nrvault.reveal.action', 'Reveal');
        } finally {
            this.revealBtn.disabled = false;
            this.showLoading(false);
        }
    }

    showLoading(loading) {
        if (this.btnIcon && this.btnSpinner) {
            if (loading) {
                this.btnIcon.classList.add('d-none');
                this.btnSpinner.classList.remove('d-none');
                this.btnText.textContent = lang('nrvault.reveal.loadingAction', 'Loading...');
            } else {
                this.btnIcon.classList.remove('d-none');
                this.btnSpinner.classList.add('d-none');
            }
        }
    }

    async handleCopy() {
        if (!this.secretValue) return;

        try {
            await navigator.clipboard.writeText(this.secretValue);
            const originalChildNodes = Array.from(this.copyBtn.childNodes).map(n => n.cloneNode(true));
            this.copyBtn.textContent = '';
            const copiedSpan = document.createElement('span');
            copiedSpan.className = 'text-success';
            copiedSpan.textContent = lang('nrvault.copied.inline', 'Copied!');
            this.copyBtn.appendChild(copiedSpan);
            setTimeout(() => {
                this.copyBtn.textContent = '';
                originalChildNodes.forEach(node => this.copyBtn.appendChild(node));
            }, 2000);
            Notification.success(lang('nrvault.copied', 'Copied'), lang('nrvault.copy.success', 'Secret copied to clipboard'), 2);
        } catch {
            Notification.error(lang('nrvault.error', 'Error'), lang('nrvault.copy.failed', 'Failed to copy to clipboard'), 5);
        }
    }

    /**
     * Escape text for safe display in UI strings.
     */
    escapeText(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    handleDelete(event) {
        event.preventDefault();
        const button = event.currentTarget;
        const form = button.closest('form');
        const identifier = button.dataset.identifier;

        Modal.confirm(
            lang('nrvault.delete.title', 'Delete Secret'),
            lang(
                'nrvault.delete.confirm',
                'Are you sure you want to delete the secret "{0}"? This action cannot be undone.',
                this.escapeText(identifier),
            ),
            Severity.warning,
            [
                {
                    text: lang('nrvault.cancel', 'Cancel'),
                    active: true,
                    btnClass: 'btn-default',
                    trigger: () => Modal.dismiss()
                },
                {
                    text: lang('nrvault.delete', 'Delete'),
                    btnClass: 'btn-danger',
                    trigger: () => {
                        Modal.dismiss();
                        form.submit();
                    }
                }
            ]
        );
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new SecretView());
} else {
    new SecretView();
}

export default SecretView;
