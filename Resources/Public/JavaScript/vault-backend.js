/**
 * JavaScript module for vault backend module.
 */
import Notification from '@typo3/backend/notification.js';
import AjaxRequest from '@typo3/core/ajax/ajax-request.js';

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

class VaultBackend {
    constructor() {
        this.init();
    }

    init() {
        // Verify hash chain button
        document.querySelectorAll('.t3js-vault-verify-chain').forEach(button => {
            button.addEventListener('click', this.handleVerifyChain.bind(this));
        });
    }

    async handleVerifyChain(event) {
        const button = event.currentTarget;
        const originalChildren = Array.from(button.childNodes);

        button.disabled = true;
        const spinner = document.createElement('span');
        spinner.className = 'spinner-border spinner-border-sm';
        button.replaceChildren(spinner, document.createTextNode(' ' + lang('nrvault.verify.running', 'Verifying...')));

        try {
            const response = await new AjaxRequest(TYPO3.settings.ajaxUrls['system_vault'])
                .withQueryArguments({ action: 'verifyChain' })
                .get();

            const result = await response.resolve();

            if (result.valid) {
                Notification.success(lang('nrvault.verify.valid.title', 'Hash Chain Valid'), result.message, 5);
            } else {
                Notification.error(lang('nrvault.verify.invalid.title', 'Hash Chain Invalid'), result.message, 10);

                // Show details
                if (result.errors && Object.keys(result.errors).length > 0) {
                    const errorList = Object.entries(result.errors)
                        .map(([uid, error]) => lang('nrvault.verify.entry', 'Entry {0}: {1}', uid, error))
                        .join('\n');
                    Notification.warning(lang('nrvault.verify.errors.title', 'Verification Errors'), errorList, 15);
                }
            }
        } catch (error) {
            Notification.error(lang('nrvault.verify.failed.title', 'Verification Failed'), error.message || lang('nrvault.unknownError', 'An error occurred'), 10);
        } finally {
            button.disabled = false;
            button.replaceChildren(...originalChildren);
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new VaultBackend());
} else {
    new VaultBackend();
}

export default VaultBackend;
