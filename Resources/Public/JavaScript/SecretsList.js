/**
 * Secrets list AJAX functionality for live toggle, reveal, rotate, and delete actions.
 *
 * Uses TYPO3 v14 native modules and patterns.
 */
import Modal from '@typo3/backend/modal.js';
import Notification from '@typo3/backend/notification.js';
import Severity from '@typo3/backend/severity.js';

/**
 * Look up a backend label registered via PageRenderer::addInlineLanguageLabelFile()
 * (locallang_js.xlf). Falls back to the English default so the UI never shows a
 * raw key if the label file was not registered on the current page.
 *
 * @param {string} key      label key, e.g. 'nrvault.delete.title'
 * @param {string} fallback English default
 * @param {...string} args  values substituted for {0}, {1}, ... placeholders
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

class SecretsList {
    constructor() {
        // No in-memory secret cache: every reveal MUST hit the AJAX endpoint
        // so VaultService::retrieve() fires and an audit-log row is written.
        // Caching the plaintext across reveal-modal opens would silently bypass
        // the audit log on every reveal-after-first (violation of the
        // "Audit every access" rule — see root AGENTS.md, Security
        // Requirements item 5).
        this.init();
    }

    init() {
        document.querySelectorAll('[data-vault-toggle]').forEach(button => {
            button.addEventListener('click', this.handleToggle.bind(this));
        });

        // Delete confirmation with TYPO3 Modal
        document.querySelectorAll('.btn-danger[type="submit"]').forEach(button => {
            const form = button.closest('form');
            if (form && form.action.includes('delete')) {
                button.addEventListener('click', this.handleDelete.bind(this));
            }
        });

        // Reveal modal triggers
        document.querySelectorAll('[data-vault-reveal]').forEach(button => {
            button.addEventListener('click', this.handleReveal.bind(this));
        });

        // Rotate modal triggers
        document.querySelectorAll('[data-vault-rotate]').forEach(button => {
            button.addEventListener('click', this.handleRotate.bind(this));
        });
    }

    handleDelete(event) {
        event.preventDefault();
        const button = event.currentTarget;
        const form = button.closest('form');
        const row = button.closest('tr');
        const identifier = row?.dataset.identifier || form.querySelector('input[name="identifier"]')?.value || 'secret';

        Modal.confirm(
            lang('nrvault.delete.title', 'Delete Secret'),
            lang(
                'nrvault.delete.confirm',
                'Are you sure you want to delete the secret "{0}"? This action cannot be undone.',
                this.escapeHtml(identifier),
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

    async handleToggle(event) {
        event.preventDefault();
        const button = event.currentTarget;
        const form = button.closest('form');
        const identifier = form.querySelector('input[name="identifier"]').value;
        const row = button.closest('tr');
        const url = form.action;

        // Disable button and show loading state
        button.disabled = true;
        const originalChildren = Array.from(button.childNodes);
        const spinner = document.createElement('span');
        spinner.className = 'spinner-border spinner-border-sm';
        spinner.setAttribute('role', 'status');
        spinner.setAttribute('aria-hidden', 'true');
        button.replaceChildren(spinner);

        try {
            const formData = new FormData(form);
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: formData
            });

            const result = await response.json();

            if (result.success) {
                // Restore original children BEFORE updateButtonState so it can
                // find the .icon <span> and flip the SVG <use href="..."> href.
                button.replaceChildren(...originalChildren);
                this.updateRowState(row, result.hidden);
                this.updateButtonState(button, result.hidden);
                Notification.success(lang('nrvault.success', 'Success'), result.message, 3);
            } else {
                Notification.error(lang('nrvault.error', 'Error'), result.error || lang('nrvault.unknownError', 'An error occurred'), 5);
            }
        } catch (error) {
            Notification.error(lang('nrvault.error', 'Error'), error.message || lang('nrvault.unknownError', 'An error occurred'), 5);
        } finally {
            button.disabled = false;
            // Restore original children on any non-success path (error/thrown).
            if (!button.querySelector('.icon')) {
                button.replaceChildren(...originalChildren);
            }
        }
    }

    updateRowState(row, hidden) {
        if (hidden) {
            row.classList.add('table-secondary');
        } else {
            row.classList.remove('table-secondary');
        }

        // Update status badge
        const statusCell = row.querySelector('td:nth-child(3)');
        if (statusCell) {
            const badge = statusCell.querySelector('.badge');
            if (badge) {
                if (hidden) {
                    badge.className = 'badge text-bg-secondary';
                    badge.textContent = 'Disabled';
                } else {
                    badge.className = 'badge text-bg-success';
                    badge.textContent = 'Active';
                }
            }

            // Update aria-label
            statusCell.setAttribute('aria-label', 'Status: ' + (hidden ? 'Disabled' : 'Active'));
        }
    }

    updateButtonState(button, hidden) {
        // Update button title and icon
        const iconContainer = button.querySelector('.icon');
        if (iconContainer) {
            // TYPO3 icons are SVG use elements
            const useElement = iconContainer.querySelector('use');
            if (useElement) {
                const currentHref = useElement.getAttribute('href') || useElement.getAttribute('xlink:href');
                if (currentHref) {
                    const newIcon = hidden ? 'actions-toggle-off' : 'actions-toggle-on';
                    const newHref = currentHref.replace(/actions-toggle-(on|off)/, newIcon);
                    useElement.setAttribute('href', newHref);
                    if (useElement.hasAttribute('xlink:href')) {
                        useElement.setAttribute('xlink:href', newHref);
                    }
                }
            }
        }

        // Update title and aria-label
        const identifier = button.closest('tr')?.dataset.identifier || 'secret';
        const newTitle = hidden ? 'Enable secret' : 'Disable secret';
        const newAriaLabel = (hidden ? 'Enable' : 'Disable') + ' secret ' + identifier;
        button.setAttribute('title', newTitle);
        button.setAttribute('aria-label', newAriaLabel);
    }

    /**
     * Handle reveal button click - show modal with secret value.
     */
    async handleReveal(event) {
        const button = event.currentTarget;
        const identifier = button.dataset.vaultReveal;

        if (!identifier) {
            Notification.error(lang('nrvault.error', 'Error'), lang('nrvault.noIdentifier', 'No identifier found'), 5);
            return;
        }

        // Show loading modal
        const loadingBody = lang('nrvault.reveal.loading.body', 'Fetching secret...');
        const loadingModal = Modal.advanced({
            title: lang('nrvault.reveal.loading.title', 'Loading Secret'),
            content: '<div class="text-center p-4"><span class="spinner-border" role="status"></span><p class="mt-2">' + this.escapeHtml(loadingBody) + '</p></div>',
            severity: Severity.info,
            size: Modal.sizes.small,
            buttons: []
        });

        try {
            const response = await fetch(TYPO3.settings.ajaxUrls['vault_reveal'], {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ identifier }),
            });

            const data = await response.json();
            loadingModal.hideModal();

            if (data.success && data.secret !== undefined) {
                this.showRevealModal(identifier, data.secret);
            } else {
                Notification.error(lang('nrvault.error', 'Error'), data.error || lang('nrvault.reveal.failed', 'Failed to reveal secret'), 5);
            }
        } catch (error) {
            loadingModal.hideModal();
            Notification.error(lang('nrvault.error', 'Error'), error.message || lang('nrvault.reveal.failed', 'Failed to reveal secret'), 5);
        }
    }

    /**
     * Show the reveal modal with secret value.
     */
    showRevealModal(identifier, secret) {
        const content = this.buildRevealModalContent(identifier, secret);

        const modal = Modal.advanced({
            title: lang('nrvault.reveal.title', 'Secret Value'),
            content: content,
            severity: Severity.info,
            size: Modal.sizes.default,
            buttons: [
                {
                    text: lang('nrvault.close', 'Close'),
                    active: true,
                    btnClass: 'btn-default',
                    trigger: () => modal.hideModal()
                }
            ]
        });

        // Add event listeners after modal is shown
        setTimeout(() => {
            const toggleBtn = document.getElementById('reveal-modal-toggle');
            const copyBtn = document.getElementById('reveal-modal-copy');
            const input = document.getElementById('reveal-modal-secret');

            if (toggleBtn && input) {
                toggleBtn.addEventListener('click', () => {
                    if (input.type === 'password') {
                        input.type = 'text';
                    } else {
                        input.type = 'password';
                    }
                });
            }

            if (copyBtn && input) {
                copyBtn.addEventListener('click', async () => {
                    try {
                        await navigator.clipboard.writeText(secret);
                        Notification.success(lang('nrvault.copied', 'Copied'), lang('nrvault.copy.success', 'Secret copied to clipboard'), 2);
                    } catch (e) {
                        Notification.error(lang('nrvault.error', 'Error'), lang('nrvault.copy.failed', 'Failed to copy to clipboard'), 5);
                    }
                });
            }
        }, 100);
    }

    /**
     * Handle rotate button click - show modal with input for new secret.
     */
    handleRotate(event) {
        const button = event.currentTarget;
        const identifier = button.dataset.vaultRotate;

        if (!identifier) {
            Notification.error(lang('nrvault.error', 'Error'), lang('nrvault.noIdentifier', 'No identifier found'), 5);
            return;
        }

        const content = this.buildRotateModalContent();

        const modal = Modal.advanced({
            title: lang('nrvault.rotate.title', 'Rotate Secret: {0}', identifier),
            content: content,
            severity: Severity.warning,
            size: Modal.sizes.default,
            buttons: [
                {
                    text: lang('nrvault.cancel', 'Cancel'),
                    active: true,
                    btnClass: 'btn-default',
                    trigger: () => modal.hideModal()
                },
                {
                    text: lang('nrvault.rotate.button', 'Rotate Secret'),
                    btnClass: 'btn-warning',
                    trigger: () => this.performRotate(modal, identifier)
                }
            ]
        });

        // Add toggle visibility event listener
        setTimeout(() => {
            const toggleBtn = document.getElementById('rotate-modal-toggle');
            const input = document.getElementById('rotate-modal-secret');

            if (toggleBtn && input) {
                toggleBtn.addEventListener('click', () => {
                    if (input.type === 'password') {
                        input.type = 'text';
                    } else {
                        input.type = 'password';
                    }
                });

                // Focus the input
                input.focus();
            }
        }, 100);
    }

    /**
     * Perform the actual rotation via AJAX.
     */
    async performRotate(modal, identifier) {
        const input = document.getElementById('rotate-modal-secret');
        const newSecret = input?.value || '';

        if (!newSecret) {
            Notification.error(lang('nrvault.error', 'Error'), lang('nrvault.rotate.enterValue', 'Please enter a new secret value'), 5);
            return;
        }

        try {
            const response = await fetch(TYPO3.settings.ajaxUrls['vault_rotate'], {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ identifier, secret: newSecret }),
            });

            const data = await response.json();

            if (data.success) {
                modal.hideModal();
                Notification.success(lang('nrvault.success', 'Success'), data.message || lang('nrvault.rotate.success', 'Secret rotated successfully'), 3);
            } else {
                Notification.error(lang('nrvault.error', 'Error'), data.error || lang('nrvault.rotate.failed', 'Failed to rotate secret'), 5);
            }
        } catch (error) {
            Notification.error(lang('nrvault.error', 'Error'), error.message || lang('nrvault.rotate.failed', 'Failed to rotate secret'), 5);
        }
    }

    /**
     * Escape HTML to prevent XSS.
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Build reveal-modal DOM safely (no innerHTML interpolation).
     */
    buildRevealModalContent(identifier, secret) {
        const root = document.createElement('div');

        const group = document.createElement('div');
        group.className = 'form-group mb-3';
        const label = document.createElement('label');
        label.className = 'form-label fw-bold';
        label.setAttribute('for', 'reveal-modal-secret');
        label.textContent = lang('nrvault.reveal.label', 'Secret Value');
        const inputGroup = document.createElement('div');
        inputGroup.className = 'input-group';

        const input = document.createElement('input');
        input.type = 'password';
        input.className = 'form-control font-monospace';
        input.id = 'reveal-modal-secret';
        input.readOnly = true;
        input.value = secret;
        inputGroup.append(input);

        inputGroup.append(
            this.buildIconButton('reveal-modal-toggle', lang('nrvault.toggle.visibility', 'Toggle visibility'), 'icon-actions-eye'),
            this.buildIconButton('reveal-modal-copy', lang('nrvault.copy.clipboard', 'Copy to clipboard'), 'icon-actions-clipboard'),
        );

        group.append(label, inputGroup);

        const hint = document.createElement('p');
        hint.className = 'text-muted small mb-0';
        hint.append(document.createTextNode(lang('nrvault.reveal.hint', 'Secret value for: ')));
        const code = document.createElement('code');
        code.textContent = identifier;
        hint.append(code);

        root.append(group, hint);
        return root;
    }

    /**
     * Build rotate-modal DOM safely (no innerHTML interpolation).
     */
    buildRotateModalContent() {
        const root = document.createElement('div');

        const group = document.createElement('div');
        group.className = 'form-group mb-3';
        const label = document.createElement('label');
        label.className = 'form-label fw-bold';
        label.setAttribute('for', 'rotate-modal-secret');
        label.textContent = lang('nrvault.rotate.label', 'New Secret Value');

        const inputGroup = document.createElement('div');
        inputGroup.className = 'input-group';
        const input = document.createElement('input');
        input.type = 'password';
        input.className = 'form-control';
        input.id = 'rotate-modal-secret';
        input.placeholder = lang('nrvault.rotate.placeholder', 'Enter new secret value');
        input.autocomplete = 'new-password';
        inputGroup.append(input);
        inputGroup.append(this.buildIconButton('rotate-modal-toggle', lang('nrvault.toggle.visibility', 'Toggle visibility'), 'icon-actions-eye'));

        const help = document.createElement('div');
        help.className = 'form-text';
        help.textContent = lang('nrvault.rotate.help', 'Enter the new secret value. This will replace the existing secret.');

        group.append(label, inputGroup, help);

        const warning = document.createElement('p');
        warning.className = 'text-warning small mb-0';
        const strong = document.createElement('strong');
        strong.textContent = lang('nrvault.rotate.warning.label', 'Warning:');
        warning.append(strong, document.createTextNode(lang('nrvault.rotate.warning.body', ' Rotating a secret is irreversible. The previous value cannot be recovered.')));

        root.append(group, warning);
        return root;
    }

    /**
     * Build an input-group icon button (e.g. toggle/copy).
     */
    buildIconButton(id, title, iconClass) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-default';
        btn.id = id;
        btn.title = title;
        // aria-label: screen readers don't consistently expose `title` as the
        // accessible name for icon-only buttons.
        btn.setAttribute('aria-label', title);
        const icon = document.createElement('span');
        icon.className = `icon icon-size-small icon-state-default ${iconClass}`;
        icon.setAttribute('aria-hidden', 'true');
        btn.append(icon);
        return btn;
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new SecretsList());
} else {
    new SecretsList();
}

export default SecretsList;
