/**
 * Secret form enhancements with TYPO3 native patterns.
 *
 * Uses TYPO3 v14 native ElementBrowser for page selection via postMessage API.
 * Adds filtering to user/group selects for better UX.
 */
import Modal from '@typo3/backend/modal.js';
import Severity from '@typo3/backend/severity.js';

class SecretForm {
    pidInput = null;

    constructor() {
        this.init();
    }

    init() {
        this.initSelectFilter('secret-owner', 'owner-filter');
        this.initSelectFilter('secret-groups', 'groups-filter');
        this.initPageBrowser();
        this.initMessageListener();
    }

    /**
     * Add a filter input above a select element.
     */
    initSelectFilter(selectId, filterId) {
        const selectEl = document.getElementById(selectId);
        if (!selectEl) return;

        // Create filter input
        const filter = document.createElement('input');
        filter.type = 'text';
        filter.id = filterId;
        filter.className = 'form-control form-control-sm mb-1';
        filter.placeholder = 'Type to filter...';
        filter.setAttribute('aria-label', 'Filter options');

        // Insert before select
        selectEl.parentNode.insertBefore(filter, selectEl);

        // Store original options
        const options = Array.from(selectEl.options);

        // Filter on input
        filter.addEventListener('input', () => {
            const term = filter.value.toLowerCase();
            options.forEach(opt => {
                const matches = opt.text.toLowerCase().includes(term);
                opt.style.display = matches ? '' : 'none';
            });
        });

        // Clear filter on Escape
        filter.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                filter.value = '';
                options.forEach(opt => opt.style.display = '');
            }
        });
    }

    /**
     * Initialize page browser button for PID field.
     */
    initPageBrowser() {
        this.pidInput = document.getElementById('secret-pid');
        const browseBtn = document.getElementById('browse-page-btn');

        if (!this.pidInput || !browseBtn) return;

        browseBtn.addEventListener('click', (e) => {
            e.preventDefault();
            this.openPageBrowser();
        });
    }

    /**
     * Listen for messages from ElementBrowser iframe.
     */
    initMessageListener() {
        window.addEventListener('message', (event) => {
            // Security: only accept messages from same origin
            if (event.origin !== window.location.origin) return;

            const data = event.data;
            if (!data || typeof data !== 'object') return;

            // Handle TYPO3 ElementBrowser message
            if (data.actionName === 'typo3:elementBrowser:elementAdded') {
                this.handleElementBrowserResult(data);
            }
        });
    }

    /**
     * Handle result from ElementBrowser.
     */
    handleElementBrowserResult(data) {
        // Check if this is for our pid field
        if (data.fieldName === 'vault_pid_field' && this.pidInput) {
            // value format is "pages_123" - extract the UID
            const match = data.value.match(/pages_(\d+)/);
            if (match) {
                const uid = match[1];
                this.pidInput.value = uid;

                // Update preview
                const preview = document.getElementById('secret-pid-preview');
                if (preview) {
                    preview.textContent = data.label ? `${data.label} [${uid}]` : `Page ${uid}`;
                    preview.classList.remove('d-none');
                }
            }
            Modal.dismiss();
        }
    }

    /**
     * Open TYPO3 page browser in modal.
     */
    openPageBrowser() {
        // Build URL for TYPO3's native ElementBrowser
        // Using the wizard_element_browser route
        const params = new URLSearchParams({
            mode: 'db',
            bparams: 'vault_pid_field|||pages|'
        });

        // TYPO3 v14 uses /typo3/wizard/record/browse
        const browserUrl = top?.TYPO3?.settings?.ajaxUrls?.wizard_element_browser
            || '/typo3/wizard/record/browse';

        Modal.advanced({
            type: Modal.types.iframe,
            title: 'Select Page',
            severity: Severity.info,
            size: Modal.sizes.large,
            content: `${browserUrl}?${params.toString()}`,
            additionalCssClasses: ['modal-element-browser']
        });
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new SecretForm());
} else {
    new SecretForm();
}

export default SecretForm;
