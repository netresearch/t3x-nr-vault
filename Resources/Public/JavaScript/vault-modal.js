/**
 * Modal helpers that behave the same on every supported TYPO3 major.
 *
 * TYPO3 13 renders a backend modal with Bootstrap, TYPO3 14 with a native
 * `<dialog>`. Bootstrap ignores `hide()` while the show transition is still
 * running, so a modal closed in the same breath as it was opened — a loading
 * dialog dismissed as soon as its AJAX call returns — stays in the DOM for
 * good, together with its `.modal-backdrop`. That backdrop covers the whole
 * backend and swallows every later click, including clicks on the module
 * iframe below it.
 *
 * Measured on the branch tip against both provisioned instances
 * (TYPO3 13.4.35 and 14.3.7, chromium): `Modal.advanced()` followed by
 * `hideModal()` after 0 ms and after 50 ms left one modal and one backdrop
 * behind on 13.4 and removed both on 14.3; after 1000 ms — past the fade —
 * 13.4 removed them too.
 *
 * `openModal()` therefore records when a dialog has finished showing, and
 * `dismissModal()` waits for that moment before hiding one that has not.
 */
import Modal from '@typo3/backend/modal.js';

/**
 * Longest wait before a dismissal is carried out regardless, in milliseconds.
 * Bootstrap's modal fade is 300 ms; this only applies to a core that never
 * dispatches `typo3-modal-shown`.
 */
const SHOW_TRANSITION_FALLBACK_MS = 500;

/**
 * Longest wait for the dialog to report itself gone, in milliseconds. Keeps a
 * caller that waits for the dismissal from stalling when no event arrives —
 * a modal already removed from the document dispatches none.
 */
const HIDE_FALLBACK_MS = 1000;

/**
 * Open a backend modal and remember when it has finished showing.
 *
 * @param {object} options Passed to `Modal.advanced()` unchanged.
 * @returns {HTMLElement} The modal element, as `Modal.advanced()` returns it.
 */
export function openModal(options) {
    const modal = Modal.advanced(options);

    modal?.addEventListener?.(
        'typo3-modal-shown',
        () => {
            if (modal.dataset) {
                modal.dataset.vaultModalShown = '1';
            }
        },
        { once: true },
    );

    return modal;
}

/**
 * Hide a modal, deferring to the end of its show transition when it is still
 * opening. Idempotent, and safe to call with a modal this module did not open.
 *
 * Resolves once the dialog has actually gone away, so a caller that wants to
 * put another dialog on screen can wait for the first one to leave. TYPO3 13
 * shows one modal at a time: opening a second while the first is still there
 * loses it, and the value dialog then never appears at all.
 *
 * @param {HTMLElement|null|undefined} modal
 * @returns {Promise<void>}
 */
export function dismissModal(modal) {
    if (!modal || typeof modal.hideModal !== 'function') {
        return Promise.resolve();
    }

    return new Promise((resolve) => {
        let settled = false;
        const done = () => {
            if (settled) {
                return;
            }
            settled = true;
            resolve();
        };

        const hide = () => {
            if (settled) {
                return;
            }
            // A dialog the backend has already taken out of the document is
            // gone; asking it to hide again puts it back on TYPO3 13, and a
            // revealed value would return to the page with it.
            if (!modal.isConnected) {
                done();
                return;
            }
            modal.hideModal();
        };

        if (typeof modal.addEventListener !== 'function') {
            hide();
            done();
            return;
        }

        modal.addEventListener('typo3-modal-hidden', done, { once: true });
        window.setTimeout(done, HIDE_FALLBACK_MS);

        if (modal.dataset?.vaultModalShown === '1' || !modal.isConnected) {
            hide();
            return;
        }

        modal.addEventListener('typo3-modal-shown', hide, { once: true });
        window.setTimeout(hide, SHOW_TRANSITION_FALLBACK_MS);
    });
}
