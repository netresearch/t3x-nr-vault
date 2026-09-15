/**
 * Focus restoration for dialogs opened from a backend module.
 *
 * TYPO3 renders every modal into the TOP document, while a backend module (and
 * FormEngine) runs inside the module iframe. The browser's own restoration
 * therefore cannot reach the control that opened the dialog: closing it returns
 * focus within the top document, where that control does not exist, so focus
 * ends up on `<body>` and a keyboard user loses their place in the list.
 *
 * Measured on TYPO3 14.3.7 (headless Chromium, `document.activeElement` read in
 * the top document and in the module iframe): the reveal, rotate and delete
 * dialogs all left focus on `<body>` after Escape — a WCAG 2.4.3 failure that
 * is independent of the dialog's own focus trap, which the native `<dialog>`
 * provides correctly.
 *
 * This is the missing half of "move focus into the dialog, then give it back".
 * It is not a focus trap: the trap belongs to the core modal and must not be
 * duplicated here.
 */

/**
 * Give focus back to `trigger` once `modal` has gone away.
 *
 * Works on TYPO3 13 (Bootstrap modal, `hidden.bs.modal`) and 14 (native
 * `<dialog>`), which both emit `typo3-modal-hidden` when the dialog is gone.
 *
 * @param {HTMLElement|null|undefined} modal   Element returned by `Modal.advanced()` / `Modal.confirm()`.
 * @param {HTMLElement|null|undefined} trigger Control that opened the dialog.
 */
export function restoreFocusOnClose(modal, trigger) {
    if (typeof modal?.addEventListener !== 'function' || !trigger) {
        return;
    }

    modal.addEventListener(
        'typo3-modal-hidden',
        () => {
            // The row may be gone by now (delete confirmed, list re-rendered);
            // focusing a detached element would silently drop focus on <body>,
            // which is exactly what this guards against.
            if (trigger.isConnected) {
                trigger.focus();
            }
        },
        { once: true },
    );
}
