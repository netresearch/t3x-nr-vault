/**
 * Shared exposure-limiting lifecycle for server-revealed plaintext.
 *
 * Every surface that displays a secret fetched from `vault_reveal` (list modal,
 * FormEngine widgets) drives it through startRevealLifecycle(): the value is
 * wiped after AUTO_HIDE_SECONDS, and immediately when the tab is hidden or the
 * page goes away.
 *
 * Note: JavaScript strings cannot be reliably zeroized — the engine may retain
 * copies of the plaintext after `input.value = ''`. The goal here is minimizing
 * how long the secret is *reachable and on screen*, not guaranteed memory
 * clearing (that is the PHP side's job via `sodium_memzero()`).
 */

/**
 * Seconds a revealed secret stays visible before it is wiped automatically.
 * Bounds the exposure window when a reveal is left unattended.
 */
export const AUTO_HIDE_SECONDS = 30;

/**
 * Start the auto-hide + wipe-on-leave lifecycle for one revealed secret.
 *
 * A single interval timer drives both the countdown rendering and the auto-hide,
 * so there is exactly one timer per revealed value.
 *
 * @param {object} options
 * @param {() => void} options.onWipe Clears the plaintext and restores the hidden
 *                                    state. MUST be idempotent — it can run from
 *                                    the timer, a global listener or an explicit
 *                                    cancel.
 * @param {(secondsLeft: number) => void} [options.onTick] Renders the countdown.
 *                                    Called once immediately, then every second.
 * @returns {() => void} Wipes now and detaches every timer/listener. Idempotent.
 */
export function startRevealLifecycle({ onWipe, onTick }) {
    let remaining = AUTO_HIDE_SECONDS;
    let timerId = null;

    function onVisibilityChange() {
        if (document.hidden) {
            wipe();
        }
    }

    function onPagehide() {
        wipe();
    }

    function detach() {
        if (timerId !== null) {
            window.clearInterval(timerId);
            timerId = null;
        }
        document.removeEventListener('visibilitychange', onVisibilityChange);
        window.removeEventListener('pagehide', onPagehide);
    }

    function wipe() {
        detach();
        onWipe();
    }

    document.addEventListener('visibilitychange', onVisibilityChange);
    window.addEventListener('pagehide', onPagehide);

    onTick?.(remaining);
    timerId = window.setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
            wipe();
            return;
        }
        onTick?.(remaining);
    }, 1000);

    return wipe;
}

/**
 * Create (or reuse) the countdown line rendered below an input group.
 *
 * Deliberately not an aria-live region: announcing a new number every second
 * would drown out everything else for screen-reader users.
 *
 * @param {HTMLElement} inputGroup
 * @returns {HTMLElement}
 */
export function ensureCountdownElement(inputGroup) {
    const existing = inputGroup.parentElement?.querySelector('.t3js-vault-autohide');
    if (existing) {
        return existing;
    }

    const element = document.createElement('div');
    element.className = 'form-text text-muted t3js-vault-autohide';
    element.dataset.testid = 'vault-autohide-countdown';
    inputGroup.insertAdjacentElement('afterend', element);

    return element;
}

/**
 * Remove the countdown line belonging to an input group, if present.
 *
 * @param {HTMLElement} inputGroup
 */
export function removeCountdownElement(inputGroup) {
    inputGroup.parentElement?.querySelector('.t3js-vault-autohide')?.remove();
}
