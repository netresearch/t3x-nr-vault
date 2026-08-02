:navigation-title: Monitoring and alerting
.. include:: /Includes.rst.txt

.. _operations-monitoring-and-alerting:

=======================
Monitoring and alerting
=======================

The audit chain is evidence. Evidence nobody looks at is not a control. This
page wires the chain to something that pages a human.

Two things have to be running, and they are different: **anchoring** publishes
the chain tip so a table reset becomes detectable, and **verification** checks
the chain and compares it against the last anchor. Anchoring without
verification produces evidence nobody checks; verification without anchoring
cannot detect a reset at all.

.. _operations-monitoring-scheduler:

Scheduler tasks
===============

Both tasks are registered as native TCA task types and appear in
:guilabel:`Scheduler > Add task`. They are the scheduler counterparts of the
CLI commands and do exactly the same work.

..  list-table::
    :header-rows: 1
    :widths: 24 20 56

    *   -   Task
        -   Equivalent
        -   Fails when

    *   -   :php:`AuditAnchorTask`
        -   ``vault:audit-anchor``
        -   **No sink accepted the anchor.** An anchoring run that reached
            nothing outside the database provides no reset protection, and a
            green scheduler entry would misreport that as working tamper
            evidence.

    *   -   :php:`AuditVerifyTask`
        -   ``vault:audit-verify``
        -   Findings were raised — subject to the ``nr_vault_tamper_only``
            switch below.

Alternatively, run the commands from cron:

..  code-block:: bash
    :caption: Example crontab

    # Publish the chain tip hourly.
    17 * * * *  cd /var/www/site && vendor/bin/typo3 vault:audit-anchor --format=json
    # Verify chain + anchor every 15 minutes.
    */15 * * * * cd /var/www/site && vendor/bin/typo3 vault:audit-verify --format=json

..  note::

    **The anchoring interval is the security parameter.** Audit entries written
    since the last anchor are the window an attacker who truncates the table
    can still hide. Hourly is a reasonable starting point; daily is the loosest
    defensible setting for a vault under audit.

``nr_vault_tamper_only``
------------------------

A field on the :php:`AuditVerifyTask` record. When set, the task fails only on
tamper evidence — ``HASH_MISMATCH``, ``UID_GAP``, ``TABLE_RESET``,
``EPOCH_DOWNGRADE`` — and treats ``NO_EXTERNAL_SINK`` and ``SINK_FAILURE`` as
warnings.

Use it while sinks are still being rolled out, so a pending SIEM integration
does not leave the task permanently red and mask a real tamper alarm behind
alert fatigue. Turn it **off** once the sinks work: a persistently failing
sink is a genuine gap in your evidence.

The CLI equivalent is ``vault:audit-verify --tamper-only``.

.. _operations-monitoring-events:

AuditIntegrityAlertEvent
========================

Findings are dispatched as
:php:`Netresearch\NrVault\Event\AuditIntegrityAlertEvent`, so listeners fire
whether the finding came from a CLI run, a scheduled run, or a live vault
operation. **Nobody has to be watching the scheduler log.**

..  code-block:: php
    :caption: A listener that pages on tamper evidence only

    use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
    use TYPO3\CMS\Core\Attribute\AsEventListener;

    final readonly class VaultIntegrityPager
    {
        #[AsEventListener(identifier: 'my-ext/vault-integrity-pager')]
        public function __invoke(AuditIntegrityAlertEvent $event): void
        {
            $alert = $event->getAlert();

            if ($event->isTamperEvidence()) {
                $this->pager->page($alert->reason->value, $alert->message);

                return;
            }

            $this->logger->warning($alert->message, ['reason' => $alert->reason->value]);
        }
    }

Contract, and it matters:

*   **The event is informational, not vetoable.** The finding has already
    happened; there is nothing to cancel.
*   **Listeners must be fast and must tolerate both contexts.** The
    ``SINK_FAILURE`` path fires inside the audit write path of a live vault
    operation, not only from a CLI verification run.
*   **A throwing listener is caught and logged** at the dispatch site and never
    propagates into the audited operation — and never costs the remaining
    findings.
*   :php:`isTamperEvidence()` is the intended discriminator between paging and
    logging.

Two dispatch sites exist: :php:`AuditSinkRegistry` raises ``SINK_FAILURE``
when a sink refuses a record, and :php:`ChainTipAnchorService` raises the
tamper-evidence codes and ``NO_EXTERNAL_SINK`` from verification.

The bundled :php:`AuditIntegrityAlertSinkListener` already forwards every
alert to the enabled external sinks, so an alert reaches your SIEM by the same
route as the entries — no extra wiring needed for that part.

Break-glass has its own events —
:php:`BreakGlassActivatedEvent` and :php:`BreakGlassDeactivatedEvent`. Alert on
activation; see :ref:`operations-incident-response-breakglass`.

.. _operations-monitoring-sinks:

Wiring the sinks
================

See :ref:`security-audit-evidence-sinks` for what each sink does. Configuration
notes that only matter operationally:

Syslog
------

..  code-block:: none
    :caption: Extension configuration

    auditSinkSyslogEnabled = 1
    auditSinkSyslogIdent = nr-vault-prod

The cheapest useful sink. Facility is fixed at ``LOG_LOCAL0``; only the ident
is configurable, which is the field you actually need to vary when several
TYPO3 instances share a host — set it per instance.

..  code-block:: none
    :caption: Example rsyslog rule

    # /etc/rsyslog.d/30-nr-vault.conf
    local0.*  action(type="omfwd" target="siem.example.internal" port="514" protocol="tcp")
    & stop

Route on the ident to separate instances, and on severity to separate signal
from noise: ``LOG_CRIT`` is tamper evidence, ``LOG_ERR`` is a delivery failure,
``LOG_NOTICE`` is an anchor, ``LOG_WARNING`` a failed audit entry,
``LOG_INFO`` a successful one.

NDJSON file
-----------

..  code-block:: none
    :caption: Extension configuration

    auditSinkFileEnabled = 1
    auditSinkFilePath = /var/log/typo3/nr-vault-audit.ndjson
    auditSinkAnchorPath = /var/log/typo3/nr-vault-anchors.ndjson

Both paths must be outside any public root — a path under one makes the sink
report itself disabled rather than writing anyway. Files are created ``0600``
and directories ``0700``, and each line is written under an exclusive
``flock()``.

``auditSinkAnchorPath`` is what :php:`AnchorFileReader` reads back, so it is
the file whose integrity carries the reset-detection property. Ship it
somewhere append-only or off-host; an anchor file the attacker can truncate is
not a baseline. Note that the anchor path also receives ``alert`` records —
that is normal traffic, and the reader skips non-anchor lines.

If you rotate these files, **do not rotate the anchor file with a policy that
truncates or discards old lines** unless the copies are archived. The reader
takes the highest anchored sequence it can find; losing history shortens your
detection reach.

Webhook
-------

..  code-block:: none
    :caption: Extension configuration

    auditSinkWebhookEnabled = 1
    auditSinkWebhookUrl = https://siem.example.internal/collector/nr-vault

One JSON POST per record, with a ``type`` discriminator (``entry`` /
``anchor`` / ``alert``) and a ``source`` marker, so one endpoint routes all
three kinds.

..  warning::

    **The ``allowed_hosts`` note.** The webhook sink is built on the hardened
    HTTP client, so it inherits the extension-wide SSRF and DNS-rebinding
    defences: a collector on a private, RFC1918 or loopback address is
    **refused** unless the host is allow-listed literally in

    ..  code-block:: php
        :caption: config/system/additional.php

        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'][] = 'siem.example.internal';

    That is the intended trade-off. The webhook URL is settable from
    :guilabel:`Admin Tools > Settings`, so a compromised administrator could
    otherwise repoint it at a cloud metadata service and use the vault as an
    SSRF pivot. ``allowed_hosts`` is filesystem-bound and out of the backend's
    reach, which keeps the pivot closed while leaving the legitimate
    on-premise path open.

    Keep the list narrow — one entry per collector, never a wildcard. The
    refusal is not silent: it surfaces as a ``SINK_FAILURE`` and is reported by
    ``vault:audit-verify``.

The scheme is restricted to ``http`` and ``https``. An enabled-but-unconfigured
webhook reports itself disabled rather than claiming to be external evidence
while delivering nothing.

.. _operations-monitoring-what-to-page:

What to page on
===============

..  list-table::
    :header-rows: 1
    :widths: 24 16 60

    *   -   Reason code
        -   Response
        -   Why

    *   -   ``TABLE_RESET``
        -   **Page**
        -   The chain no longer contains the anchored tip. Either the audit
            table was wiped, or someone restored a backup without telling
            you. Both need a human now —
            :ref:`operations-incident-response-tampering`.

    *   -   ``HASH_MISMATCH``
        -   **Page**
        -   Rows were altered, or the master key and the table are from
            different points in time. Do not wait for the pattern to repeat.

    *   -   ``EPOCH_DOWNGRADE``
        -   **Page**
        -   An attempt to move rows onto a weaker or keyless algorithm. Benign
            causes exist (a lowered ``auditHmacEpoch``), but the malicious one
            is deliberate and targeted.

    *   -   ``UID_GAP``
        -   **Page**
        -   Rows were deleted from the chain.

    *   -   ``NO_EXTERNAL_SINK``
        -   Ticket, escalate if it persists
        -   Hardened only. Not an attack — but while it holds, a full reset
            would be undetectable. Treat a gap that survives one business day
            as an incident.

    *   -   ``SINK_FAILURE``
        -   Alert on rate, not on a single event
        -   A single transient failure is noise. Sustained failure means your
            evidence is only in the database it is meant to protect. Alert on
            *n* failures in a window, and on the same sink failing
            continuously.

    *   -   ``BREAK_GLASS``
        -   **Page**, and review afterwards
        -   Reserved code; also alert on
            :php:`BreakGlassActivatedEvent` directly. An activation is an
            incident by definition —
            :ref:`operations-incident-response-breakglass`.

Also worth alerting on, from outside the reason-code set:

*   **The anchor task failing** — it fails precisely when no sink accepted the
    anchor, which is exactly the state that silently removes your reset
    protection.
*   **The verify task not running** — a stalled scheduler is indistinguishable
    from a clean chain if you only watch for failures. Alert on absence, not
    just on failure.
*   **Anchor staleness.** Compare the newest anchor's ``timestamp`` against
    your expected interval. A stale anchor means the baseline is old even
    though nothing reported an error.
*   **``access_denied`` audit rows.** A burst of them is reconnaissance or a
    broken integration; either way somebody should know.
*   **``master_key_rotate_start`` without a successful
    ``master_key_rotate_end``** — a half-finished rotation
    (:ref:`operations-key-rotation-failure`).

.. _operations-monitoring-counters:

Sink failure counters
=====================

:php:`AuditSinkRegistry` counts failures for the lifetime of the request:
:php:`getFailureCount()` in total, and :php:`getFailureCountsBySink()` keyed by
sink identifier (``syslog``, ``file``, ``webhook``). These are what let a
health surface say "the audit pipeline stopped flowing" rather than only
"something logged an error".

Two behaviours to know about when reading them:

*   **A sink whose own enablement probe throws is counted as failed and
    treated as disabled** — under the record kind ``enablement-probe``. Without
    that, a misconfigured sink could throw outside the per-call handling and
    take the audited operation down.
*   **Alert delivery is non-reentrant.** A ``SINK_FAILURE`` alert is itself
    delivered through the sinks; a failure observed while delivering an alert
    is logged and counted but raises no further alert. Otherwise one broken
    sink would recurse until the stack ran out. So the counters can exceed the
    number of alerts you receive — by design.

Because the counters are per-request, they are a signal for a health check or a
custom listener, not a long-term metric. For trends, count ``SINK_FAILURE``
alerts in the SIEM.

.. _operations-monitoring-delivery-state:

Persisted delivery state
========================

The per-request counters are not the whole picture. The sink registry also
**persists** each sink's delivery state — last success, last failure, the
error text, and the consecutive-failure count — in ``sys_registry``. A freshly
started process therefore still knows that a collector has been unreachable
for days, which no request-scoped counter can tell you.

``vault:doctor`` surfaces it as one ``audit.sink_state.<sink>`` finding per
enabled sink, warning under the standard profile and critical under hardened.
A sink counts as stale once its last successful delivery is older than
:confval:`ext-nrvault-auditSinkStaleDeliveryHours` (default 24). A sink that
is enabled but has never delivered successfully is reported as such rather
than as healthy.

This is the state to monitor for "the audit pipeline is quietly broken",
because it survives process boundaries and does not depend on anyone having
been watching when the failure happened.

.. _operations-monitoring-doctor:

Periodic ``vault:doctor``
=========================

Run it on a schedule, not only at deploy time. Configuration drifts: someone
unticks a setting in :guilabel:`Admin Tools > Settings`, a key file's
permissions change, a sink URL is edited.

..  code-block:: bash

    vendor/bin/typo3 vault:doctor --profile=hardened --format=json

The exit code is the contract: ``0`` pass, ``1`` warnings, ``2`` critical.
Alert on ``2``, ticket on ``1``, and — as with the verify task — alert on the
check not having run at all.

The scheduled run above is passive: it reads state, it does not test
delivery. To prove end-to-end that every enabled sink still *accepts*
evidence, add a less frequent run with active probes:

..  code-block:: bash

    vendor/bin/typo3 vault:doctor --active-probes --format=json

This pushes the current chain-tip anchor through every enabled sink — a
webhook collector must answer 2xx — and emits one
``audit.sink_probe.<sink>`` finding each. It talks to external systems and
writes delivery state, so it is never run implicitly, neither by the passive
checks nor by the backend status panel. Schedule it daily rather than every
few minutes, and keep the passive run for the frequent one.
