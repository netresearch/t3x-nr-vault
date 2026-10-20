.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-044-signed-oauth-expiry-buffers:

===================================================
ADR-044: Signed OAuth expiry buffers avoid wrapping
===================================================

Status
======

Accepted

Date
====

2026-10-10

Context
=======

``OAuthToken::isExpired()`` accepts a signed integer buffer. A positive buffer
considers the token expired early; a negative one extends its lifetime. The
existing DateTime relative-string calculation can wrap for ``PHP_INT_MAX`` and
classify a token as valid again. ``PHP_INT_MIN`` also produces an unparseable
relative string. The existing Fuzz test caught PHPUnit assertion failures as
``Throwable`` and accepted them, hiding the positive-limit wrong answer.

Decision
========

Keep the public constructor and method signatures. Sample the real current time
once in ``isExpired()`` and delegate comparison to a private predicate. It admits
fixed DateTime inputs in precision tests without adding a public clock API.
With buffer zero retain the existing DateTime object comparison, including its
microsecond precision.

For a nonzero buffer whose native Unix timestamps convert to PHP integers,
compare the current instant to the mathematical expiry timestamp minus the
signed buffer. Check the subtraction bounds first: an adjusted expiry below
``PHP_INT_MIN`` is already expired; one above ``PHP_INT_MAX`` is still future.
If the whole seconds are equal, compare the original microsecond fields too.
Do not turn integer overflow into floating point arithmetic or feed an extreme
signed quantity into DateTime's relative-string parser.

Where native timestamp conversion raises its range exception, retain the
previous DateTime modification and object comparison. This preserves existing
valid behavior on a PHP build with narrower integers and adds no public failure
boundary or requirement for 64-bit PHP. It does not enlarge DateTime's own
calendar or timestamp range.

Regression oracles capture execution exceptions and assert their exact result
outside catches. The existing extreme-buffer Fuzz assertion must not be caught
as an acceptable execution failure.

Consequences
============

Positive and negative buffer meanings remain available without a new clock API
or interface method. Whole-second arithmetic uses elapsed Unix seconds, with the
fractional part preserved. Token-cache and OAuth grant selection are unchanged.

Native 64-bit tests cover ordinary signed buffers, both integer-limit buffers,
and representable timestamp extremes. Fixed DateTime cases cover before, equal
and after fractional expiry for zero, positive and negative buffers. The public
wrapper retains real-clock expiry tests. Deliberate faults must fail behavioral
assertions rather than merely cause framework errors. Controlled DateTime
subclasses exercise both native range-exception types and the unchanged object
comparison; they also prove buffer zero avoids conversion. A real
conversion-range event does not occur on that native matrix. A narrower-integer
runtime remains a separate compatibility check, not a claimed successful test
here.

References
==========

* `PHP timestamp conversion <https://www.php.net/manual/en/datetime.gettimestamp.php>`__
* `PHP microsecond formatting <https://www.php.net/manual/en/datetime.format.php>`__
* :ref:`adr-008-http-client`
