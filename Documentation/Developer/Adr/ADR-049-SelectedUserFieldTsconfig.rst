.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-049-selected-user-field-tsconfig:

================================================
ADR-049: Selected-user field TSconfig
================================================

Status
======

Proposed repair of the existing optional-user argument; a separate dependent
implementation follows this decision and specification.

Context
=======

``VaultFieldPermissionService`` accepts an optional backend-user object in all
three public wrappers. That object selects admin bypass and cache identity,
while the configuration path currently reads ambient Page TSconfig. Real
opposing-account tests expose the mismatch. Merely passing selected User
TSconfig into Core's PageTsConfigFactory still evaluates backend-user conditions
against the ambient Context. This boundary cannot be removed by describing the
existing argument as a narrower selector after the fact.

Native TYPO313.4.36 and TYPO314.3.8 each produce five genuine assertion failures
in the same twenty-case original probe. A local-context Core coordination
prototype passes four cases/112 assertions on both, including mutable tree,
visitor and real ambient runtime-cache identity checks. It is architecture
evidence; production is unchanged and requires its own final acceptance run.

Decision
========

Thread the selected object into private policy resolution. Keep the existing
BackendUtility page-zero path when the object is the global backend account.
For a distinct object, use Core's include tree, tokenizer, condition-aware
traverser and configured fresh AST visitor with a newly constructed condition
visitor bound to a cloned Context and selected backend UserAspect.

Preserve Core's selected materialized ``page.*`` overrides, native page-zero
defaults and other request aspects. Neither the global account, main Context
nor Core's ambient page-UID runtime cache may change. Stateful visitors and
trees must not leak between resolutions. Isolate Core13's logger setter versus
Core14's constructor logger; both condition visitors must be fresh.

Keep public signatures, constructor compatibility, admin/read-only behavior,
precedence, boolean conversion and the existing UID permission cache until
clearCache. A selected policy evaluation changes no execution/login identity
and grants no underlying Vault operation or secret permission by itself.

The concrete external specification is
:file:`specs/008-selected-user-field-policy/spec.md`. It records the native
supported-major evidence and final production falsification requirements.

Consequences
============

The helper duplicates the narrow Core factory coordination that cannot receive
a local Context; it does not duplicate the parser. Core helpers are internal,
so their supported-major behavior is checked with actual native tests rather
than assumed from one major's signatures.

TYPO313's deprecated global Page TSconfig input remains supported by its Core;
TYPO314's removal stays in effect. Existing field UI/Hook users that omit the
argument keep the ordinary path. No current repository caller is claimed to
exercise the defective optional argument, and no whole ACL-family closure
follows from this repair.
