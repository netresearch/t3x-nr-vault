.. include:: /Includes.rst.txt

.. _developer-technical-actor-context:

=======================
Technical actor context
=======================

Headless consumers — Symfony Messenger workers, scheduler runs, CLI
jobs — often need vault-gated secrets under a **named** technical
backend user: per-consumer audit attribution and group-scoped vault
ACL instead of the all-or-nothing CLI access switch.

:php:`Netresearch\NrVault\Security\TechnicalActorContextInterface`
provides that as a scoped API (see
:ref:`adr-029-technical-actor-context`):

.. code-block:: php
   :caption: EXT:my_extension/Classes/MessageHandler/IngestHandler.php

   use Netresearch\NrVault\Security\TechnicalActorContextInterface;
   use Netresearch\NrVault\Service\VaultServiceInterface;

   final readonly class IngestHandler
   {
       public function __construct(
           private TechnicalActorContextInterface $technicalActorContext,
           private VaultServiceInterface $vaultService,
       ) {}

       public function __invoke(IngestMessage $message): void
       {
           $apiKey = $this->technicalActorContext->runAs(
               $this->technicalBeUserUid,
               fn (): ?string => $this->vaultService->retrieve('my_ext/embeddings_api_key'),
           );
           // ...
       }
   }

Semantics
=========

While the callable runs, vault access checks evaluate as the given
backend user with the same user-based semantics a real authenticated
BE user gets: admin override, owner check, and the :ref:`ADR-005
group tiers <adr-005-access-control>` (including stale-group
filtering).
Groups are resolved exactly like a real login, including subgroup
expansion.

Validation is fail-closed and happens **before** the callable runs.
:php:`runAs()` throws a typed
:php:`Netresearch\NrVault\Exception\TechnicalActorException` for:

===========  ==================================================
Code         Refusal
===========  ==================================================
1784000001   uid is not a positive integer
1784000002   no non-deleted ``be_users`` record with that uid
1784000003   the user record is disabled
1784000004   the user is outside its start/end time window
===========  ==================================================

The identity is **always** restored on scope exit — including when the
callable throws.
Nested :php:`runAs()` calls stack; the innermost actor wins and each
scope restores the previous one.

The audit log records the scope honestly: entries written inside
:php:`runAs()` carry the actor's uid and username with
``actor_type = 'technical'``, sealed into the tamper-evident HMAC
chain like every other attribution field.

.. note::

   :php:`runAs()` is **not** an authentication mechanism.
   Any PHP code with DI access can act as any enabled backend user —
   the same power that ``$GLOBALS['BE_USER']`` mutation already grants
   every extension.
   The API adds validation, guaranteed restoration, and honest audit
   attribution; it does not add a privilege boundary.

.. _developer-technical-actor-context-migration:

Migrating from ``$GLOBALS['BE_USER']`` mutation
===============================================

Before this API, consumers impersonated a technical user by hydrating a
:php:`BackendUserAuthentication` via the ``@internal``
:php:`setBeUserByUid()` and swapping it into ``$GLOBALS['BE_USER']``
(restoring it in a ``finally``) so that vault's access control — which
read only that global — would see the identity:

.. code-block:: php
   :caption: Legacy consumer workaround (do not copy)

   $backendUser = new BackendUserAuthentication();
   $backendUser->setBeUserByUid($technicalBeUserUid); // @internal API

   $previous = $GLOBALS['BE_USER'] ?? null;
   $GLOBALS['BE_USER'] = $backendUser; // visible to ALL code in this process
   try {
       $result = $callback();
   } finally {
       $GLOBALS['BE_USER'] = $previous;
   }

That pattern is unsafe in any PHP process shared with a live visitor
request: while the scope is open, **all** code in the process observes
a fully privileged backend-user identity.
It also spreads ``@internal`` core API usage across every consumer.

Migration is mechanical:

#. Inject :php:`TechnicalActorContextInterface` instead of constructing
   :php:`BackendUserAuthentication` yourself.
#. Replace the global swap with
   :php:`$context->runAs($technicalBeUserUid, $callback)`.
#. Drop any ``Context`` aspect swap done *solely* for vault — vault
   never reads the ``backend.user`` aspect.
   Keep it only if other collaborators in the callback need the aspect.
#. Remove the record-validation code — :php:`runAs()` refuses missing,
   deleted, disabled, and time-restricted users itself.

``$GLOBALS['BE_USER']`` is never touched by :php:`runAs()`; an ambient
backend user (or the CLI placeholder a messenger worker runs under)
stays untouched and regains effect the moment the scope ends.
