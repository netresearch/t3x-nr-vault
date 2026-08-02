.. include:: /Includes.rst.txt

.. _adr-index:

=================================
Architecture decision records
=================================

This section documents significant architectural decisions made during the
development of nr-vault, along with the context and consequences of each
decision.

Architecture Decision Records (ADRs) capture important decisions along with
their context and consequences. They provide a historical record of why
certain decisions were made, helping future maintainers understand the
codebase.

.. contents:: Table of contents
   :local:
   :depth: 1

Overview
========

=======  =======================================================  ========
ADR      Title                                                    Status
=======  =======================================================  ========
001      :ref:`adr-001-uuid-v7`                                   Accepted
002      :ref:`adr-002-envelope-encryption`                       Accepted
003      :ref:`adr-003-master-key-management`                     Accepted
004      :ref:`adr-004-tca-integration`                           Accepted
005      :ref:`adr-005-access-control`                            Accepted
006      :ref:`adr-006-audit-logging`                             Accepted
007      :ref:`adr-007-secret-metadata`                           Accepted
008      :ref:`adr-008-http-client`                               Accepted
009      :ref:`adr-009-extension-configuration-secrets`           Accepted
010      :ref:`adr-010-secure-outbound`                           Accepted
011      :ref:`adr-011-credential-sets`                           Accepted
012      :ref:`adr-012-secure-http-transports`                    Accepted
013      :ref:`adr-013-rust-ffi-preload`                          Accepted
014      :ref:`adr-014-packaging-native`                          Accepted
015      :ref:`adr-015-http3-feature-flag`                        Accepted
016      :ref:`adr-016-sidecar-option`                            Accepted
017      :ref:`adr-017-audit-metadata-retention`                  Accepted
018      :ref:`adr-018-flexform-secret-lifecycle`                 Accepted
019      :ref:`adr-019-configurable-audit-read-logging`           Accepted
020      :ref:`adr-020-master-key-request-lifetime-caching`       Accepted
021      :ref:`adr-021-batch-secret-loading`                      Accepted
022      :ref:`adr-022-dedicated-oauth-exception`                 Accepted
023      :ref:`adr-023-audit-hash-chain-hmac`                     Accepted
024      :ref:`adr-024-audit-hash-forensic-fields`                Accepted
025      :ref:`adr-025-secret-entity-readonly`                    Accepted
026      :ref:`adr-026-dns-rebinding-defence`                     Accepted
027      :ref:`adr-027-oauth-client-unification`                  Accepted
028      :ref:`adr-028-phpat-http-client-lock`                    Accepted
029      :ref:`adr-029-technical-actor-context`                   Accepted
030      :ref:`adr-030-site-config-vault-read-time-resolution`    Accepted
031      :ref:`adr-031-shared-secret-pattern-catalogue`           Accepted
032      :ref:`adr-032-portable-envelope-codec`                   Accepted
033      :ref:`adr-033-foreign-envelope-rotation`                 Accepted
034      :ref:`adr-034-audit-chain-tip-anchor`                    Accepted
035      :ref:`adr-035-frontend-placeholder-allow-set`            Amended
=======  =======================================================  ========

.. toctree::
   :maxdepth: 1
   :titlesonly:

   ADR-001-UuidV7Identifiers
   ADR-002-EnvelopeEncryption
   ADR-003-MasterKeyManagement
   ADR-004-TcaIntegration
   ADR-005-AccessControl
   ADR-006-AuditLogging
   ADR-007-SecretMetadata
   ADR-008-HttpClient
   ADR-009-ExtensionConfigurationSecrets
   ADR-010-SecureOutboundInNrVault
   ADR-011-CredentialSetsDataModel
   ADR-012-SecureHttpClientTransports
   ADR-013-RustFfiPreload
   ADR-014-PackagingNativeArtifacts
   ADR-015-Http3FeatureFlag
   ADR-016-SidecarOption
   ADR-017-AuditMetadataRetention
   ADR-018-FlexFormSecretLifecycle
   ADR-019-ConfigurableAuditReadLogging
   ADR-020-MasterKeyRequestLifetimeCaching
   ADR-021-BatchSecretLoading
   ADR-022-DedicatedOAuthException
   ADR-023-AuditHashChainHmac
   ADR-024-AuditHashForensicFields
   ADR-025-SecretEntityReadonly
   ADR-026-DnsRebindingDefence
   ADR-027-OAuthClientUnification
   ADR-028-PhpatHttpClientLock
   ADR-029-TechnicalActorContext
   ADR-030-SiteConfigVaultReadTimeResolution
   ADR-031-SharedSecretPatternCatalogue
   ADR-032-PortableEnvelopeCodec
   ADR-033-ForeignEnvelopeRotation
   ADR-034-AuditChainTipAnchor
   ADR-035-FrontendPlaceholderAllowSet
