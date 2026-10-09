<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- SPDX-FileCopyrightText: Netresearch DTT GmbH -->
# Additional Vault body credentials

ADR-041. Required by actor-bound MCP RFC-8693 exchange in nr-llm.

1. Add `AdditionalSecretHttpClientInterface::withAdditionalBodyField()` without
   changing existing interface signatures. Concrete client exposes
   capability, returns only immutable clones, and has no credential getter.
2. Primary authentication plus independently stored body credentials reach one
   PSR request via the existing Vault injection and secured transport. Both
   form-encoded and JSON-object requests preserve nonsecret fields.
3. Every clone (authentication, OAuth, reason, timeout) preserves bindings.
   Original instances remain unchanged. Timeout rebuild keeps the same security
   stack and credentials; cancellable and streaming paths share injection.
4. Missing/denied additional credential stops transport contact. Already-cancelled
   requests read no credentials. Existing HTTP/access audit and body redaction
   apply; no new body logging, plaintext retrieval or nested client is exposed.
5. Reject duplicate field bindings, primary field collisions in either builder
   order, malformed field names, and more than eight bindings. Existing
   constructors retain positional compatibility via optional trailing metadata.
   Field names match `[A-Za-z_][A-Za-z0-9_]{0,63}`; identifiers contain 1–255
   bytes and no ASCII controls. Bound fields replace any existing body value;
   OAuth resource bindings never enter the OAuth token leg.

Evidence: unit `VaultHttpClientAdditionalBodyFieldTest` exercises actual outgoing
request bytes, clone sequences, rejection/denial and no transport contact;
existing cancellable/streaming tests and focused added cases prove those paths;
API snapshot tests prove additive surface, fuzz tests prove new bounds;
functional secured-send fixture proves credentials enter the pinned transport.
Run container unit/fuzz/functional checks, PHPStan, code style and API snapshot.
