- Implement the documented `*` identifier patterns in `VaultService::list()` and
  `vault:list --pattern`. Patterns match complete identifiers; `%` and `_` stay
  literal. Repository prefix filters retain their literal prefix semantics.
  Real database tests cover PHP and CLI results, access checks, disabled and
  deleted records, and pattern/prefix combinations.
