# Specification 005: contain hook diagnostic-writer failures

Status: proposed for bounded audit repair. Parent: exact FlexForm final-link implementation #436 (19857f40be9bf1c7d08cc403e10dc59739130820). Decision: ADR047.

## Confirmed failure

The unmodified VaultFailureReporter passes its cause-independent message through a PSR-3 error logger before returning it. A writer RuntimeException or Error replaces both a missing-secret and denied-secret diagnostic: four native PHP8.5 cases produce four genuine assertion failures and zero framework Errors.

The public FlexForm copy hook stores and links a clone before an injected final-link failure. Clone deletion then fails, and the diagnostic writer also throws. That second failure exits the compensation handler before clearing the column. A real Core XML serializer and captured connection state show that the duplicate still references its clone: sixteen native cases, 252 assertions, four genuine assertion failures, zero framework Errors. The twelve existing link/recovery controls remain green. Connection/Vault callbacks establish recovery logic, not native SQL or cryptographic execution. A missing-tool trial and a refused AST fixture transaction executed no test and are excluded.

## Required behavior

1. VaultFailureReporter attempts its existing PSR-3 error write once. Contain any Throwable from that write so existing callers can continue recovery and obtain the existing cause-independent, correlated user message.
2. Keep the constant server log message, sanitized/bounded context, cause class and matching reference when a logger accepts the record. Do not retry or recursively report a failed logger through itself. An attempted log is not a delivery receipt.
3. Do not catch the original storage, permission, encryption or required mutation-audit failure here. Their existing callers still own compensation/refusal. Only the secondary diagnostic write is best-effort.
4. In the public copy counterpart, a failed clone deletion remains a failed deletion: nevertheless attempt the existing clearing write and deliver an honest correlated notice. Preserve the other FlexForm data. No claim that all clones were deleted or the record transaction was undone.
5. Preserve public signatures and existing translation/message behavior. Random-reference generation, language-service failures and delivery through DataHandler remain separate boundaries; this is not a promise that every diagnostic collaborator can never throw.

## Validation

Keep all assertions outside the production callback/catch boundary. Exercise RuntimeException and Error writers against missing/denied causes and RuntimeException/Error cleanup failures through the public copy hook. Check the actual retained/cleared XML, exact deletion attempts, user message and correlation reference, non-vault data, no cause leakage and one writer attempt. Retain healthy sanitized-context tests. Selected guard-removal/narrow-catch faults must fail genuine assertions with zero framework Errors; restore exact source before final CI, Rector, full SQLite and relevant Core-copy database controls. Render the manual and record inherited warnings separately.
