# User Pathways for E2E Testing

This document defines all user pathways that need comprehensive E2E test coverage
for the nr-vault TYPO3 extension backend modules.

## Module Overview

| Module | Route | Controller | Primary Purpose |
|--------|-------|------------|-----------------|
| Parent Overview | `/typo3/module/admin/vault` | OverviewController | Dashboard with statistics |
| Secrets Management | `/typo3/module/admin/vault/secrets` | SecretsController | CRUD + rotation for secrets |
| Audit Log | `/typo3/module/admin/vault/audit` | AuditController | Audit trail viewing/export |
| Migration Wizard | `/typo3/module/admin/vault/migration` | MigrationController | Migrate plaintext to vault |

---

## 1. Overview Module User Pathways

### UP-OV-001: View Dashboard Statistics
**Actor:** Backend Admin
**Steps:**
1. Navigate to Vault module
2. View total secrets count
3. View active secrets count
4. View disabled secrets count
5. See navigation cards to submodules

### UP-OV-002: Navigate to Submodules
**Actor:** Backend Admin
**Steps:**
1. View overview dashboard
2. Click on "Secrets" card → Navigate to secrets list
3. Click on "Audit" card → Navigate to audit log
4. Click on "Migration" card → Navigate to migration wizard

---

## 2. Secrets Module User Pathways

### UP-SEC-001: View Secrets List
**Actor:** Backend Admin
**Steps:**
1. Navigate to Secrets module
2. View paginated list of secrets
3. See secret identifiers, descriptions, status
4. See creation dates and ownership info

### UP-SEC-002: Filter Secrets List
**Actor:** Backend Admin
**Steps:**
1. Navigate to Secrets list
2. Filter by identifier (text search)
3. Filter by status (active/disabled)
4. Filter by owner (backend user)
5. Apply multiple filters
6. Clear filters

### UP-SEC-003: Create New Secret (Happy Path)
**Actor:** Backend Admin
**Steps:**
1. Navigate to Secrets list
2. Click "Create Secret" button
3. Fill in identifier (required)
4. Fill in secret value (required)
5. Add description (optional)
6. Set frontend accessibility flag
7. Assign backend users/groups (optional)
8. Set expiration date (optional)
9. Submit form
10. Verify success message
11. Verify secret appears in list

### UP-SEC-004: Create Secret - Validation Errors
**Actor:** Backend Admin
**Steps:**
1. Navigate to Create Secret form
2. Leave identifier empty → Submit → See validation error
3. Leave value empty → Submit → See validation error
4. Enter duplicate identifier → Submit → See error
5. Enter invalid identifier format → Submit → See error

### UP-SEC-005: View Secret Details
**Actor:** Backend Admin
**Steps:**
1. Navigate to Secrets list
2. Click on a secret row/view button
3. View secret metadata (identifier, description, dates)
4. See owner information
5. See frontend accessibility status
6. NOT see the actual secret value (security)

### UP-SEC-006: Reveal Secret Value (AJAX)
**Actor:** Backend Admin
**Steps:**
1. Navigate to secret view or list
2. Click "Reveal" button
3. See masked/revealed value toggle
4. Value is fetched via AJAX (revealAction) — every reveal re-hits the endpoint
5. Audit log entry created for "read" action
6. Copy-to-clipboard offered only when the response reports `copyAllowed`
7. Dialog counts down and closes itself after 30 s, wiping the input
8. Hiding the tab or leaving the page wipes and closes it immediately

### UP-SEC-007: Edit Secret Metadata
**Actor:** Backend Admin
**Steps:**
1. Navigate to secret view
2. Click "Edit" button
3. Modify description
4. Modify backend users/groups assignment
5. Modify frontend accessibility
6. Modify expiration date
7. Save changes
8. Verify success message
9. Verify changes persisted

### UP-SEC-008: Rotate Secret Value
**Actor:** Backend Admin
**Steps:**
1. Navigate to secret view
2. Click "Rotate" button
3. See rotation form with current identifier
4. Enter new secret value
5. Confirm rotation
6. Verify success message
7. Verify old value replaced
8. Verify audit log entry for "rotate"

### UP-SEC-009: Toggle Secret Status (Enable/Disable)
**Actor:** Backend Admin
**Steps:**
1. Navigate to Secrets list
2. Click toggle button on active secret → Becomes disabled
3. Click toggle button on disabled secret → Becomes enabled
4. Verify status change reflected in UI
5. Verify audit log entry

### UP-SEC-010: Delete Secret
**Actor:** Backend Admin
**Steps:**
1. Navigate to secret view or list
2. Click "Delete" button
3. See confirmation dialog/prompt
4. Confirm deletion
5. Verify success message
6. Verify secret removed from list
7. Verify audit log entry for "delete"

### UP-SEC-011: Delete Secret - Cancellation
**Actor:** Backend Admin
**Steps:**
1. Navigate to secret view
2. Click "Delete" button
3. See confirmation dialog
4. Cancel deletion
5. Verify secret still exists

### UP-SEC-012: Secrets List - Empty State
**Actor:** Backend Admin
**Steps:**
1. Navigate to Secrets module (with no secrets)
2. See empty state message
3. See "Create Secret" call-to-action

### UP-SEC-013: Access Denied - Unauthorized Secret
**Actor:** Non-Admin Backend User
**Steps:**
1. Attempt to access secret not owned by user
2. See access denied message
3. Audit log entry for "access_denied"

---

## 3. Audit Module User Pathways

### UP-AUD-001: View Audit Log
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit module
2. View paginated audit entries
3. See grouped entries by date
4. See timestamps, actions, actors, success status
5. See truncated hash values

### UP-AUD-002: Filter Audit Log by Secret Identifier
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit log
2. Enter secret identifier in filter
3. Apply filter
4. See only entries for that secret
5. Clear filter

### UP-AUD-003: Filter Audit Log by Action Type
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit log
2. Select action type (create/read/update/delete/rotate/access_denied/http_call)
3. Apply filter
4. See only entries with that action

### UP-AUD-004: Filter Audit Log by Date Range
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit log
2. Set "since" date
3. Set "until" date
4. Apply filter
5. See only entries within range

### UP-AUD-005: Filter Audit Log by Success Status
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit log
2. Filter by "success = true"
3. See only successful operations
4. Filter by "success = false"
5. See only failed operations

### UP-AUD-006: Audit Log Pagination
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit log (with >50 entries)
2. See first page (50 entries)
3. Click "Next" → See second page
4. Click "Previous" → Return to first page
5. Click "Last" → See last page
6. Click "First" → Return to first page

### UP-AUD-007: Export Audit Log as JSON (Admin Only)
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit log
2. Click "Export JSON" button
3. Download JSON file
4. Verify JSON structure contains audit entries

### UP-AUD-008: Export Audit Log as CSV (Admin Only)
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit log
2. Click "Export CSV" button
3. Download CSV file
4. Verify CSV has proper headers and data

### UP-AUD-009: Verify Hash Chain Integrity (Admin Only)
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit log
2. Click "Verify Chain" button
3. See verification results page
4. If valid: See success message
5. If tampered: See error with affected entries

### UP-AUD-010: Audit Log - Empty State
**Actor:** Backend Admin
**Steps:**
1. Navigate to Audit module (with no entries)
2. See empty state message
3. See explanation of what audit log tracks

### UP-AUD-011: Combined Filters with Pagination
**Actor:** Backend Admin
**Steps:**
1. Apply secret identifier filter
2. Apply action type filter
3. Navigate through paginated results
4. Verify filters persist across pages

---

## 4. Migration Module User Pathways

### UP-MIG-001: View Migration Wizard Start
**Actor:** Backend Admin
**Steps:**
1. Navigate to Migration module
2. See introduction/explanation
3. See "Start Scan" button
4. Understand purpose of migration

### UP-MIG-002: Scan for Plaintext Secrets
**Actor:** Backend Admin
**Steps:**
1. Start migration wizard
2. Click "Start Scan"
3. Wait for scan completion
4. See scan results summary
5. See count of detected secrets
6. See grouping by severity (high/medium/low)
7. See grouping by source (database/config)

### UP-MIG-003: Review Detected Secrets
**Actor:** Backend Admin
**Steps:**
1. Complete scan step
2. Click "Review" to continue
3. See list of detected plaintext secrets
4. Filter by source (database/config)
5. Filter by severity
6. Select secrets for migration
7. Deselect secrets to skip

### UP-MIG-004: Configure Migration Options
**Actor:** Backend Admin
**Steps:**
1. Select secrets for migration
2. Click "Configure" to continue
3. Define identifier pattern for migrated secrets
4. Set default ownership
5. Review configuration summary
6. Proceed to execution

### UP-MIG-005: Execute Migration
**Actor:** Backend Admin
**Steps:**
1. Complete configuration
2. Click "Execute Migration"
3. See progress indicator
4. Wait for completion
5. See migration results (success/failure counts)

### UP-MIG-006: Verify Migration Results
**Actor:** Backend Admin
**Steps:**
1. Complete migration execution
2. See verification page
3. Review successful migrations
4. Review failed migrations (if any)
5. See recommendations for manual fixes

### UP-MIG-007: Migration - No Secrets Found
**Actor:** Backend Admin
**Steps:**
1. Start migration wizard
2. Run scan
3. No plaintext secrets detected
4. See "all clear" message
5. Option to return to dashboard

### UP-MIG-008: Migration Wizard - Back Navigation
**Actor:** Backend Admin
**Steps:**
1. Progress through wizard steps
2. Click "Back" at review step → Return to scan
3. Click "Back" at configure step → Return to review
4. Verify state preserved when going back

### UP-MIG-009: Migration - Prevent Duplicate Migrations
**Actor:** Backend Admin
**Steps:**
1. Complete a migration for certain secrets
2. Run scan again
3. Already-migrated secrets not shown as candidates
4. Verify vault identifiers not re-migrated

---

## 5. Cross-Module User Pathways

### UP-CROSS-001: Full Secret Lifecycle
**Actor:** Backend Admin
**Steps:**
1. Create a new secret (Secrets module)
2. Verify creation audit entry (Audit module)
3. View secret details (Secrets module)
4. Verify read audit entry (Audit module)
5. Edit secret metadata (Secrets module)
6. Verify update audit entry (Audit module)
7. Rotate secret value (Secrets module)
8. Verify rotate audit entry (Audit module)
9. Disable secret (Secrets module)
10. Enable secret (Secrets module)
11. Delete secret (Secrets module)
12. Verify delete audit entry (Audit module)

### UP-CROSS-002: Dashboard Statistics Accuracy
**Actor:** Backend Admin
**Steps:**
1. Note current counts on Overview dashboard
2. Create a new secret
3. Verify total count increased by 1
4. Verify active count increased by 1
5. Disable the secret
6. Verify active count decreased by 1
7. Verify disabled count increased by 1
8. Delete the secret
9. Verify total count decreased by 1

### UP-CROSS-003: Module Navigation Consistency
**Actor:** Backend Admin
**Steps:**
1. Navigate from Overview → Secrets → Create → Submit → Return to list
2. Navigate from Secrets → Audit → Back to Secrets
3. Use browser back button
4. Verify navigation works consistently

---

## Test Priority Matrix

| Priority | Pathway ID | Description | Risk Level |
|----------|------------|-------------|------------|
| P0 | UP-SEC-003 | Create Secret (Happy Path) | Critical |
| P0 | UP-SEC-010 | Delete Secret | Critical |
| P0 | UP-SEC-008 | Rotate Secret | Critical |
| P0 | UP-AUD-009 | Verify Hash Chain | Critical |
| P1 | UP-SEC-006 | Reveal Secret (AJAX) | High |
| P1 | UP-SEC-004 | Create Secret Validation | High |
| P1 | UP-SEC-009 | Toggle Secret Status | High |
| P1 | UP-MIG-005 | Execute Migration | High |
| P1 | UP-CROSS-001 | Full Secret Lifecycle | High |
| P2 | UP-AUD-002-005 | Audit Filtering | Medium |
| P2 | UP-AUD-007-008 | Audit Export | Medium |
| P2 | UP-SEC-002 | Secrets Filtering | Medium |
| P2 | UP-MIG-001-009 | Migration Wizard | Medium |
| P3 | UP-OV-001-002 | Overview Navigation | Low |
| P3 | UP-AUD-006 | Pagination | Low |

---

## Implementation Notes

### Test Data Setup
- Need test secrets with various states (active, disabled, expired)
- Need test users with different permission levels
- Need audit log entries for filter testing
- May need database fixtures or API-based setup

### Authentication
- Use existing `auth.ts` fixture for TYPO3 backend login
- Admin credentials: admin / Joh316!!

### Selectors Strategy
- Prefer data-testid attributes where possible
- Use TYPO3 module structure selectors
- Use accessible selectors (role, label) for form elements

### Assertions
- Verify HTTP responses (no 500/503 errors)
- Verify UI state changes
- Verify database state where critical
- Verify audit log entries for security-critical operations
