#
# Table structure for table 'tx_nrvault_secret'
#
CREATE TABLE tx_nrvault_secret (
    uid int(11) unsigned NOT NULL auto_increment,
    pid int(11) DEFAULT 0 NOT NULL,
    scope_pid int(11) unsigned DEFAULT 0 NOT NULL,

    -- Identification
    identifier varchar(255) DEFAULT '' NOT NULL,
    description text,

    -- Encrypted data (local adapter only)
    encrypted_value mediumblob,
    encrypted_dek text,
    dek_nonce varchar(24) DEFAULT '' NOT NULL,
    value_nonce varchar(24) DEFAULT '' NOT NULL,
    encryption_version int(11) unsigned DEFAULT 1 NOT NULL,

    -- Change detection (without decrypting)
    value_checksum char(64) DEFAULT '' NOT NULL,

    -- Access control
    owner_uid int(11) unsigned DEFAULT 0 NOT NULL,
    allowed_groups text,
    write_groups text,
    context varchar(50) DEFAULT '' NOT NULL,
    frontend_accessible tinyint(1) unsigned DEFAULT 0 NOT NULL,

    -- Versioning and lifecycle
    version int(11) unsigned DEFAULT 1 NOT NULL,
    expires_at int(11) unsigned DEFAULT 0 NOT NULL,
    last_rotated_at int(11) unsigned DEFAULT 0 NOT NULL,
    read_count int(11) unsigned DEFAULT 0 NOT NULL,
    last_read_at int(11) unsigned DEFAULT 0 NOT NULL,
    metadata text,

    -- Adapter info
    adapter varchar(50) DEFAULT 'local' NOT NULL,
    external_reference varchar(500) DEFAULT '' NOT NULL,

    -- Standard TYPO3 fields
    tstamp int(11) unsigned DEFAULT 0 NOT NULL,
    crdate int(11) unsigned DEFAULT 0 NOT NULL,
    cruser_id int(11) unsigned DEFAULT 0 NOT NULL,
    deleted tinyint(1) unsigned DEFAULT 0 NOT NULL,
    hidden tinyint(1) unsigned DEFAULT 0 NOT NULL,

    PRIMARY KEY (uid),
    UNIQUE KEY identifier (identifier, deleted),
    KEY owner_uid (owner_uid),
    KEY adapter (adapter),
    KEY expires_at (expires_at),
    KEY context (context),
    KEY expires_cleanup (deleted, expires_at)
);

#
# Table structure for table 'tx_nrvault_secret_begroups_mm'
#
CREATE TABLE tx_nrvault_secret_begroups_mm (
    uid_local int(11) unsigned DEFAULT 0 NOT NULL,
    uid_foreign int(11) unsigned DEFAULT 0 NOT NULL,
    sorting int(11) unsigned DEFAULT 0 NOT NULL,
    sorting_foreign int(11) unsigned DEFAULT 0 NOT NULL,

    KEY uid_local (uid_local),
    KEY uid_foreign (uid_foreign)
);

#
# Table structure for table 'tx_nrvault_secret_writegroups_mm'
#
CREATE TABLE tx_nrvault_secret_writegroups_mm (
    uid_local int(11) unsigned DEFAULT 0 NOT NULL,
    uid_foreign int(11) unsigned DEFAULT 0 NOT NULL,
    sorting int(11) unsigned DEFAULT 0 NOT NULL,
    sorting_foreign int(11) unsigned DEFAULT 0 NOT NULL,

    KEY uid_local (uid_local),
    KEY uid_foreign (uid_foreign)
);

#
# Table structure for table 'tx_nrvault_audit_log'
#
CREATE TABLE tx_nrvault_audit_log (
    uid int(11) unsigned NOT NULL auto_increment,
    pid int(11) DEFAULT 0 NOT NULL,

    -- What happened
    secret_identifier varchar(255) DEFAULT '' NOT NULL,
    action varchar(50) DEFAULT '' NOT NULL,
    success tinyint(1) unsigned DEFAULT 1 NOT NULL,
    error_message text,
    reason text,

    -- Who did it
    actor_uid int(11) unsigned DEFAULT 0 NOT NULL,
    actor_type varchar(50) DEFAULT '' NOT NULL,
    actor_username varchar(255) DEFAULT '' NOT NULL,
    actor_role varchar(100) DEFAULT '' NOT NULL,

    -- Context
    ip_address varchar(45) DEFAULT '' NOT NULL,
    user_agent varchar(500) DEFAULT '' NOT NULL,
    request_id varchar(100) DEFAULT '' NOT NULL,

    -- Tamper detection (hash chain)
    previous_hash varchar(64) DEFAULT '' NOT NULL,
    entry_hash varchar(64) DEFAULT '' NOT NULL,

    -- Change tracking
    hash_before char(64) DEFAULT '' NOT NULL,
    hash_after char(64) DEFAULT '' NOT NULL,

    -- When
    crdate int(11) unsigned DEFAULT 0 NOT NULL,

    -- HMAC epoch (0 = legacy SHA-256, 1+ = HMAC-SHA256 with derived key)
    hmac_key_epoch int(11) unsigned DEFAULT 0 NOT NULL,

    -- Additional data (JSON)
    context text,

    PRIMARY KEY (uid),
    KEY secret_identifier (secret_identifier),
    KEY secret_identifier_time (secret_identifier, crdate DESC),
    KEY action (action),
    KEY actor_uid (actor_uid),
    KEY crdate (crdate),
    KEY success (success),
    KEY secret_outcome_time (secret_identifier, success, crdate)
);

#
# Extend tx_scheduler_task for OrphanCleanupTask fields
#
CREATE TABLE tx_scheduler_task (
    nr_vault_retention_days int(11) unsigned DEFAULT 7 NOT NULL,
    nr_vault_table_filter varchar(255) DEFAULT '' NOT NULL
);
