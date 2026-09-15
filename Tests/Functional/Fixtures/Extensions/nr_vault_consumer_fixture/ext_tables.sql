#
# Envelopes this consumer seals itself and hands to master-key rotation
#
CREATE TABLE tx_nrvaultconsumerfixture_payload (
    uid int(11) unsigned NOT NULL auto_increment,
    pid int(11) DEFAULT 0 NOT NULL,
    sealed text,

    PRIMARY KEY (uid)
);
