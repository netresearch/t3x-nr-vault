CREATE TABLE tx_nrvaulttest_record (
    title varchar(255) DEFAULT '' NOT NULL,
    api_key varchar(255) DEFAULT '' NOT NULL,
    api_secret varchar(255) DEFAULT '' NOT NULL,
    api_token varchar(255) DEFAULT '' NOT NULL,
    children int(11) unsigned DEFAULT 0 NOT NULL
);

CREATE TABLE tx_nrvaulttest_child (
    title varchar(255) DEFAULT '' NOT NULL,
    api_key varchar(255) DEFAULT '' NOT NULL,
    parent int(11) unsigned DEFAULT 0 NOT NULL
);
