-- PDNS API Proxy - Initial schema migration
-- Run against the PowerDNS-Admin database
-- No prerequisites: can run on a fresh database before PowerDNS-Admin is set up.
-- account_id is intentionally stored without a FK so this migration is independent
-- of the PowerDNS-Admin schema version.

CREATE TABLE IF NOT EXISTS api_keys (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    key_hash    CHAR(64)     NOT NULL,
    key_prefix  VARCHAR(13)  NOT NULL,
    description VARCHAR(255) NULL,
    account_id  INT UNSIGNED NOT NULL,
    is_active   TINYINT(1)   NOT NULL DEFAULT 1,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by  INT UNSIGNED NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_api_keys_key_hash (key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS api_key_ip_allowlist (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    api_key_id  INT UNSIGNED NOT NULL,
    ip_address  VARCHAR(45)  NOT NULL,
    cidr_mask   TINYINT UNSIGNED NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_akial_api_key FOREIGN KEY (api_key_id)
        REFERENCES api_keys (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    api_key_id      INT UNSIGNED    NOT NULL,
    method          VARCHAR(10)     NOT NULL,
    path            VARCHAR(500)    NOT NULL,
    request_body    TEXT            NULL,
    response_status SMALLINT        NOT NULL,
    client_ip       VARCHAR(45)     NOT NULL,
    user_agent      VARCHAR(255)    NULL,
    timestamp       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_api_key_id (api_key_id),
    KEY idx_audit_timestamp (timestamp),
    CONSTRAINT fk_al_api_key FOREIGN KEY (api_key_id)
        REFERENCES api_keys (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
