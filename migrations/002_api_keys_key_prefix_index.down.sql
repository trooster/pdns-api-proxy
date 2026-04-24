-- Rollback: 002_api_keys_key_prefix_index

ALTER TABLE api_keys
    DROP INDEX idx_api_keys_key_prefix;
