-- Add an index on api_keys.key_prefix so that API-key authentication can
-- locate the candidate row in O(1) instead of scanning every active key and
-- running argon2id against each (~100 ms per call). Removes a timing side-
-- channel that otherwise leaks the total number of active keys.

ALTER TABLE api_keys
    ADD INDEX idx_api_keys_key_prefix (key_prefix);
