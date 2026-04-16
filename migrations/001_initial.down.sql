-- Rollback: 001_initial
-- Drops all custom tables created by 001_initial.up.sql
-- Order matters: child tables with FKs first

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS api_key_ip_allowlist;
DROP TABLE IF EXISTS api_keys;
