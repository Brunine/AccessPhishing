-- 0017_domains.down.sql

BEGIN;

DROP TABLE IF EXISTS domain_verifications;
DROP TABLE IF EXISTS domain_assignments;
DROP TABLE IF EXISTS domains;
DROP TYPE IF EXISTS domain_status;

COMMIT;
