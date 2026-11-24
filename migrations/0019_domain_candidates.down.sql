-- 0019_domain_candidates.down.sql — reverse 0019.

BEGIN;

DROP TABLE IF EXISTS domain_price_quotes;
DROP TABLE IF EXISTS domain_candidates;
DROP TABLE IF EXISTS registrar_providers;
DROP TYPE IF EXISTS domain_candidate_status;

COMMIT;
