CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

CREATE TABLE test_table (id serial PRIMARY KEY, data text);
INSERT INTO test_table (data) SELECT md5(random()::text) FROM generate_series(1, 1000);

-- Create monitoring role (same as production setup).
CREATE ROLE topsrv LOGIN PASSWORD 'topsrv';
GRANT pg_monitor TO topsrv;
GRANT SELECT ON pg_stat_statements TO topsrv;

-- Auto-discovery role: password = DerivePassword("test_token_for_ci") = SHA256("test_token_for_ci")[:32].
CREATE ROLE topsrv_auto LOGIN PASSWORD 'ced34ab353b764ba0860c80113f75be7';
GRANT pg_monitor TO topsrv_auto;
GRANT SELECT ON pg_stat_statements TO topsrv_auto;

-- Second user for testing userid aggregation (same queryid, same db, different user).
CREATE ROLE appuser LOGIN PASSWORD 'appuser';
GRANT SELECT ON test_table TO appuser;

-- Second database for testing cross-database queryid deduplication.
CREATE DATABASE testdb2;
\c testdb2
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE TABLE test_table (id serial PRIMARY KEY, data text);
INSERT INTO test_table (data) SELECT md5(random()::text) FROM generate_series(1, 100);
GRANT SELECT ON test_table TO topsrv;
GRANT SELECT ON test_table TO appuser;
