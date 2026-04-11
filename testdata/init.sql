CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

CREATE TABLE test_table (id serial PRIMARY KEY, data text);
INSERT INTO test_table (data) SELECT md5(random()::text) FROM generate_series(1, 1000);

-- Create monitoring role (same as production setup).
CREATE ROLE topsrv LOGIN PASSWORD 'topsrv';
GRANT pg_monitor TO topsrv;
