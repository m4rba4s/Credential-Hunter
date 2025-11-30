-- Synthetic database dump with embedded secrets
CREATE TABLE users(id INT, name TEXT, password TEXT);
INSERT INTO users VALUES (1, 'admin', 'P@ssw0rd!Sup3rS3cret');

-- Connection strings
-- Mongo (matches detection regex)
-- mongodb://admin:Sup3rSecret@mongo.internal:27017/app
-- Postgres
-- postgres://ech_app:Ultra$ecret@pg.prod.internal:5432/ech
