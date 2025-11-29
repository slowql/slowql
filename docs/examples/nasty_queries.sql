-- nasty_queries.sql
-- Consolidated examples used in the demo (one per detector). 
-- Paste into the CLI or save as a file and run: slowql --input-file nasty_queries.sql

-- 1) SELECT *
SELECT * FROM orders;

-- 2) DELETE without WHERE (missing_where)
DELETE FROM users;

-- 3) Function on indexed column (non_sargable)
SELECT * FROM events WHERE YEAR(created_at) = 2024;

-- 4) Implicit conversion (string vs numeric)
SELECT * FROM users WHERE id = '123';

-- 5) Cartesian product (missing join condition)
SELECT a.*, b.* FROM products a, orders b;

-- 6) N+1 pattern (example pattern; run in app context)
-- (Demonstration note: this is an application pattern rather than a single SQL statement)
-- Example: SELECT * FROM users; then for each user: SELECT * FROM orders WHERE user_id = ?;

-- 7) Correlated subquery
SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.x = t.x AND u.y > 5);

-- 8) OR that may prevent index usage
SELECT * FROM t WHERE col = 1 OR col = 2;

-- 9) Offset pagination (deep offset)
SELECT * FROM logs ORDER BY ts DESC LIMIT 100 OFFSET 100000;

-- 10) DISTINCT overused
SELECT DISTINCT id FROM orders;

-- 11) Huge IN clause
SELECT * FROM t WHERE id IN (1,2,3,4,5,6,7,8,9,10, /* ... , */ 9999,10000);

-- 12) Leading wildcard LIKE
SELECT * FROM users WHERE name LIKE '%smith';

-- 13) COUNT(*) with EXISTS pattern
SELECT COUNT(*) FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.t_id = t.id);

-- 14) NOT IN with nullable subquery
SELECT * FROM t WHERE id NOT IN (SELECT id FROM other);

-- 15) Unbounded EXISTS
SELECT * FROM t WHERE EXISTS (SELECT 1 FROM big_table);

-- 16) Floating point equality
SELECT * FROM products WHERE price = 0.1;

-- 17) NULL comparison using =
SELECT * FROM t WHERE col = NULL;

-- 18) Function on column (another example)
SELECT * FROM users WHERE LOWER(email) = 'a@b.com';

-- 19) HAVING without aggregates
SELECT * FROM t HAVING id > 5;

-- 20) UNION (missing ALL when appropriate)
SELECT a FROM t UNION SELECT a FROM u;

-- 21) Scalar subquery in select list
SELECT (SELECT id FROM t2 WHERE t2.x = t1.x) AS sub_id FROM t1;

-- 22) BETWEEN with timestamps
SELECT * FROM events WHERE ts BETWEEN '2024-01-01' AND '2024-12-31';

-- 23) CASE in WHERE
SELECT * FROM t WHERE CASE WHEN x THEN y ELSE z END = 1;

-- 24) OFFSET without ORDER BY
SELECT * FROM t LIMIT 10 OFFSET 10;

-- 25) LIKE without wildcard (use = instead)
SELECT * FROM users WHERE name LIKE 'john';

-- 26) Multiple wildcards
SELECT * FROM users WHERE name LIKE '%a%b%c%';

-- 27) ORDER BY ordinal
SELECT id, name FROM users ORDER BY 1, 2;
