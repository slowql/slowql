-- Demo queries for SlowQL smoke test
-- These should trigger various rules across dimensions

-- Performance: SELECT * full table scan
SELECT * FROM users WHERE status = 'active';

-- Security: potential SQL injection pattern
SELECT * FROM orders WHERE id = $1 OR 1=1;

-- Reliability: DELETE without WHERE
DELETE FROM session_logs;

-- Performance: ORDER BY without index hint, LIKE with leading wildcard
SELECT name, email FROM customers WHERE name LIKE '%john%' ORDER BY created_at DESC;

-- Quality: NULL comparison
SELECT * FROM products WHERE price = NULL;

-- Performance: SELECT DISTINCT on large result set
SELECT DISTINCT user_id, email, name FROM audit_log;

-- Reliability: UPDATE without WHERE
UPDATE accounts SET balance = 0;

-- Security: hardcoded credentials
SELECT * FROM users WHERE password = 'admin123';

-- Performance: nested subquery
SELECT * FROM orders WHERE customer_id IN (
    SELECT id FROM customers WHERE region IN (
        SELECT region_id FROM regions WHERE active = 1
    )
);

-- Cost: Cartesian join (implicit cross join)
SELECT a.name, b.order_id FROM users a, orders b;
