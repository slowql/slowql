-- select_star
SELECT * FROM users;
SELECT * FROM orders;
SELECT * FROM products;
SELECT * FROM logs;

-- missing_where
UPDATE accounts SET status = 'inactive';
DELETE FROM sessions;
UPDATE employees SET salary = salary * 1.1;
DELETE FROM audit_log;

-- non_sargable
SELECT * FROM orders WHERE YEAR(created_at) = 2025;
SELECT * FROM logs WHERE MONTH(event_date) = 12;
SELECT * FROM invoices WHERE DAY(issue_date) = 15;
SELECT * FROM users WHERE UPPER(name) = 'ALICE';

-- implicit_conversion
SELECT * FROM customers WHERE email = 12345;
SELECT * FROM users WHERE status = 0;
SELECT * FROM accounts WHERE code = 999;
SELECT * FROM employees WHERE name = 42;

-- cartesian_product
SELECT * FROM users, orders;
SELECT * FROM products, categories;
SELECT * FROM employees, departments;
SELECT * FROM logs, errors;

-- n_plus_1
SELECT * FROM comments WHERE post_id = ?;
SELECT * FROM likes WHERE user_id = ?;
SELECT * FROM orders WHERE customer_id = ?;
SELECT * FROM messages WHERE thread_id = ?;

-- correlated_subquery
SELECT * FROM users WHERE EXISTS (SELECT * FROM orders WHERE orders.user_id = users.id);
SELECT * FROM products WHERE price > (SELECT AVG(price) FROM orders WHERE orders.product_id = products.id);
SELECT * FROM employees WHERE salary < (SELECT AVG(salary) FROM employees e WHERE e.department_id = employees.department_id);
SELECT * FROM accounts WHERE EXISTS (SELECT * FROM transactions WHERE transactions.account_id = accounts.id);

-- or_prevents_index
SELECT * FROM products WHERE category = 'books' OR category = 'electronics';
SELECT * FROM users WHERE role = 'admin' OR role = 'editor';
SELECT * FROM orders WHERE status = 'pending' OR status = 'failed';
SELECT * FROM logs WHERE severity = 'high' OR severity = 'critical';

-- offset_pagination
SELECT * FROM logs OFFSET 100;
SELECT * FROM users OFFSET 50;
SELECT * FROM products OFFSET 200;
SELECT * FROM orders OFFSET 300;

-- distinct_unnecessary
SELECT DISTINCT user_id FROM sessions;
SELECT DISTINCT account_id FROM transactions;
SELECT DISTINCT product_id FROM orders;
SELECT DISTINCT employee_id FROM payroll;

-- huge_in_list
SELECT * FROM items WHERE id IN (1,2,3,4,5,6,7,8,9,10);
SELECT * FROM users WHERE id IN (11,12,13,14,15,16,17,18,19,20);
SELECT * FROM orders WHERE id IN (21,22,23,24,25,26,27,28,29,30);
SELECT * FROM products WHERE id IN (31,32,33,34,35,36,37,38,39,40);

-- leading_wildcard
SELECT * FROM users WHERE name LIKE '%smith';
SELECT * FROM products WHERE description LIKE '%discount';
SELECT * FROM logs WHERE message LIKE '%error';
SELECT * FROM employees WHERE title LIKE '%manager';

-- count_star_exists
SELECT * FROM users WHERE (SELECT COUNT(*) FROM orders) > 0;
SELECT * FROM products WHERE (SELECT COUNT(*) FROM reviews) > 0;
SELECT * FROM accounts WHERE (SELECT COUNT(*) FROM transactions) > 0;
SELECT * FROM employees WHERE (SELECT COUNT(*) FROM payroll) > 0;

-- not_in_nullable
SELECT * FROM users WHERE id NOT IN (SELECT user_id FROM orders);
SELECT * FROM products WHERE id NOT IN (SELECT product_id FROM reviews);
SELECT * FROM accounts WHERE id NOT IN (SELECT account_id FROM transactions);
SELECT * FROM employees WHERE id NOT IN (SELECT employee_id FROM payroll);

-- no_limit_exists
SELECT * FROM users WHERE EXISTS (SELECT * FROM orders);
SELECT * FROM products WHERE EXISTS (SELECT * FROM reviews);
SELECT * FROM accounts WHERE EXISTS (SELECT * FROM transactions);
SELECT * FROM employees WHERE EXISTS (SELECT * FROM payroll);

-- floating_point_equals
SELECT * FROM products WHERE price = 19.99;
SELECT * FROM invoices WHERE amount = 123.45;
SELECT * FROM accounts WHERE balance = 1000.50;
SELECT * FROM payroll WHERE total = 2500.75;

-- null_comparison
SELECT * FROM users WHERE email = NULL;
SELECT * FROM products WHERE description != NULL;
SELECT * FROM accounts WHERE status = NULL;
SELECT * FROM employees WHERE department != NULL;

-- function_on_column
SELECT * FROM accounts WHERE LOWER(email) = 'test@example.com';
SELECT * FROM users WHERE UPPER(name) = 'ALICE';
SELECT * FROM orders WHERE YEAR(created_at) = 2025;
SELECT * FROM logs WHERE MONTH(event_date) = 12;

-- having_no_aggregates
SELECT department FROM employees HAVING department = 'HR';
SELECT role FROM users HAVING role = 'admin';
SELECT status FROM orders HAVING status = 'pending';
SELECT category FROM products HAVING category = 'books';

-- union_missing_all
SELECT id FROM users UNION SELECT id FROM admins;
SELECT name FROM employees UNION SELECT name FROM contractors;
SELECT product_id FROM orders UNION SELECT product_id FROM returns;
SELECT account_id FROM accounts UNION SELECT account_id FROM archives;

-- subquery_select_list
SELECT id, (SELECT COUNT(*) FROM orders) FROM users;
SELECT name, (SELECT AVG(price) FROM products) FROM categories;
SELECT department, (SELECT SUM(salary) FROM employees) FROM departments;
SELECT account_id, (SELECT MAX(amount) FROM transactions) FROM accounts;

-- between_timestamps
SELECT * FROM logs WHERE created_at BETWEEN '2025-01-01' AND '2025-12-31';
SELECT * FROM orders WHERE shipped_at BETWEEN '2025-02-01' AND '2025-03-01';
SELECT * FROM invoices WHERE issue_date BETWEEN '2025-04-01' AND '2025-04-30';
SELECT * FROM sessions WHERE login_time BETWEEN '2025-05-01' AND '2025-05-15';

-- case_in_where
SELECT * FROM orders WHERE CASE WHEN status = 'pending' THEN 1 ELSE 0 END = 1;
SELECT * FROM users WHERE CASE WHEN role = 'admin' THEN 1 ELSE 0 END = 1;
SELECT * FROM products WHERE CASE WHEN category = 'books' THEN 1 ELSE 0 END = 1;
SELECT * FROM accounts WHERE CASE WHEN status = 'active' THEN 1 ELSE 0 END = 1;

-- offset_no_order
SELECT * FROM users OFFSET 50;
SELECT * FROM products OFFSET 100;
SELECT * FROM orders OFFSET 200;
SELECT * FROM logs OFFSET 300;

-- like_no_wildcard
SELECT * FROM users WHERE name LIKE 'Alice';
SELECT * FROM products WHERE category LIKE 'Books';
SELECT * FROM orders WHERE status LIKE 'Pending';
SELECT * FROM employees WHERE role LIKE 'Manager';

-- order_by_ordinal
SELECT * FROM users ORDER BY 2;
SELECT * FROM products ORDER BY 3;
SELECT * FROM orders ORDER BY 1;
SELECT * FROM employees ORDER BY 4;
