SELECT * FROM users;

SELECT * FROM users WHERE username = '' OR '1'='1';

SELECT password FROM users WHERE id = 1;

INSERT INTO users (username, password) VALUES ('admin', 'password123');

SELECT MD5(password) FROM users;

GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';

DELETE FROM orders;

TRUNCATE TABLE logs;

SELECT * FROM users WHERE email LIKE '%' + @input + '%';

EXEC xp_cmdshell 'dir';

SELECT * FROM OPENROWSET('SQLNCLI', 'Server=remote;UID=sa;PWD=pass', 'SELECT * FROM data');

CREATE USER admin IDENTIFIED BY 'admin';

SELECT @@VERSION;

SELECT * FROM INFORMATION_SCHEMA.TABLES;

UPDATE accounts SET balance = balance + 100 WHERE id = 1;

BEGIN TRANSACTION; UPDATE inventory SET qty = qty - 1 WHERE product_id = 1;

SELECT * FROM products WHERE price > 0 AND price < 1000 OR category = 'sale';

SELECT COUNT(*) FROM (SELECT * FROM orders ORDER BY date) sub;

SELECT * FROM orders OFFSET 10000 LIMIT 10;

SELECT COUNT(*) FROM orders;

CREATE TABLE products (name VARCHAR(100), price FLOAT);

SELECT * FROM users a JOIN orders b ON a.id = b.user_id;

DECLARE user_cursor CURSOR FOR SELECT * FROM users;

SELECT ROW_NUMBER() OVER (ORDER BY date) FROM events;

INSERT INTO summary SELECT * FROM raw_data;

SELECT * FROM db1.users JOIN db2.orders ON db1.users.id = db2.orders.user_id;

SELECT * FROM users WHERE status = 'PENDING_REVIEW';

CREATE TABLE orders (id INT, user_id INT);

SELECT * FROM patients WHERE ssn = '123-45-6789';

SELECT card_number FROM payments WHERE user_id = 1;

INSERT INTO audit_log VALUES (1, 'test'); DELETE FROM audit_log WHERE id = 1;

SELECT * FROM users WHERE user_id = '123';

UPDATE ledger SET amount = 1000 WHERE id = 1;

SELECT * FROM events GROUP BY created_at;

SELECT * FROM orders WITH (TABLOCK);

SELECT * FROM orders WITH (NOLOCK);

WHILE @counter < 1000 BEGIN UPDATE table SET x = x + 1; END

SELECT * FROM users WHERE id IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60);

SELECT * INTO #temp FROM orders;

SELECT * FROM orders OPTION (FORCE ORDER);

SELECT * FROM orders USE INDEX (idx_date);

SELECT dbo.GetUserName(user_id) FROM orders;

SELECT * FROM (SELECT * FROM (SELECT * FROM users WHERE active = 1) t1 WHERE verified = 1) t2;

SELECT CASE WHEN x = 1 THEN CASE WHEN y = 1 THEN CASE WHEN z = 1 THEN 'value' END END END FROM table;

INSERT INTO users (username) VALUES ('test@test.com');

SELECT * FROM users WHERE name = 'order';

SELECT * FROM users LIMIT 10;

CREATE TABLE users (id INT, name VARCHAR(100));

SELECT AES_ENCRYPT(data, 'hardcoded_key_123') FROM sensitive;

BEGIN TRANSACTION; UPDATE orders SET status = 'shipped';

SELECT * FROM users WHERE username = @u AND password = @p;

RAISERROR('Error in table %s', 16, 1, OBJECT_NAME(@@PROCID));

SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

INSERT INTO users (user_id, email) VALUES (999, 'test@example.com');

DELETE FROM users WHERE id = 1;

SELECT user_id FROM sessions WHERE token = 'abc123';

WITH RECURSIVE cte AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM cte WHERE n < 1000) SELECT * FROM cte;

SELECT * FROM data WHERE text REGEXP '(a+)+';

SELECT * FROM orders WHERE created_at > NOW();

INSERT INTO email_queue SELECT user_id, 'subject' FROM users;

SELECT * FROM partner_exports SELECT user_id FROM users WHERE state = 'CA';

SELECT JSON_VALUE(data, '$.' + @column) FROM documents;

SELECT * FROM ldap_query('cn=' + @username);

SELECT * FROM OPENJSON('{"filter": "' + @input + '"}');

SELECT xml_data.query('//user[@name="' + @name + '"]') FROM users;

EXEC sp_OACreate 'MSXML2.XMLHTTP', @obj;

SELECT * FROM OPENROWSET('MSDASQL', 'Server=' + @server);

SELECT price * 1.1 FROM products WHERE UPPER(name) = 'WIDGET';

SELECT * FROM orders WHERE user_id = 1 AND status = 'pending';

SELECT * FROM events WHERE event_date = '2024-01-01';

SELECT o.*, i.* FROM orders o CROSS JOIN items i;

SELECT * FROM users u JOIN orders o1 ON u.id = o1.user_id JOIN items i1 ON o1.id = i1.order_id JOIN products p1 ON i1.product_id = p1.id JOIN categories c1 ON p1.category_id = c1.id JOIN suppliers s1 ON p1.supplier_id = s1.id JOIN warehouses w1 ON s1.warehouse_id = w1.id JOIN regions r1 ON w1.region_id = r1.id;

SELECT COUNT(*) FROM orders WHERE 1=1;

SELECT * FROM orders WHERE status != 'cancelled';

SELECT COALESCE(status, 'unknown') FROM orders WHERE id = 1;

UPDATE products SET stock = stock - 1 WHERE id = 1;

IF NOT EXISTS (SELECT 1 FROM users WHERE email = 'test@test.com') INSERT INTO users (email) VALUES ('test@test.com');

SELECT balance FROM accounts WHERE id = 1; UPDATE accounts SET balance = 100 WHERE id = 1;

CREATE INDEX idx_users_name ON users(name); CREATE INDEX idx_users_email ON users(email); CREATE INDEX idx_users_status ON users(status);

SELECT price, name, description, category, brand, sku, stock, weight, dimensions, color, size, rating, reviews, manufacturer, warranty, shipping_cost, discount FROM products WHERE active = 1;

SELECT content FROM articles WHERE id = 1;

CREATE TABLE logs (message TEXT);

SELECT * FROM events WHERE type = 'click';

SELECT * FROM tbl_users;

EXEC sp_get_user @id;

CREATE TABLE products (order INT, user VARCHAR(50));

CREATE INDEX idx ON users(last_name, first_name);