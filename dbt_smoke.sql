{% set target = 'stg' %}

{# This is a comment that should be ignored #}
WITH users AS (
    SELECT id, name
    FROM {{ ref('stg_users') }}
),

orders AS (
    SELECT
      id,
      user_id,
      amount
    FROM raw_schema.orders
)

SELECT
  u.name,
  SUM(o.amount) as total
FROM users u
JOIN orders o ON u.id = o.user_id
{% if target == 'stg' %}
WHERE u.name != 'testing'
{% endif %}
GROUP BY u.name
