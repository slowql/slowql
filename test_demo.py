from slowql.core.analyzer import QueryAnalyzer
from slowql.formatters.console import print_analysis
import importlib
import slowql.formatters.console
importlib.reload(slowql.formatters.console)


# Create analyzer
analyzer = QueryAnalyzer(verbose=True)

# Test queries with various issues
test_queries = [
    "SELECT * FROM users WHERE id = 1",
    "DELETE FROM orders",
    "SELECT * FROM users, orders",
    "SELECT * FROM users WHERE UPPER(email) = 'TEST@EMAIL.COM'",
    "SELECT * FROM users WHERE created_at BETWEEN '2023-01-01' AND '2023-12-31'",
    "SELECT id FROM users WHERE status = NULL",
    "SELECT * FROM products WHERE price = 19.99",
    "SELECT * FROM users WHERE id IN " + "(" + ",".join(map(str, range(100))) + ")",
]

# Run analysis
results = analyzer.analyze(test_queries)
print_analysis(results) 

# # Print beautiful report
# analyzer.print_report(results, detailed=True)

# # Show stats
# print("\n📊 Analysis Statistics:")
# stats = analyzer.get_summary_stats()
# for key, value in stats.items():
#     print(f"   {key}: {value}")
