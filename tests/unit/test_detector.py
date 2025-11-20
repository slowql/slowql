import pytest
from slowql.core.detector import QueryDetector, IssueSeverity


class TestDetector:
    def test_select_star_detection(self, detector):
        issues = detector.analyze("SELECT * FROM users")
        assert len(issues) == 1
        assert issues[0].issue_type == "SELECT * Usage"
        assert issues[0].severity == IssueSeverity.MEDIUM
        
    def test_missing_where_critical(self, detector):
        issues = detector.analyze("DELETE FROM users")
        assert any(i.severity == IssueSeverity.CRITICAL for i in issues)
        
    def test_clean_query(self, detector):
        issues = detector.analyze("SELECT id FROM users WHERE id = 1")
        assert len(issues) == 0
        
    # Test every detector method...
    @pytest.mark.parametrize("query,expected_issue", [
        ("SELECT * FROM users WHERE UPPER(name) = 'JOHN'", "Non-SARGable WHERE"),
        ("SELECT * FROM a, b", "Cartesian Product"),
        ("SELECT * FROM users WHERE id IN " + "(" + ",".join(map(str, range(100))) + ")", "Massive IN List"),
    ])

    def test_pattern_detection(self, detector, query, expected_issue):
        issues = detector.analyze(query)
        assert any(i.issue_type == expected_issue for i in issues)

class TestDetectorEdgeCases:
    """Test edge cases and missed lines"""
    
    def test_normalize_multiline_query(self, detector):
        query = """
        SELECT *
        -- Comment here
        FROM users
        /* Block comment */
        WHERE id = 1
        """
        issues = detector.analyze(query)
        # Should still detect SELECT *
        assert any(i.issue_type == "SELECT * Usage" for i in issues)
        
    def test_all_detector_methods(self, detector):
        """Ensure every detector method runs"""
        test_cases = {
            "SELECT * FROM users WHERE created > NOW() - INTERVAL '7 days'": None,
            "UPDATE users SET status = 'active'": "Missing WHERE in UPDATE/DELETE",
            "SELECT id FROM users WHERE email = 123": "Implicit Type Conversion",
            "SELECT DISTINCT id FROM users": "Unnecessary DISTINCT",
            "SELECT * FROM users WHERE name LIKE 'John'": "LIKE without Wildcards",
            "SELECT * FROM users WHERE price = 19.99": "Floating Point Equality",
            "SELECT * FROM users WHERE status = NULL": "NULL Comparison Error",
            "SELECT * FROM users OFFSET 5000": "Large OFFSET Pagination",
            "SELECT * FROM users WHERE name LIKE '%%%test%%%'": "Multiple Wildcards",
            "SELECT * FROM users ORDER BY 1, 2": "ORDER BY Ordinal",
            "SELECT COUNT(*) FROM users HAVING COUNT(*) > 5": None,
            "SELECT * FROM users WHERE id > 5 OFFSET 100": "OFFSET without ORDER BY",
            "SELECT * FROM users WHERE YEAR(created_at) = 2023": "Non-SARGable WHERE",
            "SELECT * FROM users WHERE id + 1 = 10": "Non-SARGable WHERE", 
            "SELECT *, (SELECT COUNT(*) FROM orders WHERE orders.user_id = users.id) FROM users": "Correlated Subquery",
            "SELECT * FROM users WHERE id NOT IN (SELECT user_id FROM orders)": "NOT IN with NULLable",
            "SELECT * FROM users WHERE EXISTS (SELECT * FROM orders WHERE user_id = users.id)": "EXISTS without LIMIT",
            "SELECT * FROM users WHERE created BETWEEN '2023-01-01' AND '2023-12-31'": "BETWEEN with Timestamps",
            "SELECT * FROM users WHERE CASE WHEN status = 1 THEN true ELSE false END": "CASE in WHERE Clause",
            "SELECT * FROM users WHERE column_name + 5 = 10": "Non-SARGable WHERE",  
            "DELETE FROM users WHERE id > 5": None,  
            "SELECT * FROM users GROUP BY status": None,  
            "SELECT * FROM users WHERE user_id + 5 = 10": "Non-SARGable WHERE",  
            "SELECT * FROM users WHERE id IN (SELECT NULL)": None,  
            "SELECT * FROM users HAVING status = 'active'": "HAVING Instead of WHERE",  
            "SELECT * FROM users WHERE created BETWEEN '2023-01-01 00:00:00' AND '2023-12-31 23:59:59'": None,  


        }
        
        for query, expected_issue in test_cases.items():
            issues = detector.analyze(query)
            if query == "SELECT * FROM users WHERE status = NULL":
                print(f"Issues: {[(i.issue_type, i.severity) for i in issues]}")
            if expected_issue:
                assert any(i.issue_type == expected_issue for i in issues), f"Failed for: {query}"