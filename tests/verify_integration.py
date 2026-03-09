import sys
from slowql.analyzers.registry import AnalyzerRegistry

def verify_rules():
    registry = AnalyzerRegistry()
    registry.discover()
    analyzers = registry.get_all()
    
    expected_counts = {
        "security": 45,
        "performance": 39,
        "quality": 30,
        "cost": 20,
        "reliability": 19,
        "compliance": 18
    }
    
    total_loaded = 0
    all_passed = True
    
    print("--- SlowQL Rule Integration Verification ---")
    for analyzer in analyzers:
        rules = analyzer.get_rules()
        count = len(rules)
        total_loaded += count
        expected = expected_counts.get(analyzer.name, 0)
        
        status = "✅ PASS" if count == expected else "❌ FAIL"
        if count != expected:
            all_passed = False
            
        print(f"Analyzer: {analyzer.name:12} | Rules: {count:3} | Expected: {expected:3} | {status}")
        
    print("-" * 45)
    print(f"Total Rules Loaded: {total_loaded}")
    print(f"Grand Total Expected: 171")
    
    if total_loaded == 171 and all_passed:
        print("\n✨ SUCCESS: All 171 rules are correctly integrated!")
        return 0
    else:
        print("\n⚠️ FAILURE: Rule counts do not match expectations.")
        return 1

if __name__ == "__main__":
    sys.exit(verify_rules())
