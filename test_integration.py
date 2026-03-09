"""SlowQL Integration Diagnostic"""
from slowql.analyzers.registry import get_registry
from slowql.core.config import EngineConfig
from slowql.core.engine import Engine
from slowql.rules.catalog import get_all_rules

print("=" * 70)
print("SLOWQL INTEGRATION DIAGNOSTIC")
print("=" * 70)

# 1. Check Rules
print("\n📋 RULES STATUS:")
rules = get_all_rules()
print(f"  ✅ Total rules loaded: {len(rules)}")
print(f"  Sample: {rules[0].rule_id} - {rules[0].name}")
print(f"  Dimensions: {set(r.dimension.value for r in rules)}")

# 2. Check Registry
print("\n🏗️  REGISTRY STATUS:")
registry = get_registry()
registry.discover()
all_analyzers = registry.get_all()
print(f"  Analyzers registered: {len(all_analyzers)}")
if all_analyzers:
    for analyzer in all_analyzers[:3]:
        print(f"    - {analyzer.__class__.__name__} (dimension: {analyzer.dimension.value})")
else:
    print("    ❌ NO ANALYZERS REGISTERED!")

# 3. Check Engine
print("\n⚙️  ENGINE STATUS:")
config = EngineConfig()
engine = Engine(config=config)
print(f"  Analyzers loaded: {len(engine.analyzers)}")
if engine.analyzers:
    for analyzer in engine.analyzers[:3]:
        print(f"    - {analyzer.__class__.__name__}")
else:
    print("    ❌ NO ANALYZERS LOADED!")

# 4. Test Analysis
print("\n🧪 TEST ANALYSIS:")
test_query = "SELECT * FROM users WHERE email = 123 AND id = NULL"
print(f"  Query: {test_query}")

try:
    result = engine.analyze(test_query)
    print("  ✅ Analysis completed")
    print(f"  Issues found: {len(result.issues)}")

    if result.issues:
        print("\n  First 3 issues:")
        for issue in result.issues[:3]:
            print(f"    - [{issue.severity.value}] {issue.name}")
    else:
        print("  ❌ NO ISSUES DETECTED - INTEGRATION BROKEN!")

except Exception as e:
    print(f"  ❌ Analysis failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
