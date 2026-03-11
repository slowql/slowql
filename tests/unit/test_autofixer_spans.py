from slowql.core.autofixer import AutoFixer
from slowql.core.models import Fix, FixConfidence


class TestAutoFixerSpanSupport:
    def setup_method(self) -> None:
        self.autofixer = AutoFixer()

    def test_apply_fix_with_exact_span(self) -> None:
        query = "SELECT * FROM users WHERE deleted_at = NULL"
        start = query.index("= NULL")
        end = start + len("= NULL")
        fix = Fix(
            description="Replace = NULL with IS NULL",
            original="= NULL",
            replacement="IS NULL",
            confidence=FixConfidence.SAFE,
            rule_id="QUAL-NULL-001",
            is_safe=True,
            start=start,
            end=end,
        )
        updated = self.autofixer.apply_fix(query, fix)
        assert updated == "SELECT * FROM users WHERE deleted_at IS NULL"

    def test_apply_fix_with_invalid_span_no_change(self) -> None:
        query = "SELECT * FROM users"
        fix = Fix(
            description="Invalid span",
            original="users",
            replacement="accounts",
            confidence=FixConfidence.SAFE,
            rule_id="TEST-INVALID-SPAN",
            start=100,
            end=105,
        )
        assert self.autofixer.apply_fix(query, fix) == query

    def test_apply_fix_with_span_original_mismatch_no_change(self) -> None:
        query = "SELECT * FROM users"
        fix = Fix(
            description="Mismatched original",
            original="orders",
            replacement="accounts",
            confidence=FixConfidence.SAFE,
            rule_id="TEST-MISMATCH",
            start=query.index("users"),
            end=query.index("users") + len("users"),
        )
        assert self.autofixer.apply_fix(query, fix) == query

    def test_apply_all_fixes_with_multiple_non_overlapping_spans(self) -> None:
        query = "a = NULL AND b = NULL"
        first_start = query.index("= NULL")
        first_end = first_start + len("= NULL")
        second_start = query.rindex("= NULL")
        second_end = second_start + len("= NULL")

        fixes = [
            Fix(
                description="First NULL fix",
                original="= NULL",
                replacement="IS NULL",
                confidence=FixConfidence.SAFE,
                rule_id="QUAL-NULL-001",
                start=first_start,
                end=first_end,
            ),
            Fix(
                description="Second NULL fix",
                original="= NULL",
                replacement="IS NULL",
                confidence=FixConfidence.SAFE,
                rule_id="QUAL-NULL-001",
                start=second_start,
                end=second_end,
            ),
        ]

        updated = self.autofixer.apply_all_fixes(query, fixes)
        assert updated == "a IS NULL AND b IS NULL"

    def test_apply_all_fixes_skips_overlapping_spans(self) -> None:
        query = "abcdef"
        fixes = [
            Fix(
                description="Outer span",
                original="bcd",
                replacement="X",
                confidence=FixConfidence.SAFE,
                rule_id="TEST-OUTER",
                start=1,
                end=4,
            ),
            Fix(
                description="Inner overlapping span",
                original="cd",
                replacement="Y",
                confidence=FixConfidence.SAFE,
                rule_id="TEST-INNER",
                start=2,
                end=4,
            ),
        ]

        updated = self.autofixer.apply_all_fixes(query, fixes)
        assert updated in {"aXef", "abYef"}

    def test_text_based_fix_still_works_without_spans(self) -> None:
        query = "SELECT * FROM users WHERE deleted_at = NULL"
        fix = Fix(
            description="Legacy exact-text fix",
            original="= NULL",
            replacement="IS NULL",
            confidence=FixConfidence.SAFE,
            rule_id="QUAL-NULL-001",
        )
        updated = self.autofixer.apply_fix(query, fix)
        assert updated == "SELECT * FROM users WHERE deleted_at IS NULL"
