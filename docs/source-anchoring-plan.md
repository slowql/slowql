# Source Anchoring Plan

## Problem

SlowQL currently loses exact original SQL statement text during parsing.

In `src/slowql/parser/universal.py`, `_split_statements()` uses regenerated SQL (`stmt.sql()`) on the happy path instead of preserving the exact source slice from the original input.

This breaks safe autofix application for context-sensitive fixes because:
- preview may be generated from normalized SQL
- apply runs against original file text
- exact text and offsets may not match

Example:
- original file: `EXISTS (SELECT * FROM orders ...)`
- regenerated SQL: `EXISTS(SELECT * FROM orders ...)`

The autofix engine correctly refuses to apply in these cases.

## Goal

Preserve exact statement source slices and offsets so fixes can target the original file safely.

## Required outcomes

1. `Query.raw` must always be the exact original statement text.
2. `Query` should carry:
   - `start_offset`
   - `end_offset`
3. statement location line/column should map to the original source
4. semicolons inside strings/comments must not split statements
5. parser behavior must remain compatible with existing analysis flow

## Proposed approach

### Phase 1
Add `start_offset` and `end_offset` to `Query`.

### Phase 2
Replace `_split_statements()` with a dedicated splitter that:
- walks the original SQL text character by character
- tracks:
  - single quotes
  - double quotes
  - backticks
  - line comments
  - block comments
- splits only on semicolons outside those contexts
- returns:
  - exact statement substring
  - original line/column
  - start/end offsets

### Phase 3
Keep `normalized` generated separately from parsed AST.
`raw` must remain untouched original source.

### Phase 4
Add parser tests for:
- exact raw preservation
- offsets
- multiple statements
- semicolons in strings
- comments before statements

### Phase 5
Re-enable span-based autofix for `QUAL-STYLE-002`.

## Non-goals

- no new autofix rules during parser refactor
- no CLI changes
- no reporter changes
- no broad parser redesign beyond source preservation

## Why this matters

This unlocks:
- reliable span-based autofix
- trustworthy diff/apply behavior
- better future IDE/LSP mapping
- more safe autofixes without fragile text matching
