"""
tests.py — Comprehensive test suite for the password evaluation system.

Covers:
  - Rule-based validation
  - Entropy calculation
  - Hard constraint gates
  - Edge cases
  - Common/leaked passwords
  - Strong valid passwords

Run with: python tests.py
"""

import math
from checker import evaluate, validate_rules, calculate_entropy, classify_entropy, SPECIAL_CHARS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS = "PASS"
FAIL = "FAIL"

def _check(label: str, condition: bool, results: list) -> None:
    status = PASS if condition else FAIL
    results.append((label, status))
    marker = "✔" if condition else "✘"
    print(f"  {marker}  {label:<55} {status}")

# ---------------------------------------------------------------------------
# Test groups
# ---------------------------------------------------------------------------
def test_hard_constraints(results: list) -> None:
    print("\n[1] Hard Constraint Gates")
    print("-" * 70)

    r = evaluate("abc")
    _check("Too short (3 chars) → Weak", r.strength == "Weak", results)

    r = evaluate("short1!")
    _check("Under 8 chars with complexity → Weak", r.strength == "Weak", results)

    r = evaluate("password")
    _check("Common password → Weak", r.strength == "Weak", results)

    r = evaluate("123456")
    _check("Common numeric → Weak", r.strength == "Weak", results)

    r = evaluate("admin123")
    _check("Common admin password → Weak", r.strength == "Weak", results)

    r = evaluate("qwerty123")
    _check("Common keyboard pattern → Weak", r.strength == "Weak", results)

def test_rule_validation(results: list) -> None:
    print("\n[2] Rule-Based Validation")
    print("-" * 70)

    rules = validate_rules("Hello123!")
    _check("Detects uppercase",  rules.uppercase,  results)
    _check("Detects lowercase",  rules.lowercase,  results)
    _check("Detects digit",      rules.digit,      results)
    _check("Detects special",    rules.special,    results)
    _check("Length >= 8",        rules.length,     results)
    _check("Not common",         rules.not_common, results)

    rules = validate_rules("ALLCAPS1!")
    _check("No lowercase detected correctly", not rules.lowercase, results)

    rules = validate_rules("nouppercase1!")
    _check("No uppercase detected correctly", not rules.uppercase, results)

    rules = validate_rules("NoDigitsHere!")
    _check("No digit detected correctly", not rules.digit, results)

    rules = validate_rules("NoSpecial123")
    _check("No special char detected correctly", not rules.special, results)

def test_entropy(results: list) -> None:
    print("\n[3] Entropy Calculation")
    print("-" * 70)

    # Only lowercase: charset=26, length=8 → 8 * log2(26) ≈ 37.6 bits
    entropy = calculate_entropy(8, 26)
    _check("8 lowercase chars → ~37.6 bits", abs(entropy - 37.60) < 0.1, results)

    _check("Entropy < 40 → Weak",   classify_entropy(35.0)  == "Weak",   results)
    _check("Entropy = 40 → Medium", classify_entropy(40.0)  == "Medium", results)
    _check("Entropy = 60 → Medium", classify_entropy(60.0)  == "Medium", results)
    _check("Entropy > 60 → Strong", classify_entropy(60.01) == "Strong", results)

    # Strong password should have high entropy
    r = evaluate("C0mpl3x!Pass#99")
    _check("Strong password entropy > 60 bits", r.entropy_bits > 60, results)

def test_strength_classification(results: list) -> None:
    print("\n[4] Strength Classification")
    print("-" * 70)

    cases = [
        ("alllowercase1",  "Weak",   "Lower + digit only → Weak"),
        ("Hello123",       "Medium", "Upper + lower + digit → Medium"),
        ("Hello!world",    "Medium", "Upper + lower + special → Medium"),
        ("alllower!1",     "Medium", "Lower + digit + special → Medium"),
        ("H3llo!World",    "Strong", "All 4 char types → Strong"),
        ("C0mpl3x!Pass",   "Strong", "Complex mixed → Strong"),
        ("Tr0ub4dor&3xYz", "Strong", "Long complex passphrase → Strong"),
    ]

    for pwd, expected, desc in cases:
        r = evaluate(pwd)
        _check(f"{desc}", r.strength == expected, results)

def test_edge_cases(results: list) -> None:
    print("\n[5] Edge Cases")
    print("-" * 70)

    r = evaluate("")
    _check("Empty string → Weak", r.strength == "Weak", results)

    r = evaluate("A" * 100)
    _check("100 identical uppercase chars → Weak (no variety)", r.strength == "Weak", results)

    r = evaluate("Aa1!" * 3)       # "Aa1!Aa1!Aa1!" — 12 chars, all types
    _check("Repeated pattern with all types → at least Medium",
           r.strength in ("Medium", "Strong"), results)

    r = evaluate("        ")       # 8 spaces
    _check("8 spaces → Weak (no char variety)", r.strength == "Weak", results)

    r = evaluate("P@ssw0rd")       # looks strong but is common-ish
    rules = validate_rules("P@ssw0rd")
    _check("P@ssw0rd not in common list (case-insensitive check works)",
           rules.not_common, results)

def test_feedback_completeness(results: list) -> None:
    print("\n[6] Evaluation Result Fields")
    print("-" * 70)

    r = evaluate("H3llo!World")
    _check("Result has entropy_bits field",  isinstance(r.entropy_bits, float),  results)
    _check("Result has entropy_label field", isinstance(r.entropy_label, str),   results)
    _check("Result has charset_size field",  isinstance(r.charset_size, int),    results)
    _check("Result has score field",         isinstance(r.score, int),           results)
    _check("Charset size > 0",               r.charset_size > 0,                 results)
    _check("Score between 0 and 5",          0 <= r.score <= 5,                  results)

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_all_tests() -> None:
    print("=" * 70)
    print("  Password Strength Evaluation — Test Suite")
    print("=" * 70)

    results: list[tuple[str, str]] = []

    test_hard_constraints(results)
    test_rule_validation(results)
    test_entropy(results)
    test_strength_classification(results)
    test_edge_cases(results)
    test_feedback_completeness(results)

    passed = sum(1 for _, s in results if s == PASS)
    failed = sum(1 for _, s in results if s == FAIL)
    total  = len(results)

    print("\n" + "=" * 70)
    print(f"  Results: {passed}/{total} passed", end="")
    if failed:
        print(f"  |  {failed} FAILED")
        for name, status in results:
            if status == FAIL:
                print(f"    ✘  {name}")
    else:
        print("  — All tests passed.")
    print("=" * 70)

if __name__ == "__main__":
    run_all_tests()
