"""
checker.py — Core password strength evaluation engine.

Combines rule-based validation with entropy analysis.
All character scans run in O(n) — no redundant iterations.

Security note: passwords are never logged or stored.
"""

import math
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Common / leaked password dataset (predefined, lowercase-normalised)
# ---------------------------------------------------------------------------
COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "password1", "password123", "passw0rd",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwertyuiop",
    "abc123", "abcdef", "abcd1234",
    "letmein", "welcome", "welcome1",
    "admin", "admin123", "administrator",
    "iloveyou", "monkey", "dragon", "master",
    "sunshine", "princess", "shadow", "superman",
    "trustno1", "football", "baseball", "soccer",
    "michael", "jessica", "ashley", "bailey",
    "000000", "111111", "222222", "123123", "654321",
    "pass", "test", "guest", "login", "root",
})

# ---------------------------------------------------------------------------
# Character-set size lookup — used for entropy calculation
# ---------------------------------------------------------------------------
_CHARSET_SIZES = {
    "lowercase": 26,
    "uppercase": 26,
    "digit":     10,
    "special":   32,   # printable ASCII specials
}

SPECIAL_CHARS: frozenset[str] = frozenset("!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
class RuleResult(NamedTuple):
    length:     bool
    uppercase:  bool
    lowercase:  bool
    digit:      bool
    special:    bool
    not_common: bool

class EvaluationResult(NamedTuple):
    strength:       str          # "Weak" | "Medium" | "Strong"
    entropy_bits:   float
    entropy_label:  str          # "Weak" | "Medium" | "Strong"
    rules:          RuleResult
    charset_size:   int
    score:          int          # 0-5 rule score

# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------
def _charset_size(rules: RuleResult) -> int:
    """
    Derive the effective character-set size from which rule types are present.
    O(1) — fixed number of checks.
    """
    size = 0
    if rules.lowercase: size += _CHARSET_SIZES["lowercase"]
    if rules.uppercase: size += _CHARSET_SIZES["uppercase"]
    if rules.digit:     size += _CHARSET_SIZES["digit"]
    if rules.special:   size += _CHARSET_SIZES["special"]
    return max(size, 1)   # guard against log(0)

def calculate_entropy(length: int, charset_size: int) -> float:
    """
    Shannon-inspired password entropy estimate.
    entropy = length × log2(charset_size)
    """
    return length * math.log2(charset_size)

def classify_entropy(bits: float) -> str:
    if bits < 40:
        return "Weak"
    if bits <= 60:
        return "Medium"
    return "Strong"

# ---------------------------------------------------------------------------
# Rule-based validation — single O(n) pass
# ---------------------------------------------------------------------------
def _scan(password: str) -> tuple[bool, bool, bool, bool]:
    """
    Single pass over the password to detect character categories.
    Returns (has_upper, has_lower, has_digit, has_special).
    """
    has_upper = has_lower = has_digit = has_special = False
    for c in password:
        if not has_upper   and c.isupper():          has_upper   = True
        if not has_lower   and c.islower():          has_lower   = True
        if not has_digit   and c.isdigit():          has_digit   = True
        if not has_special and c in SPECIAL_CHARS:   has_special = True
        if has_upper and has_lower and has_digit and has_special:
            break   # early exit — all categories found
    return has_upper, has_lower, has_digit, has_special

def validate_rules(password: str) -> RuleResult:
    """O(n) rule validation with early-exit optimisation."""
    has_upper, has_lower, has_digit, has_special = _scan(password)
    return RuleResult(
        length     = len(password) >= 8,
        uppercase  = has_upper,
        lowercase  = has_lower,
        digit      = has_digit,
        special    = has_special,
        not_common = password.lower() not in COMMON_PASSWORDS,
    )

# ---------------------------------------------------------------------------
# Strength classification
# ---------------------------------------------------------------------------
def _rule_score(rules: RuleResult) -> int:
    """Count how many of the 5 core criteria are satisfied (0–5)."""
    return sum([rules.uppercase, rules.lowercase, rules.digit, rules.special,
                rules.length])

def evaluate(password: str) -> EvaluationResult:
    """
    Full evaluation: rules + entropy → final strength label.

    Hard constraints (always Weak):
      • length < 8
      • password is in common/leaked list

    Final classification uses the LOWER of entropy_label and rule_label,
    ensuring both dimensions must be satisfied for a higher rating.
    """
    rules        = validate_rules(password)
    charset      = _charset_size(rules)
    entropy      = calculate_entropy(len(password), charset)
    entropy_lbl  = classify_entropy(entropy)
    score        = _rule_score(rules)

    # Hard gates
    if not rules.length or not rules.not_common:
        return EvaluationResult("Weak", entropy, entropy_lbl, rules, charset, score)

    # Rule label derived from score (excluding length, already passed)
    char_score = sum([rules.uppercase, rules.lowercase, rules.digit, rules.special])
    if char_score <= 2:
        rule_lbl = "Weak"
    elif char_score == 3:
        rule_lbl = "Medium"
    else:
        rule_lbl = "Strong"

    # Final = conservative combination of both signals
    rank = {"Weak": 0, "Medium": 1, "Strong": 2}
    final = min(rule_lbl, entropy_lbl, key=lambda x: rank[x])

    return EvaluationResult(final, entropy, entropy_lbl, rules, charset, score)
