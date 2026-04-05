"""
main.py — CLI interface for the Password Strength Evaluation System.

Handles secure input, formatted output, and actionable feedback.
Passwords are never stored or logged.
"""

import getpass
from checker import evaluate, EvaluationResult

# ---------------------------------------------------------------------------
# Display config
# ---------------------------------------------------------------------------
STRENGTH_BADGE = {
    "Weak":   "[-] WEAK",
    "Medium": "[~] MEDIUM",
    "Strong": "[+] STRONG",
}

CRITERIA_LABELS = {
    "length":     "Minimum 8 characters",
    "uppercase":  "Uppercase letter (A-Z)",
    "lowercase":  "Lowercase letter (a-z)",
    "digit":      "Number (0-9)",
    "special":    "Special character (!@#$...)",
    "not_common": "Not a known/leaked password",
}

ENTROPY_BAR_WIDTH = 30

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def _entropy_bar(bits: float) -> str:
    """Visual entropy bar scaled to 128 bits max."""
    filled = min(int((bits / 128) * ENTROPY_BAR_WIDTH), ENTROPY_BAR_WIDTH)
    bar    = "█" * filled + "░" * (ENTROPY_BAR_WIDTH - filled)
    return f"[{bar}] {bits:.1f} bits"

def _format_rules(result: EvaluationResult) -> str:
    lines = []
    for key, passed in result.rules._asdict().items():
        mark  = "✔" if passed else "✘"
        label = CRITERIA_LABELS[key]
        lines.append(f"  {mark}  {label}")
    return "\n".join(lines)

def _build_feedback(result: EvaluationResult) -> list[str]:
    tips = []
    rules = result.rules

    if not rules.length:
        tips.append("Use at least 8 characters.")
    if not rules.not_common:
        tips.append("Avoid commonly used or leaked passwords.")
    if not rules.uppercase:
        tips.append("Add at least one uppercase letter (A-Z).")
    if not rules.lowercase:
        tips.append("Add at least one lowercase letter (a-z).")
    if not rules.digit:
        tips.append("Include at least one digit (0-9).")
    if not rules.special:
        tips.append("Include a special character (e.g. !@#$%^&*).")

    if result.entropy_bits < 40:
        tips.append(
            f"Entropy is low ({result.entropy_bits:.1f} bits). "
            "Increase length or use more character variety."
        )
    elif result.entropy_bits < 60:
        tips.append(
            f"Entropy is moderate ({result.entropy_bits:.1f} bits). "
            "Consider a longer passphrase for better security."
        )

    if not tips:
        tips.append("Password meets all requirements. Well done.")

    return tips

def _print_result(result: EvaluationResult) -> None:
    badge = STRENGTH_BADGE[result.strength]

    print(f"\n  Strength  :  {badge}")
    print(f"  Entropy   :  {_entropy_bar(result.entropy_bits)}")
    print(f"  Charset   :  {result.charset_size} possible characters")
    print(f"  Score     :  {result.score}/5 criteria met\n")

    print("  Rule Checklist:")
    print(_format_rules(result))

    print("\n  Recommendations:")
    for tip in _build_feedback(result):
        print(f"    • {tip}")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 50)
    print("   Password Strength Evaluation System")
    print("   Cybersecurity Training Tool")
    print("=" * 50)
    print("  Passwords are not stored or logged.\n")

    while True:
        try:
            # getpass masks input — avoids shoulder-surfing and terminal logs
            password = getpass.getpass("  Enter password (Ctrl+C to quit): ")
        except (KeyboardInterrupt, EOFError):
            print("\n  Session ended.")
            break

        if not password:
            print("  Please enter a password.\n")
            continue

        result = evaluate(password)
        _print_result(result)

        # Explicitly delete reference — minimise in-memory exposure
        del password
        print("-" * 50)

if __name__ == "__main__":
    main()
