# Password Strength Evaluation System

A modular, production-style password evaluation tool built as part of a cybersecurity training program.
Combines rule-based validation with entropy analysis to assess password strength — the same dual-signal
approach used in real-world security tooling.

---

## Architecture

```
password_checker/
├── checker.py   # Core evaluation engine (logic only, no I/O)
├── main.py      # Secure CLI interface
├── tests.py     # Comprehensive test suite (40 cases)
└── README.md
```

Each layer is fully independent. `checker.py` has zero I/O concerns — it can be imported into any
interface (CLI, web API, GUI) without modification.

---

## How It Works

### Dual-Signal Evaluation

Every password is assessed on two independent axes:

| Signal | Method | Thresholds |
|---|---|---|
| Rule score | Charset presence + length + common-password check | Weak / Medium / Strong |
| Entropy | `length × log₂(charset_size)` | < 40 bits = Weak, 40–60 = Medium, > 60 = Strong |

The final classification is the **conservative minimum** of both signals. A long but simple password
(e.g. `aaaaaaaaaaaaaaaa`) cannot score Strong on rules alone — entropy will pull it down.

### Hard Constraints (always Weak, no exceptions)

- Password length < 8
- Password matches the common/leaked password dataset

### Rule Score (0–4 character criteria)

| Score | Label |
|---|---|
| 0–2 | Weak |
| 3 | Medium |
| 4 | Strong |

Character criteria: uppercase, lowercase, digit, special character.

### Entropy Thresholds

| Bits | Label |
|---|---|
| < 40 | Weak |
| 40–60 | Medium |
| > 60 | Strong |

---

## Performance

All character-class detection runs in a **single O(n) pass** with early exit — once all four
character types are found, the loop terminates immediately. No regex, no redundant scans.

```python
# Early-exit scan — stops as soon as all categories are confirmed
for c in password:
    if not has_upper   and c.isupper():        has_upper   = True
    if not has_lower   and c.islower():        has_lower   = True
    if not has_digit   and c.isdigit():        has_digit   = True
    if not has_special and c in SPECIAL_CHARS: has_special = True
    if has_upper and has_lower and has_digit and has_special:
        break
```

Common-password lookup is O(1) via `frozenset`.

---

## Security Design

| Concern | Mitigation |
|---|---|
| Terminal echo | Input via `getpass` — password never printed |
| Plaintext logging | No logging calls anywhere in the codebase |
| In-memory exposure | Password reference explicitly `del`-ed after evaluation |
| Timing side-channels | `frozenset` lookup is constant-time for the common-password check |
| Sensitive data leakage | `EvaluationResult` stores no password data — only derived metrics |

---

## Usage

```bash
cd password_checker
python main.py
```

```
==================================================
   Password Strength Evaluation System
   Cybersecurity Training Tool
==================================================
  Passwords are not stored or logged.

  Enter password (Ctrl+C to quit):

  Strength  :  [+] STRONG
  Entropy   :  [████████████████░░░░░░░░░░░░░░] 72.1 bits
  Charset   :  94 possible characters
  Score     :  5/5 criteria met

  Rule Checklist:
  ✔  Minimum 8 characters
  ✔  Uppercase letter (A-Z)
  ✔  Lowercase letter (a-z)
  ✔  Number (0-9)
  ✔  Special character (!@#$...)
  ✔  Not a known/leaked password

  Recommendations:
    • Password meets all requirements. Well done.
```

---

## Running Tests

```bash
python tests.py
```

40 test cases across 6 categories:

| # | Category | Cases |
|---|---|---|
| 1 | Hard constraint gates | 6 |
| 2 | Rule-based validation | 10 |
| 3 | Entropy calculation | 6 |
| 4 | Strength classification | 7 |
| 5 | Edge cases | 5 |
| 6 | Result integrity | 6 |

---

## Using the Core Engine Directly

`checker.py` exposes a clean public API:

```python
from checker import evaluate, validate_rules, calculate_entropy, classify_entropy

# Full evaluation
result = evaluate("H3llo!World")
print(result.strength)       # "Strong"
print(result.entropy_bits)   # 72.1
print(result.score)          # 5

# Rule check only
rules = validate_rules("Hello123")
print(rules.uppercase)       # True
print(rules.special)         # False

# Entropy only
bits = calculate_entropy(12, 94)
print(classify_entropy(bits)) # "Strong"
```

### `EvaluationResult` fields

| Field | Type | Description |
|---|---|---|
| `strength` | `str` | Final label: Weak / Medium / Strong |
| `entropy_bits` | `float` | Calculated entropy in bits |
| `entropy_label` | `str` | Entropy-only classification |
| `rules` | `RuleResult` | Per-criterion boolean results |
| `charset_size` | `int` | Effective character pool size |
| `score` | `int` | Number of criteria met (0–5) |

---

## Requirements

- Python 3.10+ (uses `NamedTuple`, `frozenset`, `match`-compatible type hints)
- No external dependencies — standard library only

---

## Team

| Role | Responsibility |
|---|---|
| Core Logic | `checker.py` — evaluation engine, entropy, rule validation |
| Testing | `tests.py` — 40-case test suite across all evaluation dimensions |
| Interface | `main.py` — secure CLI, output formatting, feedback engine |
