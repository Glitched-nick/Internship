# 🔐 Password Strength Evaluation System

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Security-Cybersecurity-red?style=for-the-badge&logo=shield&logoColor=white"/>
  <img src="https://img.shields.io/badge/Tests-40%2F40%20Passing-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Complexity-O(n)-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Internship-DecodeLabs%202026-purple?style=for-the-badge"/>
</p>

<p align="center">
  A production-style password evaluation system built during the <strong>DecodeLabs Cybersecurity Internship (2026)</strong>.<br/>
  Combines rule-based validation with entropy analysis to assess password strength — the same dual-signal approach used in real-world security tooling.
</p>

---

## � Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [How It Works](#-how-it-works)
- [Strength Classification](#-strength-classification)
- [Security Design](#-security-design)
- [Performance](#-performance)
- [Installation & Usage](#-installation--usage)
- [Example Output](#-example-output)
- [Test Suite](#-test-suite)
- [Future Roadmap](#-future-roadmap)
- [Team](#-team)

---

## � Overview

Most password checkers apply simple rule checks — length, uppercase, digits. This system goes further by treating password strength as a **dual-signal problem**:

1. **Rule-based validation** — checks character composition and known weak passwords
2. **Entropy analysis** — measures the theoretical unpredictability of the password

The final classification is the **conservative minimum** of both signals. A long but repetitive password cannot score Strong on entropy alone if it fails character diversity rules — and vice versa.

This mirrors how enterprise security tools (password managers, IAM systems) evaluate credentials in production environments.

---

## 📌 Features

| Feature | Details |
|---|---|
| Rule-based validation | Length, charset diversity, common password detection |
| Entropy scoring | `length × log₂(charset_size)` — real information-theoretic metric |
| Dual-signal classification | Conservative minimum of rule score and entropy label |
| Common password detection | Predefined dataset of known/leaked passwords (frozenset, O(1) lookup) |
| Secure input | `getpass` — no terminal echo, no shell history exposure |
| No data retention | Passwords never logged, stored, or persisted |
| Actionable feedback | Specific, targeted improvement suggestions per evaluation |
| O(n) performance | Single-pass scan with early-exit optimization |
| 40 test cases | Full coverage across 6 test categories |
| Zero dependencies | Standard library only — no pip installs required |

---

## 🏗 System Architecture

```
Internship/
└── password_checker/
    ├── checker.py     ← Core evaluation engine  (logic only, zero I/O)
    ├── main.py        ← Secure CLI interface
    └── tests.py       ← Comprehensive test suite
```

Each layer is fully decoupled. `checker.py` has no I/O concerns and can be imported into any interface — CLI, REST API, or web frontend — without modification.

```
User Input (getpass)
       │
       ▼
  [ main.py ]  ──────────────────────────────────────────┐
       │                                                  │
       ▼                                                  ▼
  [ checker.py ]                                   Format & Display
       │                                            Strength Badge
       ├── validate_rules()   → RuleResult          Entropy Bar
       ├── calculate_entropy()→ float               Criteria Checklist
       ├── classify_entropy() → label               Recommendations
       └── evaluate()         → EvaluationResult
```

---

## 🧠 How It Works

### Rule-Based Validation

Each password is checked against 6 criteria:

| Criterion | Check |
|---|---|
| Length | `len(password) >= 8` |
| Uppercase | At least one `A–Z` character |
| Lowercase | At least one `a–z` character |
| Digit | At least one `0–9` character |
| Special character | At least one from `!@#$%^&*()...` |
| Not common | Not present in the known weak password dataset |

### Entropy-Based Analysis

```
entropy (bits) = length × log₂(character_set_size)
```

The character set size is derived from which character classes are present:

| Class | Pool Size |
|---|---|
| Lowercase (a–z) | 26 |
| Uppercase (A–Z) | 26 |
| Digits (0–9) | 10 |
| Special characters | 32 |
| Full mixed charset | 94 |

### Dual-Signal Classification

```
final_strength = min(rule_label, entropy_label)
```

Both signals must independently agree on a rating. This prevents:
- A long but simple password (e.g. `aaaaaaaaaaaaa`) from scoring Strong via entropy
- A complex but short password from bypassing the length hard gate

### Hard Constraints

These always result in **Weak**, regardless of other criteria:

- Password length < 8
- Password found in the common/leaked password dataset

---

## � Strength Classification

### Rule Score

| Character Criteria Met | Label |
|---|---|
| 0 – 2 | Weak |
| 3 | Medium |
| 4 | Strong |

### Entropy Thresholds

| Entropy | Label |
|---|---|
| < 40 bits | Weak |
| 40 – 60 bits | Medium |
| > 60 bits | Strong |

### Real Examples

| Password | Entropy | Rule Score | Final |
|---|---|---|---|
| `password` | 37.6 bits | — | **Weak** (common) |
| `Hello123` | 47.6 bits | 3/4 | **Medium** |
| `H3llo!World` | 72.1 bits | 4/4 | **Strong** |
| `Tr0ub4dor&3xYz` | 85.2 bits | 4/4 | **Strong** |
| `aaaaaaaaaaaaa` | 46.1 bits | 1/4 | **Weak** (rule gate) |

---

## 🔐 Security Design

| Threat | Mitigation |
|---|---|
| Terminal exposure | Input via `getpass` — password never echoed or printed |
| Plaintext logging | Zero logging calls in the entire codebase |
| In-memory persistence | Password reference explicitly `del`-ed after evaluation |
| Timing side-channels | `frozenset` lookup for common passwords is O(1) constant-time |
| Sensitive data in results | `EvaluationResult` stores only derived metrics — never the password itself |
| Shoulder surfing | Masked input prevents visual interception |

---

## ⚡ Performance

**Time Complexity: O(n)** — where n is the password length.

The character scan uses a single loop with **early-exit** — once all four character classes are detected, iteration stops immediately:

```python
for c in password:
    if not has_upper   and c.isupper():        has_upper   = True
    if not has_lower   and c.islower():        has_lower   = True
    if not has_digit   and c.isdigit():        has_digit   = True
    if not has_special and c in SPECIAL_CHARS: has_special = True
    if has_upper and has_lower and has_digit and has_special:
        break  # all classes found — stop scanning
```

Common password lookup is **O(1)** via `frozenset` hash lookup — no linear search.

No regex. No redundant passes. No recomputation between functions.

---

## ⚙️ Installation & Usage

### Requirements

- Python 3.10+
- No external dependencies

### Clone

```bash
git clone https://github.com/Glitched-nick/Internship.git
cd Internship/password_checker
```

### Run

```bash
python main.py
```

### Test

```bash
python tests.py
```

### Use the API directly

```python
from checker import evaluate

result = evaluate("H3llo!World")

print(result.strength)      # "Strong"
print(result.entropy_bits)  # 72.1
print(result.score)         # 5
print(result.rules.special) # True
```

---

## 📸 Example Output

```
==================================================
   Password Strength Evaluation System
   Cybersecurity Training Tool
==================================================
  Passwords are not stored or logged.

  Enter password (Ctrl+C to quit):

  Strength  :  [~] MEDIUM
  Entropy   :  [███████████░░░░░░░░░░░░░░░░░░░] 47.6 bits
  Charset   :  62 possible characters
  Score     :  4/5 criteria met

  Rule Checklist:
  ✔  Minimum 8 characters
  ✔  Uppercase letter (A-Z)
  ✔  Lowercase letter (a-z)
  ✔  Number (0-9)
  ✘  Special character (!@#$...)
  ✔  Not a known/leaked password

  Recommendations:
    • Include a special character (e.g. !@#$%^&*).
    • Entropy is moderate (47.6 bits). Consider a longer passphrase for better security.
--------------------------------------------------
```

---

## 🧪 Test Suite

```bash
python tests.py
```

| # | Category | Cases |
|---|---|---|
| 1 | Hard constraint gates | 6 |
| 2 | Rule-based validation | 10 |
| 3 | Entropy calculation & thresholds | 6 |
| 4 | Strength classification | 7 |
| 5 | Edge cases | 5 |
| 6 | Result integrity | 6 |
| | **Total** | **40 / 40 ✅** |

---

## 🚀 Future Roadmap

- [ ] Integration with HaveIBeenPwned API (real leaked password database)
- [ ] Web-based UI with live strength meter
- [ ] REST API wrapper for integration into other services
- [ ] Advanced pattern detection (keyboard walks, sequences, l33tspeak)
- [ ] Passphrase entropy model (word-based passwords)

---

## � Team

| Role | Responsibility |
|---|---|
| Core Logic | `checker.py` — evaluation engine, entropy, rule validation |
| Testing | `tests.py` — 40-case test suite across all evaluation dimensions |
| Interface | `main.py` — secure CLI, output formatting, feedback engine |

Developed as part of the **DecodeLabs Cybersecurity Internship (2026)**.

---

## 📄 License

This project is for educational and internship purposes only.

---

<p align="center">
  <em>Strong security starts with strong validation.</em>
</p>
