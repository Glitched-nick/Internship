# 🔐 Password Strength Checker
### Cybersecurity Project 1 — DecodeLabs Internship

A secure, efficient, and modular Password Strength Evaluation System built as part of the **DecodeLabs Cybersecurity Internship (2026)**.

This project goes beyond basic validation by combining rule-based checks with entropy-based analysis, simulating real-world password security evaluation systems.

---

## 📌 Features

- ✅ Rule-based password validation
- ✅ Entropy-based strength calculation
- ✅ Detection of common/weak passwords
- ✅ Actionable feedback for improvement
- ✅ Secure input handling (no password echo)
- ✅ O(n) time complexity (single-pass evaluation)
- ✅ 40 comprehensive test cases

---

## 🧠 How It Works

### 🔹 Dual-Signal Model

The system evaluates password strength using two approaches:

**Rule-Based Validation**
- Minimum length (≥ 8 characters)
- Uppercase letters
- Lowercase letters
- Digits
- Special characters
- Common password detection

**Entropy-Based Analysis**
```
entropy = length × log2(character_set_size)
```

### 🔹 Final Classification

The final password strength is determined using a conservative approach:

> The **minimum** of rule-based score and entropy classification is selected.
> This prevents weak patterns from being misclassified as strong.

---

## 📊 Strength Classification

| Strength | Criteria |
|---|---|
| Weak | Fails length OR common password OR very low entropy |
| Medium | Meets some criteria with moderate entropy |
| Strong | Meets all criteria with high entropy |

---

## 📁 Project Structure

```
password_checker/
├── checker.py       # Core evaluation logic
├── tests.py         # Test suite (40 cases)
└── main.py          # CLI interface
```

---

## ⚙️ Installation & Usage

### 🔹 Clone Repository
```bash
git clone https://github.com/Glitched-nick/Internship.git
cd password_checker
```

### 🔹 Run Application
```bash
python main.py
```

### 🔹 Run Tests
```bash
python tests.py
```

---

## 🔐 Security Considerations

| Concern | Mitigation |
|---|---|
| Password exposure | Uses `getpass` (no terminal echo) |
| Plaintext storage | No logging or persistence |
| Timing risks | Efficient single-pass evaluation |
| Weak passwords | Common password detection |

---

## ⚡ Performance

- **Time Complexity:** O(n) (single-pass scan)
- Early-exit optimization for character checks
- No redundant computations

---

## 🧪 Testing

✅ 40 test cases covering:
- Edge cases (empty, spaces, repeated chars)
- Weak/common passwords
- Strong passwords
- Entropy correctness
- Output validation

```bash
python tests.py
```

---

## 📸 Example Output

```
Password: ********

  Strength  :  [~] MEDIUM
  Entropy   :  [███████████░░░░░░░░░░░░░░░░░░░] 52.3 bits
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
    • Entropy is moderate (52.3 bits). Consider a longer passphrase for better security.
```

---

## 👥 Team & Contribution

Developed as part of **DecodeLabs Cybersecurity Internship**.

- **Core Logic** — Password evaluation engine
- **Testing** — Comprehensive validation suite
- **UI** — CLI interface and feedback system

---

## 🚀 Future Improvements

- Web-based UI (Vercel deployment)
- Integration with leaked password databases (HIBP-style)
- API-based password strength service
- Advanced pattern detection (keyboard patterns, sequences)

---

## 📄 License

This project is for educational and internship purposes.

---

## ⭐ Acknowledgment

Special thanks to **DecodeLabs** for providing structured cybersecurity training and hands-on project experience.

---

> 💡 **Key Takeaway:** Strong security starts with strong validation. This project demonstrates how simple logic, when designed correctly, can significantly improve user security.
