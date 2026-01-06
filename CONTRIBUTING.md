# 🎯 Contributing Guidelines

Welcome to the **CTF Crypto Toolkit** project! We're excited that you want to contribute to this tool that helps cybersecurity activists and CTF players solve cryptographic challenges. This document explains how you can contribute effectively.

## 👥 Development Team

### Lead Maintainer

- **[satellacodes]** - Creator & Lead Developer
  - Role: Main architecture, core feature development, code review
  - Contact: [GitHub](https://github.com/satellacodes)
  - Specialization: Cryptography, CTF Challenges, Python Development
  - CTF Experience: [Your CTF team/experience if any]

### Contributors

_(This section will be populated as contributors join)_

## 📋 How to Contribute

### 1. Reporting Bugs 🐛

1. Check existing [Issues](https://github.com/satellacodes/CTF-Crypto-Toolkit/issues) first
2. Create a new issue using the bug report template:

```
**Bug Description:**
[Brief description of the bug]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Behavior:**
[What should have happened]

**Actual Behavior:**
[What actually happened]

**Environment:**
- OS: [e.g., Ubuntu 20.04]
- Python Version: [e.g., Python 3.9]
- Tool Version: [e.g., v1.0.0]

**Screenshots/Logs:**
[Paste error logs or add screenshots]
```

### 2. Suggesting New Features 💡

1. Create an issue with the "enhancement" label
2. Use the following template:

```
**Feature Request:**
[Feature name]

**Problem Solved:**
[What problem this feature solves]

**Proposed Solution:**
[How the feature would work]

**Usage Example:**
[Example command or usage]

**Alternatives Considered:**
[Any alternative solutions]

**Additional Context:**
[Any additional information]
```

### 3. Submitting Code 📦

#### Step-by-Step Process:

1. **Fork the repository**
2. **Clone your fork:**

```bash
git clone https://github.com/satellacodes/CTF-Crypto-Toolkit.git
cd CTF-Crypto-Toolkit
```

3. **Create a feature branch:**

```bash
git checkout -b type/feature-name
# Examples:
# - feat/add-des-cipher
# - fix/base64-padding
# - docs/update-examples
# - test/add-coverage
```

4. **Develop your feature**
5. **Test your changes:**

```bash
# Ensure no syntax errors
python3 -m py_compile ctf_crypto_tool.py

# Test with examples
./ctf_crypto_tool.py base --decode --type b64 --input "SGVsbG8="
```

6. **Commit your changes:**

```bash
git add .
git commit -m "type: brief description"
# Examples:
# "feat: add DES cipher implementation"
# "fix: handle edge case in caesar cipher"
# "docs: update installation instructions"
```

7. **Push to your fork:**

```bash
git push origin type/feature-name
```

8. **Create a Pull Request** to the main repository

## 📏 Code Standards

### Python Style Guide

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use 4 spaces for indentation (no tabs)
- Maximum 79 characters per line
- Use snake_case for functions and variables
- Use PascalCase for classes
- Add type hints for function signatures

### Example of Good Function Structure:

```python
def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
    """
    Implement Caesar Cipher encryption/decryption.

    Args:
        text: Text to encrypt/decrypt
        shift: Shift amount (0-25)
        decrypt: True for decryption, False for encryption

    Returns:
        Processed text

    Raises:
        ValueError: If shift is not in range 0-25
    """
    if not 0 <= shift <= 25:
        raise ValueError("Shift must be between 0 and 25")

    result = []
    for char in text:
        # Cipher implementation
        pass

    return ''.join(result)
```

### Documentation Requirements

Each function should have:

- Brief description
- Parameters with types
- Return value description
- Possible exceptions
- Examples if needed

## 🧪 Testing

### Before Submitting PR:

1. **Test your new function:**

```python
# Create simple tests
def test_your_function():
    result = your_function("input")
    assert result == "expected_output"
```

2. **Test edge cases:**
   - Empty input
   - Special characters
   - Numeric input
   - Very long input
   - Invalid input types

3. **Test backward compatibility:**
   - Ensure existing features still work
   - Changes don't break existing functionality

## 🔐 Security Guidelines

### Core Principles:

1. **Never implement production cryptography yourself**
   - Use well-tested libraries (pycryptodome, cryptography)
   - This tool is for education and CTF, not production systems

2. **Handle sensitive data properly:**
   - Don't log plaintext or keys
   - Clear sensitive data from memory after use
   - Use appropriate random number generators

3. **Validate all input:**
   - Always validate user input
   - Handle errors with graceful degradation
   - Sanitize output when necessary

### Secure Implementation Example:

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(plaintext: str, key: str) -> str:
    """
    AES Encryption (for CTF purposes only).

    WARNING: For CTF challenges only, not for production use.
    """
    # Input validation
    if not plaintext or not key:
        raise ValueError("Plaintext and key cannot be empty")

    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes")

    try:
        cipher = AES.new(key.encode(), AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        iv = cipher.iv
        return base64.b64encode(iv + ct_bytes).decode()
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {str(e)}")
```

## 📚 Documentation

### When Adding New Features:

1. **Update README.md:**
   - Add usage examples
   - Update features list
   - Add to command reference

2. **Update help text in code:**

```python
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CTF Crypto Toolkit - Tool for solving cryptography challenges"
    )
    # Add arguments for new feature
```

3. **Create example files** in `examples/` folder if needed

## 🏷️ Issue and PR Labels

### Issue Labels:

- `bug` - Bug report
- `enhancement` - New feature request
- `documentation` - Documentation improvement
- `good first issue` - Good for new contributors
- `help wanted` - Needs assistance
- `question` - Usage question
- `security` - Security-related issue

### PR Labels:

- `WIP` - Work in Progress (do not merge)
- `ready for review` - Ready for review
- `needs testing` - Requires additional testing
- `breaking change` - Major change affecting compatibility

## 🤝 Review Process

### What We Review:

1. **Code Quality:**
   - Follows style guide
   - Clear comments and documentation
   - Modular and reusable code

2. **Functionality:**
   - Feature works as described
   - Sufficient test coverage
   - Proper error handling

3. **Security:**
   - No potential vulnerabilities
   - Proper use of cryptography

4. **Documentation:**
   - README updated
   - Clear help text
   - Usage examples

### Review Timeline:

- **First 24 hours:** Initial maintainer check
- **3-7 days:** Review and feedback period
- **After fixes:** Merge to main branch

## 🌟 Contributor Recognition

Contributors will receive:

1. **Name in README.md** - Contributor list
2. **Credit in CHANGELOG.md** - For each release
3. **Special badge** on GitHub profile (for significant contributions)
4. **Invitation** to organization for consistent contributors

### Contributor Levels:

- **🥇 Gold Contributor:** 10+ merged PRs (significant features)
- **🥈 Silver Contributor:** 5-9 merged PRs (important improvements)
- **🥉 Bronze Contributor:** 1-4 merged PRs (initial contributions)

## ❓ Frequently Asked Questions

### Q: I'm new to Python, can I contribute?

**A:** Absolutely! Look for issues with `good first issue` or `documentation` labels. Documentation improvements or examples are very helpful.

### Q: What cryptographic features can I add?

**A:** Classic ciphers (Playfair, Hill), encoding methods (base85, ascii85), or analysis tools (frequency analysis, index of coincidence).

### Q: What if I'm unsure about my implementation?

**A:** Create a PR with the `WIP` label and discuss in the PR description. We'll help you.

### Q: Are there other communication channels?

**A:** Currently, we use GitHub Issues and Discussions only.

## 📞 Contact Maintainer

- **GitHub Issues:** For bug reports and feature requests
- **GitHub Discussions:** For general discussion and questions
- **Email:** [dimasarisp52@gmail.com] (only for urgent security issues)

---

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).

**Thank you for helping make this tool better for the global CTF community!** 🔐🚀

---

_This document is inspired by CONTRIBUTING.md files from various open-source projects and adapted for the CTF Crypto Toolkit._
