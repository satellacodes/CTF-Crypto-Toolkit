# 🔐 CTF Crypto Toolkit

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-CTF-red?logo=keybase&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

> A powerful command-line Swiss Army knife for solving cryptography challenges in CTFs and cybersecurity competitions

## 📦 Features

| Module              | Description                                          | Status |
| ------------------- | ---------------------------------------------------- | ------ |
| **Base Encodings**  | Base64, Base32, Base16 encoding/decoding             | ✅     |
| **Caesar Cipher**   | Bruteforce or specific shift operations              | ✅     |
| **ROT Family**      | ROT-n transformations (ROT13, ROT47, etc.)           | ✅     |
| **Vigenère Cipher** | Decryption with known key or brute-force attempts    | ✅     |
| **XOR Cipher**      | Single-byte XOR bruteforce analysis                  | ✅     |
| **Affine Cipher**   | Solve affine cipher equations                        | ✅     |
| **RSA Operations**  | Decrypt RSA with given parameters or factorable n    | ✅     |
| **Hash Analysis**   | MD5, SHA1, SHA256 hashing and cracking via wordlists | ✅     |
| **Encoding Tools**  | URL encoding, HTML entities, character conversions   | ✅     |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/CTF-Crypto-Toolkit.git
cd CTF-Crypto-Toolkit

# Install dependencies
pip3 install pycryptodome

# Make the script executable
chmod +x ctf_crypto_tool.py
```

### Basic Usage

```bash
./ctf_crypto_tool.py <mode> [options]
```

## 💡 Usage Examples

### Base64 Decoding

```bash
./ctf_crypto_tool.py base --decode --type b64 --input "SGVsbG8gd29ybGQ="
```

**Output:** `Hello world`

### Caesar Cipher Bruteforce

```bash
./ctf_crypto_tool.py caesar --bruteforce --input "Khoor"
```

**Output:** All possible shifts with likelihood scoring

### XOR Analysis

```bash
./ctf_crypto_tool.py xor --bruteforce --input hex:"3a2f1b"
```

**Output:** Possible plaintexts ranked by character frequency

### Hash Cracking

```bash
./ctf_crypto_tool.py hash --crack --type md5 --hash "5d41402abc4b2a76b9719d911017c592" --wordlist rockyou.txt
```

**Output:** Found match: "hello"

## 📋 Command Reference

### Modes Overview

| Mode         | Command                                                      | Description            |
| ------------ | ------------------------------------------------------------ | ---------------------- |
| **base**     | `base --decode --type [b64/b32/b16] --input <text>`          | Base encoding/decoding |
| **caesar**   | `caesar --bruteforce --input <ciphertext>`                   | Caesar cipher analysis |
| **rot**      | `rot --n <value> --input <text>`                             | ROT-n transformation   |
| **vigenere** | `vigenere --decrypt --key <key> --input <ciphertext>`        | Vigenère decryption    |
| **xor**      | `xor --bruteforce --input [hex:]<data>`                      | XOR analysis           |
| **affine**   | `affine --solve --input <ciphertext>`                        | Affine cipher solver   |
| **rsa**      | `rsa --decrypt --n <value> --e <value> --ciphertext <value>` | RSA operations         |
| **hash**     | `hash --crack --type [md5/sha1/sha256] --hash <hash>`        | Hash cracking          |

### Input Formats

- **Plain text**: `--input "text"`
- **Hex**: `--input hex:"414243"`
- **Base64**: `--input b64:"QWxhZGRpbjpvcGVuIHNlc2FtZQ=="`
- **File**: `--input file:input.txt`

## 🛠️ Advanced Features

### Automated Mode Detection

```bash
# Tool attempts to identify cipher type
./ctf_crypto_tool.py auto --input <ciphertext>
```

### Chain Operations

```bash
# Multiple operations in sequence
./ctf_crypto_tool.py chain --operations "base64,rot13,xor" --input <data>
```

### Frequency Analysis

```bash
# Analyze ciphertext frequency
./ctf_crypto_tool.py analyze --frequency --input <ciphertext>
```

## 🧩 Supported CTF Challenge Types

- **Encoding/Decoding Challenges**
- **Classical Ciphers**
- **Modern Cryptography**
- **Steganography Encoding**
- **Forensic Data Extraction**
- **Network Packet Analysis**

## 📚 Learning Resources

When automated solving fails, the tool provides:

- **Hints** based on cipher characteristics
- **References** to common CTF techniques
- **Suggested tools** for further analysis
- **Educational explanations** of cryptographic concepts

## 🔧 Dependencies

```bash
# Required
pip3 install pycryptodome

# Optional (for extended features)
pip3 install numpy matplotlib  # For advanced frequency analysis
```

## 🐳 Docker Support

```bash
# Build and run with Docker
docker build -t ctf-crypto-toolkit .
docker run -it ctf-crypto-toolkit caesar --bruteforce --input "Khoor"
```

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## ⚠️ Legal Disclaimer

This tool is intended for:

- CTF competitions
- Educational purposes
- Security research with proper authorization

**Do not use for unauthorized access to systems or data.**

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/CTF-Crypto-Toolkit&type=Date)](https://star-history.com/#yourusername/CTF-Crypto-Toolkit&Date)

## 👨‍💻 Author

**Dimas Aris Pangestu** - Cybersecurity researcher and CTF enthusiast

[![Twitter](https://img.shields.io/badge/Twitter-@handle-blue?logo=twitter)](https://twitter.com/handle)
[![GitHub](https://img.shields.io/badge/GitHub-username-black?logo=github)](https://github.com/username)

---

**Made with ❤️ for the CTF community**

_If this tool helped you solve a challenge, consider giving it a star! ⭐_

---

## 🚨 Troubleshooting

### Common Issues

1. **Permission denied**: Run `chmod +x ctf_crypto_tool.py`
2. **Missing dependencies**: Run `pip3 install -r requirements.txt`
3. **Python version**: Ensure Python 3.8+ is installed

### Getting Help

```bash
# Display help
./ctf_crypto_tool.py --help

# Module-specific help
./ctf_crypto_tool.py caesar --help
```

---

**Happy Hacking! 🔓**
