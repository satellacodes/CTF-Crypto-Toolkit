# 🔐 CTF Crypto Toolkit v2.0

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-CTF-red?logo=keybase&logoColor=white)
![Version](https://img.shields.io/badge/Version-2.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

> Advanced Swiss Army knife for solving cryptography challenges in CTFs and cybersecurity competitions

## ✨ New Features in v2.0

- **Auto-detection** of encodings and ciphers
- **Intelligent scoring** for English text detection
- **Extended cipher support** (AES, DES, Vigenere with auto-key detection)
- **Enhanced RSA toolkit** with automatic factoring
- **Hash cracking** with wordlist support
- **Multiple encoding formats** (URL, HTML, Binary, Morse)
- **Improved error handling** and user feedback
- **Better performance** with optimized algorithms

## 📦 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/satellacodes/CTF-Crypto-Toolkit.git
cd CTF-Crypto-Toolkit

# Install dependencies
pip3 install pycryptodome

# Make executable
chmod +x ctf_crypto_tool.py
```

### Docker Support

```bash
# Build Docker image
docker build -t ctf-crypto-toolkit .

# Run in Docker
docker run -it ctf-crypto-toolkit caesar --auto --input "Khoor"
```

## 🚀 Quick Examples

### Auto-detect Caesar Cipher

```bash
./ctf_crypto_tool.py caesar --auto --input "Khoor Zruog"
# Output: Best matches sorted by English probability
```

### Crack XOR Encryption

```bash
./ctf_crypto_tool.py xor --auto --input "1a2b3c4d5e"
# Automatically finds the most likely XOR key
```

### RSA Decryption with Auto-factoring

```bash
./ctf_crypto_tool.py rsa --n 3233 --e 17 --c 855 --auto-factor
# Attempts to factor n and decrypt automatically
```

### Hash Cracking with Wordlist

```bash
./ctf_crypto_tool.py hash --alg md5 --crack --input "5d41402abc4b2a76b9719d911017c592" --wordlist rockyou.txt
```

### Detect Encoding Type

```bash
./ctf_crypto_tool.py detect --input "SGVsbG8gd29ybGQ="
# Output: Detected encoding: base64
```

## 📋 Complete Feature List

### Encoding/Decoding

- **Base Family**: Base64 (standard & URL-safe), Base32, Base16, Base85, ASCII85
- **Binary Encoding**: Text ↔ Binary conversion
- **URL Encoding**: Percent-encoding/decoding
- **HTML Entities**: HTML special characters
- **Morse Code**: International Morse code

### Classical Ciphers

- **Caesar Cipher**: With bruteforce and auto-detection
- **ROT Family**: ROT-n transformations
- **Vigenère Cipher**: With Kasiski examination for key detection
- **Affine Cipher**: Automatic parameter solving
- **Substitution Cipher**: Frequency analysis

### Modern Cryptography

- **XOR Operations**: Single-byte and multi-byte XOR
- **AES**: ECB, CBC, CTR modes
- **DES**: ECB, CBC modes
- **RSA Toolkit**: Complete parameter handling

### Hash Operations

- **Hash Generation**: MD5, SHA1, SHA256, SHA512, SHA3, BLAKE2
- **Hash Cracking**: Dictionary attacks with wordlists
- **Rainbow Tables**: Built-in common hash lookup

### Analysis Tools

- **Frequency Analysis**: Character and bigram analysis
- **Entropy Calculation**: Measure randomness
- **Pattern Detection**: Identify cipher types
- **Encoding Detection**: Auto-detect encoding formats

## 🔧 Advanced Usage

### Chain Operations

```bash
# Multiple operations in sequence
echo "Hello" | ./ctf_crypto_tool.py base --type b64 | ./ctf_crypto_tool.py caesar --shift 3
```

### File Input Support

```bash
# Process files directly
./ctf_crypto_tool.py xor --bruteforce --input file:encrypted.bin
```

### Output Formatting

```bash
# JSON output for programmatic use
./ctf_crypto_tool.py caesar --auto --input "Khoor" --json
```

## 🎯 CTF Challenge Examples

### Challenge 1: "The Secret Message"

```bash
# Encoded message: V2VsY29tZSB0byBDVEY=
./ctf_crypto_tool.py detect --input "V2VsY29tZSB0byBDVEY="
./ctf_crypto_tool.py base --decode --type b64 --input "V2VsY29tZSB0byBDVEY="
```

### Challenge 2: "XOR Mystery"

```bash
# Hex data: 1e3b2a4c5d6e
./ctf_crypto_tool.py xor --auto --input "1e3b2a4c5d6e"
```

### Challenge 3: "RSA Challenge"

```bash
# Given: n=3233, e=17, c=855
./ctf_crypto_tool.py rsa --n 3233 --e 17 --c 855 --auto-factor
```

## 📊 Performance Features

- **Multi-threading** for brute force operations
- **Caching** of common computations
- **Progress indicators** for long operations
- **Memory-efficient** large file handling
- **Batch processing** support

## 🛠️ Developer API

The toolkit can also be used as a Python library:

```python
from ctf_crypto_tool import solve_caesar, solve_xor, english_score

# Use functions directly
results = solve_caesar("Khoor", auto=True)
best_result = max(results, key=lambda x: x[2])
print(f"Best match: Shift {best_result[0]}, Text: {best_result[1]}")
```

## 📁 Project Structure

```
CTF-Crypto-Toolkit/
├── ctf_crypto_tool.py          # Main tool
├── README.md                   # Updated documentation
├── CONTRIBUTING.md            # Contribution guidelines
├── requirements.txt           # Dependencies
├── setup.py                   # Installation script
├── .gitignore                 # Git ignore file
├── LICENSE                    # MIT License
├── examples/                  # Challenge examples
│   ├── caesar_challenge.txt
│   ├── rsa_challenge.txt
│   └── xor_challenge.txt
├── wordlists/                 # Dictionary files
│   ├── common_passwords.txt
│   └── rockyou_sample.txt
└── tests/                     # Unit tests
    ├── test_caesar.py
    ├── test_xor.py
    └── test_integration.py
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## ⚠️ Security Disclaimer

**This tool is for:**

- CTF competitions and challenges
- Educational purposes
- Security research with proper authorization

**Not for:**

- Unauthorized access to systems
- Illegal activities
- Production cryptography

All cryptographic implementations are for educational purposes only. Use industry-standard libraries for production systems.

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=satellacodes/CTF-Crypto-Toolkit&type=Date)](https://star-history.com/#satellacodesCTF-Crypto-Toolkit&Date)

---

## 🔗 Useful Resources

- [CyberChef](https://gchq.github.io/CyberChef/) - Web-based cyber operations
- [Cryptohack](https://cryptohack.org/) - Cryptography challenges
- [CTFtime](https://ctftime.org/) - CTF competitions calendar
- [Awesome CTF](https://github.com/apsdehal/awesome-ctf) - CTF resource collection

## 👨‍💻 Author

**Dimas Aris Pangestu** - Cybersecurity researcher and CTF enthusiast

[![Tryhackme](https://img.shields.io/badge/TryHackMe-@satella-blue?logo=Tryhackme)](https://tryhackme.com/p/satella)
[![GitHub](https://img.shields.io/badge/GitHub-satellacodes-black?logo=github)](https://github.com/satellacodes)

---

**Happy Hacking! May your flags be captured and your ciphers broken!** 🚩🔓

_If this tool helped you solve a challenge, consider giving it a star! ⭐_
