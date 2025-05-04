# CTF-Crypto-Toolkit

#!/usr/bin/env python3
"""
CTF Crypto Toolkit

A command-line tool for solving common cryptography challenges in CTFs.
Covers: Base encodings, Caesar, ROT, Vigenere, XOR, Affine, RSA (small), MD5/SHA hashes, URL/HTML entities.

Usage:
chmod +x ctf_crypto_tool.py
./ctf_crypto_tool.py <mode> [options]

Modes:
base Encode/decode Base64, Base32, Base16
caesar Bruteforce or shift-specific Caesar cipher
rot ROT-n transformation
vigenere Decrypt/Vigenere brute (with known key)
xor Single-byte XOR bruteforce
affine Solve affine cipher
rsa Decrypt RSA given n, e, d or factorable n
hash Hash or crack common hashes via wordlist

If automated solver fails, tool prints manual hints and references.

Dependencies:
pip3 install pycryptodome

Examples:
./ctf_crypto_tool.py base --decode --type b64 --input "SGVsbG8gd29ybGQ="
./ctf_crypto_tool.py caesar --bruteforce --input "Khoor"
./ctf_crypto_tool.py xor --bruteforce --input hex:"3a2f1b"
"""
