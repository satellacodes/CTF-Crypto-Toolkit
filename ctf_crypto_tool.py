#!/usr/bin/env python3
"""
CTF Crypto Toolkit v2.0
Advanced cryptographic tool for CTF challenges and cybersecurity analysis.
Author: [Dimas Aris Pangestu]
"""

import argparse
import base64
import binascii
import hashlib
import math
import re
import string
import sys
import urllib.parse
from collections import Counter
from itertools import cycle, product
from typing import Dict, List, Optional, Tuple, Union

from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.number import (GCD, bytes_to_long, inverse, isPrime,
                                long_to_bytes)
from Crypto.Util.Padding import pad, unpad

# ================ UTILITY FUNCTIONS ================

def detect_encoding(data: str) -> str:
    """Detect encoding type automatically."""
    if re.match(r'^[A-Za-z0-9+/]*={0,2}$', data) and len(data) % 4 == 0:
        try:
            base64.b64decode(data)
            return 'base64'
        except:
            pass
    if re.match(r'^[A-Z2-7]*=*$', data):
        try:
            base64.b32decode(data)
            return 'base32'
        except:
            pass
    if re.match(r'^[0-9A-Fa-f]+$', data):
        return 'hex'
    if all(c in '01' for c in data):
        return 'binary'
    return 'unknown'

def english_score(text: str) -> float:
    """Calculate English language probability score."""
    common_words = ['the', 'and', 'have', 'that', 'for', 'you', 'with', 'this', 'from']
    text_lower = text.lower()
    score = 0
    
    # Check for common words
    for word in common_words:
        score += text_lower.count(word) * 10
    
    # Check character frequency
    english_freq = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
        'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
        'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
        'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
        'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
    }
    
    for char in text_lower:
        if char in english_freq:
            score += english_freq[char] / 10
    
    # Penalize non-printable characters
    printable_chars = sum(1 for c in text if 32 <= ord(c) < 127)
    score = score * (printable_chars / len(text)) if text else 0
    
    return score

# ================ BASE ENCODINGS ================

def solve_base(data: str, btype: str, decode: bool, url_safe: bool = False) -> str:
    """Handle base encoding/decoding with multiple variants."""
    try:
        if decode:
            if btype == 'b64':
                if url_safe:
                    result = base64.urlsafe_b64decode(data)
                else:
                    result = base64.b64decode(data)
            elif btype == 'b32':
                result = base64.b32decode(data.upper())
            elif btype == 'b16':
                result = base64.b16decode(data.upper())
            elif btype == 'b85':
                result = base64.b85decode(data)
            elif btype == 'a85':
                result = base64.a85decode(data)
            else:
                raise ValueError(f"Unsupported base type: {btype}")
            
            # Try to decode as string, fallback to hex
            try:
                return result.decode('utf-8')
            except:
                return result.hex()
        else:
            # Encode
            if not isinstance(data, bytes):
                data = data.encode('utf-8')
            
            if btype == 'b64':
                if url_safe:
                    result = base64.urlsafe_b64encode(data)
                else:
                    result = base64.b64encode(data)
            elif btype == 'b32':
                result = base64.b32encode(data)
            elif btype == 'b16':
                result = base64.b16encode(data)
            elif btype == 'b85':
                result = base64.b85encode(data)
            elif btype == 'a85':
                result = base64.a85encode(data)
            else:
                raise ValueError(f"Unsupported base type: {btype}")
            
            return result.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Base {btype} {'decode' if decode else 'encode'} failed: {e}")

# ================ CLASSICAL CIPHERS ================

def solve_caesar(text: str, shift: Optional[int] = None, bruteforce: bool = False, 
                 auto: bool = False) -> List[Tuple[int, str, float]]:
    """Solve Caesar cipher with bruteforce and auto-detection."""
    results = []
    alphabet = string.ascii_lowercase
    
    def caesar_transform(text: str, shift: int) -> str:
        result = []
        for char in text:
            if char.lower() in alphabet:
                idx = alphabet.index(char.lower())
                new_idx = (idx - shift) % 26 if shift >= 0 else (idx + abs(shift)) % 26
                new_char = alphabet[new_idx]
                result.append(new_char.upper() if char.isupper() else new_char)
            else:
                result.append(char)
        return ''.join(result)
    
    if shift is not None:
        decrypted = caesar_transform(text, shift)
        score = english_score(decrypted)
        results.append((shift, decrypted, score))
    elif bruteforce or auto:
        for s in range(26):
            decrypted = caesar_transform(text, s)
            score = english_score(decrypted)
            results.append((s, decrypted, score))
        
        if auto:
            # Sort by English score
            results.sort(key=lambda x: x[2], reverse=True)
    
    return results

def solve_rot(text: str, n: int, decode: bool = False) -> str:
    """ROT-n transformation."""
    if decode:
        n = -n
    return solve_caesar(text, n)[0][1]

def solve_vigenere(cipher: str, key: Optional[str] = None, decode: bool = True, 
                  language: str = 'english') -> Union[str, List[Tuple[str, str, float]]]:
    """Vigenère cipher with frequency analysis for key detection."""
    alphabet = string.ascii_lowercase
    alphabet_len = len(alphabet)
    
    if key:
        # Direct decryption with known key
        result = []
        key_idx = 0
        key = key.lower()
        
        for char in cipher:
            if char.lower() in alphabet:
                shift = alphabet.index(key[key_idx % len(key)].lower())
                if decode:
                    new_idx = (alphabet.index(char.lower()) - shift) % alphabet_len
                else:
                    new_idx = (alphabet.index(char.lower()) + shift) % alphabet_len
                
                new_char = alphabet[new_idx]
                result.append(new_char.upper() if char.isupper() else new_char)
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    else:
        # Try to find key length using Kasiski examination
        results = []
        # Simple brute force for short keys
        for key_length in range(1, 10):
            for possible_key in product(alphabet, repeat=key_length):
                key_str = ''.join(possible_key)
                decrypted = solve_vigenere(cipher, key_str, decode=True, language=language)
                score = english_score(decrypted)
                if score > 5:  # Threshold for likely English
                    results.append((key_str, decrypted[:50] + "...", score))
        
        results.sort(key=lambda x: x[2], reverse=True)
        return results[:10]  # Return top 10 results

# ================ XOR CIPHERS ================

def solve_xor(data: Union[str, bytes], key: Optional[Union[int, str, bytes]] = None, 
              bruteforce: bool = False, auto: bool = False) -> List[Tuple[Union[int, str], str, float]]:
    """XOR cipher operations with multiple key types."""
    results = []
    
    # Convert input to bytes
    if isinstance(data, str):
        if data.startswith('hex:'):
            data_bytes = bytes.fromhex(data[4:])
        elif re.match(r'^[0-9A-Fa-f]+$', data):
            data_bytes = bytes.fromhex(data)
        else:
            data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
    
    if isinstance(key, int):
        # Single-byte XOR
        decrypted = bytes(b ^ key for b in data_bytes)
        try:
            text = decrypted.decode('utf-8', errors='ignore')
            score = english_score(text)
            return [(key, text, score)]
        except:
            return [(key, decrypted.hex(), 0)]
    
    elif isinstance(key, str):
        # Multi-byte repeating key XOR
        key_bytes = key.encode('utf-8')
        decrypted = bytes(data_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data_bytes)))
        try:
            text = decrypted.decode('utf-8', errors='ignore')
            score = english_score(text)
            return [(key, text, score)]
        except:
            return [(key, decrypted.hex(), 0)]
    
    elif bruteforce or auto:
        # Bruteforce single-byte XOR
        for k in range(256):
            decrypted = bytes(b ^ k for b in data_bytes)
            try:
                text = decrypted.decode('utf-8', errors='ignore')
                score = english_score(text)
                results.append((k, text, score))
            except:
                pass
        
        if auto:
            results.sort(key=lambda x: x[2], reverse=True)
            return results[:10]
        
        return results
    
    else:
        raise ValueError("No key provided and bruteforce not specified")

# ================ MODERN CIPHERS ================

def solve_aes(data: bytes, key: bytes, mode: str = 'ECB', iv: Optional[bytes] = None, 
              decrypt: bool = True) -> bytes:
    """AES encryption/decryption."""
    if mode.upper() == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode.upper() == 'CBC':
        if iv is None:
            raise ValueError("IV required for CBC mode")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode.upper() == 'CTR':
        if iv is None:
            raise ValueError("Nonce required for CTR mode")
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
    else:
        raise ValueError(f"Unsupported AES mode: {mode}")
    
    if decrypt:
        return unpad(cipher.decrypt(data), AES.block_size)
    else:
        return cipher.encrypt(pad(data, AES.block_size))

def solve_des(data: bytes, key: bytes, mode: str = 'ECB', iv: Optional[bytes] = None,
              decrypt: bool = True) -> bytes:
    """DES encryption/decryption."""
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    
    if mode.upper() == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
    elif mode.upper() == 'CBC':
        if iv is None:
            raise ValueError("IV required for CBC mode")
        cipher = DES.new(key, DES.MODE_CBC, iv)
    else:
        raise ValueError(f"Unsupported DES mode: {mode}")
    
    if decrypt:
        return unpad(cipher.decrypt(data), DES.block_size)
    else:
        return cipher.encrypt(pad(data, DES.block_size))

# ================ RSA OPERATIONS ================

def solve_rsa(n: Optional[int] = None, e: Optional[int] = None, d: Optional[int] = None,
              p: Optional[int] = None, q: Optional[int] = None, c: Optional[int] = None,
              m: Optional[int] = None, auto_factor: bool = False) -> Dict[str, Union[int, str]]:
    """RSA operations with multiple parameter combinations."""
    result = {}
    
    # Calculate missing parameters
    if p and q:
        n = p * q
        phi = (p - 1) * (q - 1)
        result['n'] = n
        result['phi'] = phi
    
    if n and e and d:
        # Verify d is valid
        if pow(pow(2, e, n), d, n) != 2:
            raise ValueError("Invalid d for given n and e")
    
    if n and e and c:
        # Decrypt with public key (only works with small n)
        if auto_factor:
            # Try to factor n
            for i in range(2, int(math.isqrt(n)) + 1):
                if n % i == 0:
                    p_found = i
                    q_found = n // i
                    phi = (p_found - 1) * (q_found - 1)
                    d_calc = inverse(e, phi)
                    m_decrypted = pow(c, d_calc, n)
                    result['p'] = p_found
                    result['q'] = q_found
                    result['d'] = d_calc
                    result['message'] = long_to_bytes(m_decrypted).decode('utf-8', errors='ignore')
                    result['message_hex'] = hex(m_decrypted)
                    return result
        
        # If factoring fails, try Wiener attack or small d
        result['status'] = 'Cannot factor n automatically'
    
    elif n and d and c:
        # Direct decryption
        m_decrypted = pow(c, d, n)
        result['message'] = long_to_bytes(m_decrypted).decode('utf-8', errors='ignore')
        result['message_hex'] = hex(m_decrypted)
    
    elif n and e and m:
        # Encryption
        c_encrypted = pow(m, e, n)
        result['ciphertext'] = c_encrypted
        result['ciphertext_hex'] = hex(c_encrypted)
    
    return result

# ================ HASH OPERATIONS ================

def solve_hash(data: str, algorithm: str, crack: bool = False, 
               wordlist: Optional[str] = None) -> Union[str, List[str]]:
    """Hash generation and cracking."""
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512,
        'blake2s': hashlib.blake2s,
        'blake2b': hashlib.blake2b,
    }
    
    if algorithm not in algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    if crack and wordlist:
        # Hash cracking mode
        target_hash = data.lower()
        results = []
        
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    hash_obj = algorithms[algorithm]()
                    hash_obj.update(word.encode('utf-8'))
                    if hash_obj.hexdigest().lower() == target_hash:
                        results.append(f"Found: {word}")
                        if len(results) >= 5:  # Limit results
                            break
            
            if not results:
                results.append("No matches found in wordlist")
            
            return results
        except FileNotFoundError:
            return [f"Wordlist file not found: {wordlist}"]
    
    else:
        # Hash generation mode
        hash_obj = algorithms[algorithm]()
        hash_obj.update(data.encode('utf-8'))
        return hash_obj.hexdigest()

# ================ ENCODING UTILITIES ================

def solve_url(text: str, decode: bool = False) -> str:
    """URL encode/decode."""
    if decode:
        return urllib.parse.unquote(text)
    else:
        return urllib.parse.quote(text)

def solve_html(text: str, decode: bool = False) -> str:
    """HTML entity encode/decode."""
    import html
    if decode:
        return html.unescape(text)
    else:
        return html.escape(text)

def solve_binary(text: str, decode: bool = False) -> str:
    """Binary encoding/decoding."""
    if decode:
        # Remove spaces and convert binary to text
        binary_str = text.replace(' ', '')
        n = int(binary_str, 2)
        return long_to_bytes(n).decode('utf-8', errors='ignore')
    else:
        # Convert text to binary
        return ' '.join(format(ord(c), '08b') for c in text)

def solve_morse(text: str, decode: bool = False) -> str:
    """Morse code encode/decode."""
    morse_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', '0': '-----', ' ': '/'
    }
    
    reverse_morse = {v: k for k, v in morse_dict.items()}
    
    if decode:
        words = text.strip().split(' / ')
        result = []
        for word in words:
            chars = word.split(' ')
            decoded_word = ''.join(reverse_morse.get(char, '') for char in chars)
            result.append(decoded_word)
        return ' '.join(result)
    else:
        text = text.upper()
        result = []
        for char in text:
            if char == ' ':
                result.append('/')
            else:
                result.append(morse_dict.get(char, char))
        return ' '.join(result)

# ================ MAIN FUNCTION ================

def main():
    parser = argparse.ArgumentParser(
        description='CTF Crypto Toolkit v2.0 - Advanced cryptographic analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./ctf_crypto_tool.py base --decode --type b64 --input "SGVsbG8="
  ./ctf_crypto_tool.py caesar --bruteforce --input "Khoor" --auto
  ./ctf_crypto_tool.py xor --bruteforce --input "1a2b3c"
  ./ctf_crypto_tool.py hash --alg sha256 --crack --input "hash_here" --wordlist rockyou.txt
  ./ctf_crypto_tool.py rsa --n 3233 --e 17 --c 855 --auto-factor
  ./ctf_crypto_tool.py detect --input "encrypted_data"
        """
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Mode of operation')
    
    # Base encoding/decoding
    base_parser = subparsers.add_parser('base', help='Base encoding/decoding')
    base_parser.add_argument('--type', choices=['b64', 'b32', 'b16', 'b85', 'a85'], required=True)
    base_parser.add_argument('--decode', action='store_true')
    base_parser.add_argument('--input', required=True)
    base_parser.add_argument('--url-safe', action='store_true', help='Use URL-safe base64')
    
    # Caesar cipher
    caesar_parser = subparsers.add_parser('caesar', help='Caesar cipher')
    caesar_parser.add_argument('--input', required=True)
    caesar_group = caesar_parser.add_mutually_exclusive_group()
    caesar_group.add_argument('--shift', type=int, help='Specific shift value')
    caesar_group.add_argument('--bruteforce', action='store_true', help='Bruteforce all shifts')
    caesar_group.add_argument('--auto', action='store_true', help='Auto-detect best shift')
    
    # ROT cipher
    rot_parser = subparsers.add_parser('rot', help='ROT cipher')
    rot_parser.add_argument('--input', required=True)
    rot_parser.add_argument('--n', type=int, required=True, help='Rotation amount')
    rot_parser.add_argument('--decode', action='store_true')
    
    # Vigenere cipher
    vigenere_parser = subparsers.add_parser('vigenere', help='Vigenere cipher')
    vigenere_parser.add_argument('--input', required=True)
    vigenere_parser.add_argument('--key', help='Decryption key (optional for brute force)')
    vigenere_parser.add_argument('--decode', action='store_true', default=True)
    vigenere_parser.add_argument('--bruteforce', action='store_true', help='Try to find key')
    
    # XOR operations
    xor_parser = subparsers.add_parser('xor', help='XOR operations')
    xor_parser.add_argument('--input', required=True, help='Input data (hex or text)')
    xor_group = xor_parser.add_mutually_exclusive_group()
    xor_group.add_argument('--key', help='XOR key (integer or string)')
    xor_group.add_argument('--bruteforce', action='store_true', help='Bruteforce single-byte XOR')
    xor_group.add_argument('--auto', action='store_true', help='Auto-detect best key')
    
    # RSA operations
    rsa_parser = subparsers.add_parser('rsa', help='RSA operations')
    rsa_parser.add_argument('--n', type=int, help='Modulus')
    rsa_parser.add_argument('--e', type=int, help='Public exponent')
    rsa_parser.add_argument('--d', type=int, help='Private exponent')
    rsa_parser.add_argument('--p', type=int, help='Prime p')
    rsa_parser.add_argument('--q', type=int, help='Prime q')
    rsa_parser.add_argument('--c', type=int, help='Ciphertext')
    rsa_parser.add_argument('--m', type=int, help='Plaintext message')
    rsa_parser.add_argument('--auto-factor', action='store_true', help='Attempt to factor n')
    
    # Hash operations
    hash_parser = subparsers.add_parser('hash', help='Hash operations')
    hash_parser.add_argument('--input', required=True)
    hash_parser.add_argument('--alg', choices=['md5', 'sha1', 'sha256', 'sha512', 
                                              'sha3_256', 'sha3_512', 'blake2s', 'blake2b'], 
                            required=True)
    hash_parser.add_argument('--crack', action='store_true', help='Crack hash mode')
    hash_parser.add_argument('--wordlist', help='Wordlist file for cracking')
    
    # URL encoding
    url_parser = subparsers.add_parser('url', help='URL encode/decode')
    url_parser.add_argument('--input', required=True)
    url_parser.add_argument('--decode', action='store_true')
    
    # HTML encoding
    html_parser = subparsers.add_parser('html', help='HTML entity encode/decode')
    html_parser.add_argument('--input', required=True)
    html_parser.add_argument('--decode', action='store_true')
    
    # Binary encoding
    binary_parser = subparsers.add_parser('binary', help='Binary encode/decode')
    binary_parser.add_argument('--input', required=True)
    binary_parser.add_argument('--decode', action='store_true')
    
    # Morse code
    morse_parser = subparsers.add_parser('morse', help='Morse code encode/decode')
    morse_parser.add_argument('--input', required=True)
    morse_parser.add_argument('--decode', action='store_true')
    
    # Detect encoding
    detect_parser = subparsers.add_parser('detect', help='Detect encoding/cipher')
    detect_parser.add_argument('--input', required=True)
    detect_parser.add_argument('--verbose', action='store_true')
    
    args = parser.parse_args()
    
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.mode == 'base':
            result = solve_base(args.input, args.type, args.decode, args.url_safe)
            print(f"[✓] Result: {result}")
            
        elif args.mode == 'caesar':
            if args.shift is not None:
                results = solve_caesar(args.input, shift=args.shift)
            elif args.bruteforce:
                results = solve_caesar(args.input, bruteforce=True)
            elif args.auto:
                results = solve_caesar(args.input, auto=True)
            else:
                raise ValueError("Specify --shift, --bruteforce, or --auto")
            
            for shift, text, score in results:
                print(f"Shift {shift:2d}: {text[:60]}... (score: {score:.2f})")
        
        elif args.mode == 'rot':
            result = solve_rot(args.input, args.n, args.decode)
            print(f"[✓] Result: {result}")
        
        elif args.mode == 'vigenere':
            if args.key:
                result = solve_vigenere(args.input, args.key, args.decode)
                print(f"[✓] Result: {result}")
            elif args.bruteforce:
                results = solve_vigenere(args.input, None, args.decode)
                for key, text, score in results:
                    print(f"Key '{key}': {text} (score: {score:.2f})")
            else:
                raise ValueError("Specify --key or --bruteforce")
        
        elif args.mode == 'xor':
            if args.key:
                if args.key.isdigit():
                    key = int(args.key)
                else:
                    key = args.key
                results = solve_xor(args.input, key=key)
            elif args.bruteforce:
                results = solve_xor(args.input, bruteforce=True)
            elif args.auto:
                results = solve_xor(args.input, auto=True)
            else:
                raise ValueError("Specify --key, --bruteforce, or --auto")
            
            for key, text, score in results:
                print(f"Key {key}: {text[:60]}... (score: {score:.2f})")
        
        elif args.mode == 'rsa':
            result = solve_rsa(args.n, args.e, args.d, args.p, args.q, args.c, args.m, args.auto_factor)
            for key, value in result.items():
                print(f"{key}: {value}")
        
        elif args.mode == 'hash':
            if args.crack:
                results = solve_hash(args.input, args.alg, crack=True, wordlist=args.wordlist)
                for result in results:
                    print(result)
            else:
                result = solve_hash(args.input, args.alg)
                print(f"{args.alg.upper()}: {result}")
        
        elif args.mode == 'url':
            result = solve_url(args.input, args.decode)
            print(f"[✓] Result: {result}")
        
        elif args.mode == 'html':
            result = solve_html(args.input, args.decode)
            print(f"[✓] Result: {result}")
        
        elif args.mode == 'binary':
            result = solve_binary(args.input, args.decode)
            print(f"[✓] Result: {result}")
        
        elif args.mode == 'morse':
            result = solve_morse(args.input, args.decode)
            print(f"[✓] Result: {result}")
        
        elif args.mode == 'detect':
            encoding_type = detect_encoding(args.input)
            print(f"Detected encoding: {encoding_type}")
            if args.verbose:
                print(f"Input length: {len(args.input)}")
                print(f"Sample: {args.input[:50]}...")
        
        else:
            parser.print_help()
    
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
