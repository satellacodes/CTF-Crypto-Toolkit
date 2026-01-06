#!/usr/bin/env python3
"""
Unit tests for XOR cipher functionality in CTF Crypto Toolkit.
"""

import os
import sys
import unittest

# Add parent directory to path to import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ctf_crypto_tool import english_score, solve_xor


class TestXORCipher(unittest.TestCase):

    def test_single_byte_xor_encrypt(self):
        """Test single-byte XOR encryption."""
        plaintext = "Hello"
        key = 65  # 'A'

        # Convert to bytes and XOR
        plaintext_bytes = plaintext.encode("utf-8")
        encrypted = bytes(b ^ key for b in plaintext_bytes)

        # Test decryption
        results = solve_xor(encrypted.hex(), key=key)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1].lower(), "hello")

    def test_single_byte_xor_decrypt(self):
        """Test single-byte XOR decryption."""
        # "Hello" XOR with key 65 ('A')
        encrypted_hex = "25282d2d2e"
        key = 65

        results = solve_xor(encrypted_hex, key=key)
        self.assertEqual(results[0][1].lower(), "hello")

    def test_multi_byte_xor(self):
        """Test multi-byte repeating key XOR."""
        plaintext = "Hello World"
        key = "KEY"

        # Manual XOR for verification
        plaintext_bytes = plaintext.encode("utf-8")
        key_bytes = key.encode("utf-8")
        encrypted = bytes(
            plaintext_bytes[i] ^ key_bytes[i % len(key_bytes)]
            for i in range(len(plaintext_bytes))
        )

        # Test decryption
        results = solve_xor(encrypted.hex(), key=key)
        self.assertEqual(results[0][1].lower(), "hello world")

    def test_xor_bruteforce(self):
        """Test XOR bruteforce mode."""
        # Encrypt "test" with key 88 ('X')
        plaintext = "test"
        key = 88
        plaintext_bytes = plaintext.encode("utf-8")
        encrypted = bytes(b ^ key for b in plaintext_bytes)

        results = solve_xor(encrypted.hex(), bruteforce=True)

        # Should find the correct key
        found = False
        for k, text, score in results:
            if k == key and text.lower() == "test":
                found = True
                break

        self.assertTrue(found, "Bruteforce should find the correct key")

    def test_xor_auto_detection(self):
        """Test XOR auto-detection mode."""
        # Encrypt English text with key 32 (space equivalent)
        plaintext = "This is a test message for XOR auto-detection"
        key = 32
        plaintext_bytes = plaintext.encode("utf-8")
        encrypted = bytes(b ^ key for b in plaintext_bytes)

        results = solve_xor(encrypted.hex(), auto=True)

        # First result should be the best match
        self.assertGreater(len(results), 0)
        best_key, best_text, best_score = results[0]

        # The auto mode should identify this as English text
        self.assertGreater(best_score, 5.0)

    def test_xor_with_hex_prefix(self):
        """Test XOR with hex: prefix."""
        hex_data = "hex:1a2b3c4d"
        key = 42

        results = solve_xor(hex_data, key=key)
        self.assertEqual(len(results), 1)

    def test_xor_with_text_input(self):
        """Test XOR with plain text input."""
        plaintext = "hello"
        key = 100

        # XOR the text
        plaintext_bytes = plaintext.encode("utf-8")
        encrypted = bytes(b ^ key for b in plaintext_bytes)

        # Convert back to text (might not be valid UTF-8)
        try:
            encrypted_text = encrypted.decode("utf-8")
        except:
            encrypted_text = encrypted.hex()

        # Test with text input
        if isinstance(encrypted_text, str):
            results = solve_xor(encrypted_text, key=key)
            self.assertEqual(results[0][1].lower(), "hello")

    def test_xor_edge_cases(self):
        """Test XOR with edge cases."""
        # Empty input
        results = solve_xor("", key=1)
        self.assertEqual(results[0][1], "")

        # Key 0 (no change)
        results = solve_xor("test", key=0)
        self.assertEqual(results[0][1].lower(), "test")

        # Key 255 (maximum)
        results = solve_xor("test", key=255)
        # Should be able to decrypt back
        encrypted = bytes(ord(c) ^ 255 for c in "test")
        results2 = solve_xor(encrypted.hex(), key=255)
        self.assertEqual(results2[0][1].lower(), "test")

    def test_xor_with_invalid_hex(self):
        """Test XOR with invalid hex input."""
        with self.assertRaises(ValueError):
            solve_xor("invalid_hex", key=1)

    def test_english_scoring_for_xor(self):
        """Test English scoring helps identify correct XOR key."""
        # Create multiple XOR encrypted versions
        plaintext = "The quick brown fox jumps over the lazy dog"

        scores = []
        for key in [32, 65, 97, 120]:
            plaintext_bytes = plaintext.encode("utf-8")
            encrypted = bytes(b ^ key for b in plaintext_bytes)
            results = solve_xor(encrypted.hex(), bruteforce=True)

            # Find the correct decryption
            for k, text, score in results:
                if k == key:
                    scores.append(score)
                    break

        # The correct key should have a high English score
        self.assertGreater(max(scores), 10.0)


if __name__ == "__main__":
    unittest.main()
