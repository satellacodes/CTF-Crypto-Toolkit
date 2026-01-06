#!/usr/bin/env python3
"""
Unit tests for Caesar cipher functionality in CTF Crypto Toolkit.
"""

import os
import sys
import unittest

# Add parent directory to path to import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ctf_crypto_tool import english_score, solve_caesar


class TestCaesarCipher(unittest.TestCase):

    def test_caesar_encrypt_shift_3(self):
        """Test Caesar encryption with shift 3."""
        result = solve_caesar("hello", shift=3)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 3)
        self.assertEqual(result[0][1].lower(), "khoor")

    def test_caesar_decrypt_shift_3(self):
        """Test Caesar decryption with shift 3."""
        # Test lowercase
        result = solve_caesar("khoor", shift=3)
        self.assertEqual(result[0][1].lower(), "hello")

        # Test uppercase
        result = solve_caesar("KHOOR", shift=3)
        self.assertEqual(result[0][1].lower(), "hello")

    def test_caesar_mixed_case(self):
        """Test Caesar cipher with mixed case letters."""
        result = solve_caesar("Hello World", shift=3)
        self.assertEqual(result[0][1], "Khoor Zruog")

    def test_caesar_with_non_letters(self):
        """Test Caesar cipher with numbers and special characters."""
        result = solve_caesar("Hello123!@#", shift=3)
        self.assertEqual(result[0][1], "Khoor123!@#")

    def test_caesar_bruteforce(self):
        """Test Caesar cipher bruteforce mode."""
        results = solve_caesar("khoor", bruteforce=True)
        self.assertEqual(len(results), 26)

        # Check that shift 3 gives the correct decryption
        for shift, text, score in results:
            if shift == 3:
                self.assertEqual(text.lower(), "hello")
                break

    def test_caesar_auto_detection(self):
        """Test Caesar cipher auto-detection."""
        results = solve_caesar("khoor", auto=True)
        self.assertGreater(len(results), 0)

        # The first result should have the highest score
        best_shift, best_text, best_score = results[0]

        # For "khoor", shift 3 should be detected as English
        self.assertEqual(best_shift, 3)
        self.assertEqual(best_text.lower(), "hello")
        self.assertGreater(best_score, 5.0)

    def test_english_score(self):
        """Test English scoring function."""
        # English text should have higher score
        english_text = "This is a sample English text"
        non_english_text = "Xlmw mw e weqtpi Mrnsyrx ibeb"

        english_score_value = english_score(english_text)
        non_english_score_value = english_score(non_english_text)

        self.assertGreater(english_score_value, non_english_score_value)

    def test_empty_string(self):
        """Test Caesar cipher with empty string."""
        result = solve_caesar("", shift=5)
        self.assertEqual(result[0][1], "")

    def test_shift_boundary(self):
        """Test Caesar cipher with boundary shifts."""
        # Shift 0 (no change)
        result = solve_caesar("hello", shift=0)
        self.assertEqual(result[0][1].lower(), "hello")

        # Shift 25
        result = solve_caesar("hello", shift=25)
        expected = solve_caesar("gdkkn", shift=1)[0][1].lower()
        self.assertEqual(result[0][1].lower(), expected)

    def test_large_shift(self):
        """Test Caesar cipher with shift > 26."""
        result = solve_caesar("hello", shift=29)  # 29 % 26 = 3
        self.assertEqual(result[0][1].lower(), "khoor")

    def test_negative_shift(self):
        """Test Caesar cipher with negative shift."""
        result = solve_caesar("khoor", shift=-3)
        self.assertEqual(result[0][1].lower(), "hello")


if __name__ == "__main__":
    unittest.main()
