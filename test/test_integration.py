#!/usr/bin/env python3
"""
Integration tests for CTF Crypto Toolkit.
"""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestIntegration(unittest.TestCase):

    def test_cli_base64(self):
        """Test CLI base64 encoding/decoding."""
        # Test encoding
        result = subprocess.run(
            [
                "python3",
                "ctf_crypto_tool.py",
                "base",
                "--type",
                "b64",
                "--input",
                "Hello",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("SGVsbG8=", result.stdout)

        # Test decoding
        result = subprocess.run(
            [
                "python3",
                "ctf_crypto_tool.py",
                "base",
                "--decode",
                "--type",
                "b64",
                "--input",
                "SGVsbG8=",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Hello", result.stdout)

    def test_cli_caesar(self):
        """Test CLI Caesar cipher."""
        result = subprocess.run(
            [
                "python3",
                "ctf_crypto_tool.py",
                "caesar",
                "--shift",
                "3",
                "--input",
                "Hello",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Khoor", result.stdout)

    def test_cli_xor(self):
        """Test CLI XOR operations."""
        # XOR with key 65
        result = subprocess.run(
            ["python3", "ctf_crypto_tool.py", "xor", "--key", "65", "--input", "Hello"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)

    def test_cli_help(self):
        """Test CLI help command."""
        result = subprocess.run(
            ["python3", "ctf_crypto_tool.py", "--help"], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("CTF Crypto Toolkit", result.stdout)

    def test_example_challenges(self):
        """Test that example challenges work."""
        # Test Caesar challenge
        with open("examples/caesar_challenge.txt", "r") as f:
            content = f.read()
            # Extract encrypted message
            import re

            match = re.search(r'"([^"]+)"', content)
            if match:
                encrypted = match.group(1)

                result = subprocess.run(
                    [
                        "python3",
                        "ctf_crypto_tool.py",
                        "caesar",
                        "--auto",
                        "--input",
                        encrypted,
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0)
                self.assertIn("Hello", result.stdout)


if __name__ == "__main__":
    unittest.main()
