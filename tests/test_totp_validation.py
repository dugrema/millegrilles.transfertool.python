"""Tests for TOTP Validation Module.

This module contains unit tests for the TOTP validation functionality
in the MilleGrilles File Transfer utility.
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "tksample1"))

from tksample1.TotpValidation import (
    TOTPValidationError,
    is_totp_invalid,
    is_totp_required,
    sanitize_totp_code,
    validate_totp_code,
)


class TestValidateTotpCode(unittest.TestCase):
    """Tests for validate_totp_code function."""

    def test_empty_code(self):
        """Empty code should be valid (not provided)."""
        is_valid, error_msg = validate_totp_code("")
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_none_code(self):
        """None code should be valid (not provided)."""
        is_valid, error_msg = validate_totp_code(None)
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_valid_6_digit_code(self):
        """Valid 6-digit TOTP code should pass validation."""
        is_valid, error_msg = validate_totp_code("123456")
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_valid_7_digit_code(self):
        """Valid 7-digit TOTP code should pass validation."""
        is_valid, error_msg = validate_totp_code("1234567")
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_valid_8_digit_code(self):
        """Valid 8-digit TOTP code should pass validation."""
        is_valid, error_msg = validate_totp_code("12345678")
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_valid_10_digit_code(self):
        """Valid 10-digit TOTP code should pass validation."""
        is_valid, error_msg = validate_totp_code("1234567890")
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_code_with_letters(self):
        """Code with letters should fail validation."""
        is_valid, error_msg = validate_totp_code("123ABC")
        self.assertFalse(is_valid)
        self.assertEqual(error_msg, "Code TOTP doit contenir uniquement des chiffres")

    def test_code_with_special_chars(self):
        """Code with special characters should fail validation."""
        is_valid, error_msg = validate_totp_code("123!@#")
        self.assertFalse(is_valid)
        self.assertEqual(error_msg, "Code TOTP doit contenir uniquement des chiffres")

    def test_code_too_short(self):
        """Code shorter than 6 digits should fail validation."""
        is_valid, error_msg = validate_totp_code("12345")
        self.assertFalse(is_valid)
        self.assertIn("6-10 chiffres", error_msg)

    def test_code_too_long(self):
        """Code longer than 10 digits should fail validation."""
        is_valid, error_msg = validate_totp_code("12345678901")
        self.assertFalse(is_valid)
        self.assertIn("6-10 chiffres", error_msg)

    def test_code_with_whitespace(self):
        """Code with leading/trailing whitespace should be trimmed."""
        is_valid, error_msg = validate_totp_code("  123456  ")
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")


class TestSanitizeTotpCode(unittest.TestCase):
    """Tests for sanitize_totp_code function."""

    def test_strip_whitespace(self):
        """Whitespace should be removed from code."""
        sanitized = sanitize_totp_code("  123456  ")
        self.assertEqual(sanitized, "123456")

    def test_no_whitespace(self):
        """Code without whitespace should remain unchanged."""
        sanitized = sanitize_totp_code("123456")
        self.assertEqual(sanitized, "123456")

    def test_newlines(self):
        """Newlines should be stripped."""
        sanitized = sanitize_totp_code("\n123456\n")
        self.assertEqual(sanitized, "123456")


class TestIsTotpRequired(unittest.TestCase):
    """Tests for is_totp_required function."""

    def test_totp_required_true(self):
        """Server response with totp_required=True should return True."""
        response = {"totp_required": True}
        self.assertTrue(is_totp_required(response))

    def test_totp_required_false(self):
        """Server response with totp_required=False should return False."""
        response = {"totp_required": False}
        self.assertFalse(is_totp_required(response))

    def test_totp_required_missing(self):
        """Server response without totp_required should return False."""
        response = {"other_field": "value"}
        self.assertFalse(is_totp_required(response))

    def test_empty_response(self):
        """Empty response should return False."""
        response = {}
        self.assertFalse(is_totp_required(response))


class TestIsTotpInvalid(unittest.TestCase):
    """Tests for is_totp_invalid function."""

    def test_totp_invalid_true(self):
        """Server response with totp_invalid=True should return True."""
        response = {"totp_invalid": True}
        self.assertTrue(is_totp_invalid(response))

    def test_totp_invalid_false(self):
        """Server response with totp_invalid=False should return False."""
        response = {"totp_invalid": False}
        self.assertFalse(is_totp_invalid(response))

    def test_totp_invalid_missing(self):
        """Server response without totp_invalid should return False."""
        response = {"other_field": "value"}
        self.assertFalse(is_totp_invalid(response))

    def test_empty_response(self):
        """Empty response should return False."""
        response = {}
        self.assertFalse(is_totp_invalid(response))


class TestTOTPValidationError(unittest.TestCase):
    """Tests for TOTPValidationError exception."""

    def test_exception_message(self):
        """Exception should store and provide error message."""
        error_msg = "Test error message"
        try:
            raise TOTPValidationError(error_msg)
        except TOTPValidationError as e:
            self.assertEqual(str(e), error_msg)
            self.assertEqual(e.message, error_msg)


class TestIntegration(unittest.TestCase):
    """Integration tests for TOTP validation workflow."""

    def test_full_validation_flow_valid(self):
        """Test complete validation flow with valid code."""
        raw_code = "  123456  "

        # Validate
        is_valid, error_msg = validate_totp_code(raw_code)
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

        # Sanitize
        sanitized = sanitize_totp_code(raw_code)
        self.assertEqual(sanitized, "123456")

    def test_full_validation_flow_invalid(self):
        """Test complete validation flow with invalid code."""
        raw_code = "123ABC"

        # Validate
        is_valid, error_msg = validate_totp_code(raw_code)
        self.assertFalse(is_valid)
        self.assertEqual(error_msg, "Code TOTP doit contenir uniquement des chiffres")


def run_tests():
    """Run all tests."""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestValidateTotpCode)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestSanitizeTotpCode))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestIsTotpRequired))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestIsTotpInvalid))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestTOTPValidationError))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestIntegration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
