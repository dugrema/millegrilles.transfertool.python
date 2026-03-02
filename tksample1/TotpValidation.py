"""TOTP Validation Utility.

This module provides TOTP code validation functionality for the MilleGrilles File Transfer utility.
It implements validation rules for TOTP codes as specified in RFC 6238.
"""

import logging
import re
from typing import Optional, Tuple


def validate_totp_code(code: Optional[str]) -> Tuple[bool, str]:
    """Validate TOTP code format.

    TOTP codes typically are 6-8 digit numeric codes.
    This function validates the format and returns any validation errors.

    Args:
        code: TOTP code to validate. None or empty string means not provided.

    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if code is valid or not provided
        - error_message: Description of validation error, empty if valid
    """
    logger = logging.getLogger(__name__)

    # Empty or None = not provided (valid)
    if not code:
        logger.debug("TOTP code not provided (optional)")
        return True, ""

    code = code.strip()

    # Check if code contains only digits
    if not code.isdigit():
        error_msg = "Code TOTP doit contenir uniquement des chiffres"
        logger.warning(f"Invalid TOTP format: {error_msg}")
        return False, error_msg

    # Check length constraints (6-10 digits)
    if not (6 <= len(code) <= 10):
        error_msg = f"Code TOTP doit avoir 6-10 chiffres (obtenu {len(code)})"
        logger.warning(f"Invalid TOTP length: {error_msg}")
        return False, error_msg

    logger.debug(f"TOTP code validated: {code}")
    return True, ""


def sanitize_totp_code(code: str) -> str:
    """Sanitize TOTP code by removing whitespace and normalizing format.

    Args:
        code: Raw TOTP code input

    Returns:
        Sanitized TOTP code (stripped of whitespace)
    """
    return code.strip()


def is_totp_required(server_response: dict) -> bool:
    """Check if server requires TOTP authentication.

    Args:
        server_response: Response dictionary from server authentication

    Returns:
        True if server indicates TOTP is required
    """
    # Check if server explicitly requires TOTP
    return server_response.get("totp_required", False)


def is_totp_invalid(server_response: dict) -> bool:
    """Check if server rejected the TOTP code.

    Args:
        server_response: Response dictionary from server authentication

    Returns:
        True if server indicates TOTP code is invalid
    """
    return server_response.get("totp_invalid", False)


class TOTPValidationError(Exception):
    """Exception raised when TOTP validation fails."""

    def __init__(self, message: str):
        """Initialize TOTP validation error.

        Args:
            message: Error message describing the validation failure
        """
        self.message = message
        super().__init__(message)
