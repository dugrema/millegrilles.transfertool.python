"""GUI capability detection utility for MilleGrilles Transfer Tool.

This module provides utilities to detect if a GUI can be used in the current
environment, enabling auto-fallback to CLI mode when necessary.
"""

import logging
import os
import sys
from typing import Optional, Tuple

# Import tkinter error type safely
try:
    from _tkinter import TclError
except ImportError:
    TclError = Exception  # Fallback if tkinter not available

logger = logging.getLogger(__name__)


def has_display() -> bool:
    """Check if a display is available for GUI.

    Checks for:
    - $DISPLAY environment variable (X11)
    - $WAYLAND_DISPLAY environment variable (Wayland sessions)

    Returns:
        True if a display is available, False otherwise.
    """
    # Check for $DISPLAY environment variable (X11)
    if os.environ.get("DISPLAY"):
        return True

    # Check for WAYLAND_DISPLAY (Wayland sessions)
    if os.environ.get("WAYLAND_DISPLAY"):
        return True

    return False


def is_interactive() -> bool:
    """Check if running in an interactive session.

    Returns:
        True if stdin is a tty (terminal), False otherwise.
    """
    return sys.stdin.isatty()


def has_tkinter() -> Tuple[bool, Optional[str]]:
    """Check if tkinter is installed and importable.

    Returns:
        Tuple of (is_available, error_message_if_not)
    """
    try:
        import tkinter  # noqa: F401

        # Additional check: try to create a Tcl/Tk instance
        # This catches cases where tkinter is installed but can't initialize
        import tkinter as tk

        try:
            # Use a hidden root to test initialization
            root = tk.Tk()
            root.destroy()
            return True, None
        except Exception as e:
            return False, str(e)
    except ImportError as e:
        return False, f"tkinter not installed: {e}"


def can_use_gui() -> Tuple[bool, Optional[str]]:
    """Determine if GUI can be used and provide reason if not.

    This function checks all prerequisites for GUI operation:
    1. tkinter is installed and importable
    2. A display is available ($DISPLAY or $WAYLAND_DISPLAY)

    Returns:
        Tuple of (can_use_gui, reason_if_not)
    """
    # First check if tkinter is importable
    tkinter_available, tkinter_error = has_tkinter()

    if not tkinter_available:
        return False, tkinter_error

    # Then check for display availability
    if not has_display():
        return False, "No display available (missing $DISPLAY or $WAYLAND_DISPLAY)"

    return True, None


def detect_gui_capability() -> Tuple[bool, str]:
    """Detect GUI capability with detailed logging.

    Logs diagnostic information about the GUI environment.

    Returns:
        Tuple of (can_use_gui, mode_suggestion)
        mode_suggestion is either 'gui' or 'cli'
    """
    can_use, reason = can_use_gui()

    if can_use:
        logger.debug("GUI capability detected: display available, tkinter functional")
        return True, "gui"
    else:
        logger.warning(f"GUI unavailable: {reason}")
        logger.warning("Auto-falling back to CLI mode")
        return False, "cli"


def get_forced_mode_from_env() -> Optional[str]:
    """Check for forced mode via environment variable.

    Supports MGTRANSFER_MODE environment variable with values:
    - 'cli' - Force CLI mode
    - 'gui' - Force GUI mode (will error if unavailable)

    Returns:
        'cli', 'gui', or None if not set
    """
    env_mode = os.environ.get("MGTRANSFER_MODE", "").lower()

    if env_mode == "cli":
        logger.info("CLI mode forced via MGTRANSFER_MODE environment variable")
        return "cli"
    elif env_mode == "gui":
        logger.info("GUI mode forced via MGTRANSFER_MODE environment variable")
        return "gui"

    return None


def determine_execution_mode(cli_flag: bool, gui_flag: bool) -> str:
    """Determine execution mode with fallback hierarchy.

    Priority order:
    1. Explicit --cli flag -> CLI mode
    2. Explicit --gui flag -> GUI mode (will error if unavailable)
    3. Environment variable MGTRANSFER_MODE
    4. Auto-detection of display capability
    5. Default to GUI (original behavior)

    Args:
        cli_flag: True if --cli flag was passed
        gui_flag: True if --gui flag was passed

    Returns:
        'cli' or 'gui'
    """
    # Priority 1: Explicit --cli flag
    if cli_flag:
        return "cli"

    # Priority 2: Explicit --gui flag
    if gui_flag:
        mode = "gui"
        can_use, reason = can_use_gui()
        if not can_use:
            logger.error(f"GUI mode requested but unavailable: {reason}")
            raise RuntimeError(f"GUI mode requested but not available: {reason}")
        return mode

    # Priority 3: Environment variable
    env_mode = get_forced_mode_from_env()
    if env_mode:
        if env_mode == "gui":
            can_use, reason = can_use_gui()
            if not can_use:
                logger.error(f"GUI mode forced via env but unavailable: {reason}")
                raise RuntimeError(f"GUI mode forced but not available: {reason}")
        return env_mode

    # Priority 4: Auto-detection
    can_use, reason = can_use_gui()
    if can_use:
        return "gui"
    else:
        logger.warning(f"GUI unavailable ({reason}), using CLI mode")
        return "cli"


def attempt_gui_initialization() -> bool:
    """Attempt to initialize GUI with error handling.

    Tries to create a tkinter root window to verify GUI capability.
    Returns False and logs error if GUI initialization fails.

    Returns:
        True if GUI can be initialized, False otherwise
    """
    try:
        import tkinter as tk

        # Try to create a root window
        root = tk.Tk()
        root.destroy()
        return True
    except (TclError, ImportError, OSError) as e:
        logger.warning(f"GUI initialization failed: {e}")
        logger.warning("Falling back to CLI mode")
        return False
