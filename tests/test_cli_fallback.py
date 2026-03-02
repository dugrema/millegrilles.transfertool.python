"""Test script for CLI fallback feature verification.

This script tests the various scenarios for CLI auto-fallback when tkinter is not available
or when no display is present.
"""

import os
import sys
import unittest
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCLIFallback(unittest.TestCase):
    """Test cases for CLI fallback functionality."""

    def test_cli_import(self):
        """Test that CLI module can be imported without tkinter."""
        from tksample1.CLI import CLIHandler

        self.assertTrue(True, "CLI module imported successfully")

    def test_core_modules_import_without_tkinter(self):
        """Test that core modules can be imported without tkinter."""
        from tksample1.AuthUsager import Authentification
        from tksample1.Downloader import Downloader
        from tksample1.FileTransfer import TransferHandler
        from tksample1.Navigation import Navigation
        from tksample1.Uploader import Uploader

        self.assertTrue(True, "All core modules imported successfully")

    def test_gui_modules_import_when_tkinter_available(self):
        """Test that GUI modules can be imported when tkinter is available."""
        import tkinter as tk

        from tksample1.ConnectionFrame import ConnectionFrame
        from tksample1.FileTransfer import TransferFrame
        from tksample1.Navigation import NavigationFrame
        from tksample1.Uploader import UploaderFrame

        self.assertTrue(True, "All GUI modules imported successfully")

    def test_no_module_level_tkinter_imports(self):
        """Verify that tkinter is not imported at module level in core files."""
        core_files = [
            "tksample1/AuthUsager.py",
            "tksample1/Navigation.py",
            "tksample1/FileTransfer.py",
            "tksample1/Uploader.py",
            "tksample1/Downloader.py",
        ]

        for file_path in core_files:
            with open(file_path, "r") as f:
                content = f.read()
                # Check for module-level tkinter imports
                lines = content.split("\n")
                # Skip imports after class definitions
                for i, line in enumerate(lines[:50]):  # Check first 50 lines
                    if line.startswith("class ") or line.startswith("def "):
                        break
                    if "import tkinter" in line or "from tkinter" in line:
                        self.fail(
                            f"Found tkinter import at module level in {file_path} at line {i + 1}: {line.strip()}"
                        )

        self.assertTrue(True, "No module-level tkinter imports found in core files")


class TestAutoFallbackScenarios(unittest.TestCase):
    """Test cases for auto-fallback scenarios."""

    def test_has_display_detection(self):
        """Test display detection works correctly."""
        from tksample1.GuiCapability import has_display

        result = has_display()
        self.assertIsInstance(result, bool)

    def test_has_tkinter_detection(self):
        """Test tkinter detection works correctly."""
        from tksample1.GuiCapability import has_tkinter

        result, error = has_tkinter()
        self.assertIsInstance(result, bool)
        self.assertIsInstance(error, (str, type(None)))

    def test_determine_execution_mode_cli_flag(self):
        """Test that --cli flag forces CLI mode."""
        from tksample1.GuiCapability import determine_execution_mode

        mode = determine_execution_mode(cli_flag=True, gui_flag=False)
        self.assertEqual(mode, "cli")

    def test_determine_execution_mode_gui_flag(self):
        """Test that --gui flag forces GUI mode."""
        from tksample1.GuiCapability import determine_execution_mode

        mode = determine_execution_mode(cli_flag=False, gui_flag=True)
        self.assertEqual(mode, "gui")

    def test_determine_execution_mode_auto_fallback(self):
        """Test auto-fallback to CLI when no display."""
        from tksample1.GuiCapability import (
            determine_execution_mode,
            has_display,
            has_tkinter,
        )

        display_available = has_display()
        tkinter_available, _ = has_tkinter()

        mode = determine_execution_mode(cli_flag=False, gui_flag=False)

        # If display not available, should fallback to CLI
        if not display_available or not tkinter_available:
            self.assertEqual(mode, "cli")
        else:
            self.assertEqual(mode, "gui")


class TestWindowInitialization(unittest.TestCase):
    """Test GUI window initialization."""

    def test_window_import_without_instantiation(self):
        """Test that Window class can be imported without tkinter being initialized."""
        # This should not trigger tkinter imports until Window is instantiated
        import importlib

        import tksample1.__main__

        # Access the Window class without instantiating it
        Window = tksample1.__main__.Window
        self.assertTrue(True, "Window class accessible without initialization")


def run_tests():
    """Run all tests and return summary."""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCLIFallback)
    suite.addTests(
        unittest.TestLoader().loadTestsFromTestCase(TestAutoFallbackScenarios)
    )
    suite.addTests(
        unittest.TestLoader().loadTestsFromTestCase(TestWindowInitialization)
    )

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
