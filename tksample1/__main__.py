"""MilleGrilles Transfer Tool - Main Entry Point.

This module provides the main entry point for the application with support for:
- GUI mode with automatic fallback to CLI when display is unavailable
- CLI mode for headless environments (SSH, Docker, CI/CD)
- Environment variable control via MGTRANSFER_MODE
"""

import argparse
import logging
import time
from threading import Event, Thread, active_count, enumerate
from typing import Optional

from tksample1.CLI import CLIHandler
from tksample1.Configuration import Configuration
from tksample1.GuiCapability import determine_execution_mode


class Window:
    """GUI Window wrapper that imports tkinter components."""

    def __init__(
        self,
        stop_event: Event,
        auth,
        navigation,
        transfer_handler,
        *args,
        **kwargs,
    ):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event

        # Import tkinter components only when GUI mode is confirmed
        import tkinter as tk
        from tkinter import ttk

        from tksample1.ConnectionFrame import ConnectionFrame
        from tksample1.NavigationFrame import NavigationFrame
        from tksample1.TransferFrame import TransferFrame

        self._tk_root = tk.Tk(*args, **kwargs)

        self._tk_root.title("Transfer Tool - MilleGrilles")
        self._tk_root.geometry("900x700")  # Increased size to accommodate tabs
        self._tk_root.minsize(700, 500)

        # Bind configure event for resize
        self._tk_root.bind("<Configure>", self.on_resize)

        # Configure grid weights for main window
        self._tk_root.grid_rowconfigure(0, weight=1)
        self._tk_root.grid_columnconfigure(0, weight=1)

        self.auth = auth
        self.auth_frame = None

        self.__frame_notebook = ttk.Notebook(self._tk_root)
        self.__frame_notebook.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Add Connection tab
        self.__frame_connection = ConnectionFrame(auth, master=self.__frame_notebook)
        self.__frame_notebook.add(self.__frame_connection, text="Connection")

        # Add Navigation tab
        self.__frame_navigation = NavigationFrame(
            navigation, master=self.__frame_notebook
        )
        self.__frame_notebook.add(self.__frame_navigation, text="Navigation")

        # Add Transfers tab
        self.__frame_transfert = TransferFrame(
            transfer_handler, master=self.__frame_notebook
        )
        self.__frame_notebook.add(self.__frame_transfert, text="Transferts")

        # Register TransferFrame callbacks with ProgressManager
        transfer_handler.progress_manager.register_callbacks(
            download_transfer_callback=self.__frame_transfert.on_download_transfer_progress,
            download_decrypt_callback=self.__frame_transfert.on_download_decrypt_progress,
            upload_encrypt_callback=self.__frame_transfert.on_upload_encrypt_progress,
            upload_transfer_callback=self.__frame_transfert.on_upload_transfer_progress,
        )

        # Wiring frames to backend components
        self.auth_frame = self.__frame_connection
        self.auth.auth_frame = self.__frame_connection
        navigation.nav_frame = self.__frame_navigation
        transfer_handler.transfer_frame = self.__frame_transfert

    def on_resize(self, event):
        """Handle window resize events."""
        if event.width < 700 or event.height < 500:
            self.__frame_notebook.grid(padx=2, pady=2)
        else:
            self.__frame_notebook.grid(padx=5, pady=5)

    def mainloop(self):
        """Start the tkinter main loop."""
        self._tk_root.mainloop()

    def quit(self):
        """Quit the tkinter application."""
        self._tk_root.quit()


class App:
    """Main application class with mode selection."""

    def __init__(
        self, config: Optional[Configuration] = None, cli_mode: Optional[bool] = None
    ):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = Event()
        self.__exit_code = 0
        self.config = config or Configuration.default()

        # Determine execution mode with auto-detection if not specified
        if cli_mode is None:
            self.cli_mode = False  # Will be set by determine_mode()
        else:
            self.cli_mode = cli_mode

        # Initialize core components (no tkinter dependency)
        from tksample1.AuthUsager import Authentification
        from tksample1.FileTransfer import TransferHandler
        from tksample1.Navigation import Navigation

        self.auth = Authentification(
            self.__stop_event, downdir=self.config.downdir, tmpdir=self.config.tmpdir
        )
        self.transfer_handler = TransferHandler(self.__stop_event, self.auth)
        self.navigation = Navigation(
            self.__stop_event, self.auth, self.transfer_handler
        )

        # Initialize based on mode
        if self.cli_mode:
            self.cli_handler = CLIHandler(
                self.__stop_event, self.auth, self.navigation, self.transfer_handler
            )
        else:
            self.window = Window(
                self.__stop_event, self.auth, self.navigation, self.transfer_handler
            )

    def exec(self):
        self.__logger.info("Debut mainloop")
        Thread(name="Stop thread", target=self.stop_thread).start()
        self.auth.init_config()

        if self.cli_mode:
            self._exec_cli_mode()
        else:
            self._exec_gui_mode()

        if self.__stop_event.is_set() is False:
            self.__stop_event.set()
            self.__exit_code = 0

    def _exec_cli_mode(self):
        """Execute CLI mode."""
        self.cli_handler.run()

    def _exec_gui_mode(self):
        """Execute GUI mode."""
        self.window.mainloop()

    def stop_thread(self):
        self.__logger.info("Attente arret app")
        self.__stop_event.wait()

        self.__logger.info("Arret App")
        if not self.cli_mode:
            self.window.quit()
        self.auth.quit()
        self.navigation.quit()
        self.transfer_handler.quit()

        self.__logger.info("Arret complete, exit code : %d" % self.__exit_code)

        active_threads = active_count()
        if active_threads > 0:
            self.__logger.warning("Active threads : %d" % active_threads)
            time.sleep(10)
            for t in enumerate():
                self.__logger.warning("Active thread : %s" % t)

        exit(self.__exit_code)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="MilleGrilles Transfer Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run in CLI mode (disable GUI)",
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="Force GUI mode (will fail if display not available)",
    )

    parser.add_argument(
        "--downdir",
        type=str,
        default=None,
        help="Download directory (overrides config)",
    )

    parser.add_argument(
        "--tmpdir", type=str, default=None, help="Temporary directory for processing"
    )

    return parser.parse_args()


def main():
    """Main entry point with argument parsing and auto-fallback."""
    args = parse_arguments()

    # Create configuration from arguments or defaults
    config = Configuration.default()

    # Override with command-line arguments if provided
    if args.downdir:
        config.downdir = args.downdir
    if args.tmpdir:
        config.tmpdir = args.tmpdir

    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("__main__").setLevel(logging.DEBUG)
    logging.getLogger("tksample1").setLevel(logging.DEBUG)

    # Determine execution mode with auto-fallback
    try:
        execution_mode = determine_execution_mode(args.cli, args.gui)
    except RuntimeError as e:
        logging.error(f"Failed to initialize requested mode: {e}")
        exit(1)

    # Create app with determined mode
    cli_mode = execution_mode == "cli"
    App(config, cli_mode=cli_mode).exec()


if __name__ == "__main__":
    main()
