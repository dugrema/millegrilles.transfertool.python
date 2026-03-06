"""TransferFrame.py - GUI frame for file transfer operations.

This module provides the Transfer tab UI with progress bars for:
- Download transfer (server to local)
- Download decryption (encrypted to decrypted)
- Upload encryption (local to encrypted)
- Upload transfer (encrypted to server)

Feature 2: Progress bars turn green upon completion.
"""

import logging
import tkinter as tk
from tkinter import ttk
from typing import Optional

# Progress bar color constants
COLOR_IN_PROGRESS = "#3B82F6"  # Blue - active transfer
COLOR_COMPLETED = "#10B981"  # Green - completed
COLOR_ERROR = "#EF4444"  # Red - error
COLOR_DISABLED = "#9CA3AF"  # Gray - empty/disabled


class TransferFrame(tk.Frame):
    """GUI frame for file transfer operations with progress tracking.

    Provides UI for monitoring download and upload progress with
    color-coded progress bars that turn green on completion.
    """

    def __init__(self, transfer_handler, *args, **kwargs):
        """Initialize the transfer frame.

        Args:
            transfer_handler: TransferHandler instance for backend operations
            *args: Arguments passed to tk.Frame
            **kwargs: Keyword arguments passed to tk.Frame
        """
        super().__init__(*args, **kwargs)

        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__transfer_handler = transfer_handler

        # Build the UI
        self._create_ui()

        # Register callbacks with ProgressManager
        self._register_progress_manager_callbacks()

        # Set up queue display
        self._update_download_queue(None, [])
        self._update_upload_queue(None, [])

    def _create_ui(self):
        """Create the transfer UI components."""
        # Configure grid weights for responsive layout
        self.grid_rowconfigure(0, weight=0)  # Title
        self.grid_rowconfigure(1, weight=1)  # Download section
        self.grid_rowconfigure(2, weight=1)  # Upload section

        self.grid_columnconfigure(0, weight=1)

        # Section title
        title_label = ttk.Label(
            self, text="File Transfers", font=("Helvetica", 14, "bold")
        )
        title_label.grid(row=0, column=0, sticky="ew", pady=(0, 10), padx=5)

        # === Download Section ===
        download_frame = ttk.LabelFrame(self, text="Downloads", padding=5)
        download_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Configure download frame grid
        download_frame.grid_rowconfigure(0, weight=0)  # Transfer progress
        download_frame.grid_rowconfigure(1, weight=0)  # Decrypt progress
        download_frame.grid_rowconfigure(2, weight=1)  # Queue list

        download_frame.grid_columnconfigure(0, weight=1)

        # Download transfer progress
        self.__download_transfer_label = tk.StringVar(value="")
        self.__download_transfer_pct_var = tk.StringVar(value="0%")
        self.__download_transfer_pct_label: Optional[ttk.Label] = None

        ttk.Label(download_frame, text="Download from server:", font=("Helvetica", 10))
        ttk.Label(
            download_frame,
            textvariable=self.__download_transfer_label,
            foreground="gray",
        ).grid(row=0, column=0, sticky="w", padx=5, pady=2)

        self.__download_progress = ttk.Progressbar(
            download_frame,
            orient="horizontal",
            length=400,
            mode="determinate",
            maximum=100,
        )
        self.__download_progress.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.__download_transfer_var = tk.DoubleVar(value=0.0)
        self.__download_progress["variable"] = self.__download_transfer_var

        self.__download_transfer_pct_label = ttk.Label(
            download_frame,
            textvariable=self.__download_transfer_pct_var,
            foreground=COLOR_IN_PROGRESS,
        )
        self.__download_transfer_pct_label.grid(row=0, column=0, sticky="e", padx=5)

        # Download decrypt progress
        self.__download_decrypt_label = tk.StringVar(value="")
        self.__download_decrypt_pct_var = tk.StringVar(value="0%")
        self.__download_decrypt_pct_label: Optional[ttk.Label] = None

        ttk.Label(download_frame, text="Decryption:", font=("Helvetica", 10))
        ttk.Label(
            download_frame,
            textvariable=self.__download_decrypt_label,
            foreground="gray",
        ).grid(row=1, column=0, sticky="w", padx=5, pady=2)

        self.__decrypt_progress = ttk.Progressbar(
            download_frame,
            orient="horizontal",
            length=400,
            mode="determinate",
            maximum=100,
        )
        self.__decrypt_progress.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        self.__download_decrypt_var = tk.DoubleVar(value=0.0)
        self.__decrypt_progress["variable"] = self.__download_decrypt_var

        self.__download_decrypt_pct_label = ttk.Label(
            download_frame,
            textvariable=self.__download_decrypt_pct_var,
            foreground=COLOR_IN_PROGRESS,
        )
        self.__download_decrypt_pct_label.grid(row=1, column=0, sticky="e", padx=5)

        # Cancel downloads button
        self.__cancel_download_btn = ttk.Button(
            download_frame,
            text="Cancel Downloads",
            command=self.cancel_all_downloads,
            state="disabled",
        )
        self.__cancel_download_btn.grid(
            row=2, column=0, sticky="ew", padx=5, pady=(5, 0)
        )

        # Download queue list
        self.__download_queue_frame = ttk.Frame(download_frame)
        self.__download_queue_frame.grid(row=3, column=0, sticky="nsew", pady=5)

        # === Upload Section ===
        upload_frame = ttk.LabelFrame(self, text="Uploads", padding=5)
        upload_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)

        # Configure upload frame grid
        upload_frame.grid_rowconfigure(0, weight=0)  # Encrypt progress
        upload_frame.grid_rowconfigure(1, weight=0)  # Transfer progress
        upload_frame.grid_rowconfigure(2, weight=1)  # Queue list

        upload_frame.grid_columnconfigure(0, weight=1)

        # Upload encrypt progress
        self.__upload_encrypt_label = tk.StringVar(value="")
        self.__upload_encrypt_pct_var = tk.StringVar(value="0%")
        self.__upload_encrypt_pct_label: Optional[ttk.Label] = None

        ttk.Label(upload_frame, text="Encryption:", font=("Helvetica", 10))
        ttk.Label(
            upload_frame, textvariable=self.__upload_encrypt_label, foreground="gray"
        ).grid(row=0, column=0, sticky="w", padx=5, pady=2)

        self.__encrypt_progress = ttk.Progressbar(
            upload_frame,
            orient="horizontal",
            length=400,
            mode="determinate",
            maximum=100,
        )
        self.__encrypt_progress.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.__upload_encrypt_var = tk.DoubleVar(value=0.0)
        self.__encrypt_progress["variable"] = self.__upload_encrypt_var

        self.__upload_encrypt_pct_label = ttk.Label(
            upload_frame,
            textvariable=self.__upload_encrypt_pct_var,
            foreground=COLOR_IN_PROGRESS,
        )
        self.__upload_encrypt_pct_label.grid(row=0, column=0, sticky="e", padx=5)

        # Upload transfer progress
        self.__upload_transfer_label = tk.StringVar(value="")
        self.__upload_transfer_pct_var = tk.StringVar(value="0%")
        self.__upload_transfer_pct_label: Optional[ttk.Label] = None

        ttk.Label(upload_frame, text="Upload to server:", font=("Helvetica", 10))
        ttk.Label(
            upload_frame, textvariable=self.__upload_transfer_label, foreground="gray"
        ).grid(row=1, column=0, sticky="w", padx=5, pady=2)

        self.__upload_progress = ttk.Progressbar(
            upload_frame,
            orient="horizontal",
            length=400,
            mode="determinate",
            maximum=100,
        )
        self.__upload_progress.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        self.__upload_transfer_var = tk.DoubleVar(value=0.0)
        self.__upload_progress["variable"] = self.__upload_transfer_var

        self.__upload_transfer_pct_label = ttk.Label(
            upload_frame,
            textvariable=self.__upload_transfer_pct_var,
            foreground=COLOR_IN_PROGRESS,
        )
        self.__upload_transfer_pct_label.grid(row=1, column=0, sticky="e", padx=5)

        # Cancel uploads button
        self.__cancel_upload_btn = ttk.Button(
            upload_frame,
            text="Cancel Uploads",
            command=self.cancel_all_uploads,
            state="disabled",
        )
        self.__cancel_upload_btn.grid(row=2, column=0, sticky="ew", padx=5, pady=(5, 0))

        # Upload queue list
        self.__upload_queue_frame = ttk.Frame(upload_frame)
        self.__upload_queue_frame.grid(row=3, column=0, sticky="nsew", pady=5)

    def _register_progress_manager_callbacks(self):
        """Register callback functions with ProgressManager."""
        self.__transfer_handler.progress_manager.register_callbacks(
            download_transfer_callback=self.on_download_transfer_progress,
            download_decrypt_callback=self.on_download_decrypt_progress,
            download_reset_callback=self.on_download_reset,
            upload_encrypt_callback=self.on_upload_encrypt_progress,
            upload_transfer_callback=self.on_upload_transfer_progress,
            upload_reset_callback=self.on_upload_reset,
            # Color callbacks for completion state (Feature 2)
            download_transfer_color_callback=self.on_download_transfer_color,
            download_decrypt_color_callback=self.on_download_decrypt_color,
            upload_encrypt_color_callback=self.on_upload_encrypt_color,
            upload_transfer_color_callback=self.on_upload_transfer_color,
        )

    def _set_progress_color(self, pct_label: Optional[ttk.Label], is_complete: bool):
        """Set percentage label color based on completion state.

        Args:
            pct_label: The percentage label widget
            is_complete: True if complete (green), False if in progress (blue)
        """
        if pct_label is None:
            return
        color = COLOR_COMPLETED if is_complete else COLOR_IN_PROGRESS
        pct_label.configure(foreground=color)

    # === Download Progress Callbacks ===

    def on_download_transfer_progress(self, filename: str, progress: float):
        """Callback to update download transfer progress bar."""
        self.__download_transfer_label.set(filename)
        self.__download_transfer_var.set(progress)
        self.__download_transfer_pct_var.set(f"{progress:.1f}%")

    def on_download_decrypt_progress(self, filename: str, progress: float):
        """Callback to update download decrypt progress bar."""
        self.__download_decrypt_label.set(filename)
        self.__download_decrypt_var.set(progress)
        self.__download_decrypt_pct_var.set(f"{progress:.1f}%")

    # === Upload Progress Callbacks ===

    def on_upload_encrypt_progress(self, filename: str, progress: float):
        """Callback to update upload encrypt progress bar."""
        self.__upload_encrypt_label.set(filename)
        self.__upload_encrypt_var.set(progress)
        self.__upload_encrypt_pct_var.set(f"{progress:.1f}%")

    def on_upload_transfer_progress(self, filename: str, progress: float):
        """Callback to update upload transfer progress bar."""
        self.__upload_transfer_label.set(filename)
        self.__upload_transfer_var.set(progress)
        self.__upload_transfer_pct_var.set(f"{progress:.1f}%")

    # === Color Change Callbacks (Feature 2) ===

    def on_download_transfer_color(self, filename: str, is_complete: bool):
        """Callback to change download transfer percentage label color."""
        self._set_progress_color(self.__download_transfer_pct_label, is_complete)

    def on_download_decrypt_color(self, filename: str, is_complete: bool):
        """Callback to change download decrypt percentage label color."""
        self._set_progress_color(self.__download_decrypt_pct_label, is_complete)

    def on_upload_encrypt_color(self, filename: str, is_complete: bool):
        """Callback to change upload encrypt percentage label color."""
        self._set_progress_color(self.__upload_encrypt_pct_label, is_complete)

    def on_upload_transfer_color(self, filename: str, is_complete: bool):
        """Callback to change upload transfer percentage label color."""
        self._set_progress_color(self.__upload_transfer_pct_label, is_complete)

    # === Reset Callbacks ===

    def on_download_reset(self, filename: str):
        """Callback to reset download decrypt progress before new decryption."""
        self.__download_decrypt_var.set(0.0)
        self.__download_decrypt_label.set("")
        self.__download_decrypt_pct_var.set("0%")
        # Reset color to in-progress state
        self._set_progress_color(self.__download_decrypt_pct_label, False)

    def on_upload_reset(self, filename: str):
        """Callback to reset upload transfer progress before new upload."""
        self.__upload_transfer_var.set(0.0)
        self.__upload_transfer_label.set("")
        self.__upload_transfer_pct_var.set("0%")
        # Reset color to in-progress state
        self._set_progress_color(self.__upload_transfer_pct_label, False)

    # === Queue Update Methods ===

    def _update_download_queue(self, current: Optional[object], queue: list):
        """Update the download queue display.

        Args:
            current: Currently downloading file/directory
            queue: List of items in download queue
        """
        # Clear existing queue items
        for widget in self.__download_queue_frame.winfo_children():
            widget.destroy()

        # Build queue display
        if current:
            current_label = tk.Label(
                self.__download_queue_frame,
                text=f"→ {getattr(current, 'nom', 'File')}",
                foreground=COLOR_IN_PROGRESS,
                font=("Helvetica", 10),
            )
            current_label.pack(anchor="w", pady=2)

        for i, item in enumerate(queue):
            label = tk.Label(
                self.__download_queue_frame,
                text=f"  • {getattr(item, 'nom', 'Item')} [{'INLINE' if getattr(item, 'inline', False) else '2PHASE'}]",
                foreground=COLOR_IN_PROGRESS,
                font=("Helvetica", 9),
            )
            label.pack(anchor="w", pady=1)

        # Enable/disable cancel button based on active downloads
        if current or queue:
            self.__cancel_download_btn.configure(state="normal")
        else:
            self.__cancel_download_btn.configure(state="disabled")

    def _update_upload_queue(self, current: Optional[object], queue: list):
        """Update the upload queue display.

        Args:
            current: Currently uploading file/directory
            queue: List of items in upload queue
        """
        # Clear existing queue items
        for widget in self.__upload_queue_frame.winfo_children():
            widget.destroy()

        # Build queue display
        if current:
            current_label = tk.Label(
                self.__upload_queue_frame,
                text=f"→ {getattr(current, 'path', None) and (getattr(current.path, 'name', 'File') if hasattr(current, 'path') else 'File') or 'File'}",
                foreground=COLOR_IN_PROGRESS,
                font=("Helvetica", 10),
            )
            current_label.pack(anchor="w", pady=2)

        for i, item in enumerate(queue):
            label = tk.Label(
                self.__upload_queue_frame,
                text=f"  • {getattr(item, 'path', None) and item.path.name or 'Item'}",
                foreground=COLOR_IN_PROGRESS,
                font=("Helvetica", 9),
            )
            label.pack(anchor="w", pady=1)

        # Enable/disable cancel button based on active uploads
        if current or queue:
            self.__cancel_upload_btn.configure(state="normal")
        else:
            self.__cancel_upload_btn.configure(state="disabled")

    # === Cancel Methods ===

    def cancel_all_downloads(self):
        """Cancel all downloads and clear the download UI."""
        self.__transfer_handler.downloader.cancel_all_downloads()
        # Clear download progress UI and reset colors
        self.__download_transfer_var.set(0.0)
        self.__download_transfer_label.set("")
        self.__download_transfer_pct_var.set("0%")
        self.__download_decrypt_var.set(0.0)
        self.__download_decrypt_label.set("")
        self.__download_decrypt_pct_var.set("0%")
        # Reset colors to in-progress state
        self._set_progress_color(self.__download_transfer_pct_label, False)
        self._set_progress_color(self.__download_decrypt_pct_label, False)

    def cancel_all_uploads(self):
        """Cancel all uploads and clear the upload UI."""
        self.__transfer_handler.uploader.cancel_all_uploads()
        # Clear upload progress UI and reset colors
        self.__upload_encrypt_var.set(0.0)
        self.__upload_encrypt_label.set("")
        self.__upload_encrypt_pct_var.set("0%")
        self.__upload_transfer_var.set(0.0)
        self.__upload_transfer_label.set("")
        self.__upload_transfer_pct_var.set("0%")
        # Reset colors to in-progress state
        self._set_progress_color(self.__upload_encrypt_pct_label, False)
        self._set_progress_color(self.__upload_transfer_pct_label, False)
