"""GUI Frame for File Transfers.

This module contains the TransferFrame class for the tkinter GUI.
Core transfer logic is in FileTransfer.py (no tkinter dependency).
"""

import logging

# Import tkinter at module level for GUI frames (they are only used in GUI mode)
import tkinter as tk
from tkinter import ttk

from tksample1.NavigationFrame import NavigationFrame


class TransferFrame(tk.Frame):
    """GUI frame for displaying upload and download transfer status."""

    def __init__(self, transfer_handler, *args, **kwargs):
        """Initialize the transfer frame.

        Args:
            transfer_handler: TransferHandler instance for managing transfers
            *args: Arguments passed to tk.Frame
            **kwargs: Keyword arguments passed to tk.Frame
        """
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__transfer_handler = transfer_handler

        # Register callbacks with ProgressManager
        self._register_progress_manager_callbacks()

        # Call super().__init__() first before creating child widgets
        super().__init__(*args, **kwargs)

        # Configure grid weights for TransferFrame
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create Transferts frame directly (no notebook, single tab view)
        self.__create_transferts_tab()

    def _format_size(self, size: int) -> str:
        """Format size in human-readable format."""
        return NavigationFrame._format_size(size)

    def __create_transferts_tab(self):
        """Create the Transferts tab with progress bars and pending queues."""
        self.__frame_transferts = tk.Frame(self)

        # Upload Section
        self.__frame_upload = tk.LabelFrame(self.__frame_transferts, text="Uploads")
        self.__frame_upload.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Upload progress bars (2-phase: Encrypting + Uploading)
        self.__upload_encrypt_var = tk.DoubleVar(value=0.0)
        self.__upload_encrypt_label = tk.StringVar(value="")
        self.__upload_encrypt_pct_var = tk.StringVar(value="0%")
        self.__encrypt_progress = ttk.Progressbar(
            self.__frame_upload,
            variable=self.__upload_encrypt_var,
            orient="horizontal",
            length=400,
        )
        self.__encrypt_progress.grid(row=0, column=0, sticky="ew", pady=2)
        self.__encrypt_label = tk.Label(
            self.__frame_upload, textvariable=self.__upload_encrypt_label
        )
        self.__encrypt_label.grid(row=1, column=0, sticky="w", padx=5, pady=(0, 5))
        self.__encrypt_pct_label = tk.Label(
            self.__frame_upload, textvariable=self.__upload_encrypt_pct_var
        )
        self.__encrypt_pct_label.grid(row=1, column=0, sticky="e", padx=(200, 5))

        self.__upload_transfer_var = tk.DoubleVar(value=0.0)
        self.__upload_transfer_label = tk.StringVar(value="")
        self.__upload_transfer_pct_var = tk.StringVar(value="0%")
        self.__upload_progress = ttk.Progressbar(
            self.__frame_upload,
            variable=self.__upload_transfer_var,
            orient="horizontal",
            length=400,
        )
        self.__upload_progress.grid(row=2, column=0, sticky="ew", pady=2)
        self.__upload_file_label = tk.Label(
            self.__frame_upload, textvariable=self.__upload_transfer_label
        )
        self.__upload_file_label.grid(row=3, column=0, sticky="w", padx=5, pady=(0, 5))
        self.__upload_transfer_pct_label = tk.Label(
            self.__frame_upload, textvariable=self.__upload_transfer_pct_var
        )
        self.__upload_transfer_pct_label.grid(
            row=3, column=0, sticky="e", padx=(200, 5)
        )

        # Upload pending queue
        self.__upload_queue_listbox = self._create_scrollable_list(
            self.__frame_upload, row=4, column=0
        )

        # Upload cancel button
        self.__upload_cancel_btn = ttk.Button(
            self.__frame_upload,
            text="Cancel All Uploads",
            command=self.__cancel_all_uploads,
        )
        self.__upload_cancel_btn.grid(row=5, column=0, sticky="w", padx=5, pady=5)

        # Upload frame grid configuration
        self.__frame_upload.grid_rowconfigure(4, weight=1)
        self.__frame_upload.grid_columnconfigure(0, weight=1)

        # Download Section
        self.__frame_download = tk.LabelFrame(self.__frame_transferts, text="Downloads")
        self.__frame_download.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Download progress bars (2-phase: Downloading + Decrypting)
        self.__download_transfer_var = tk.DoubleVar(value=0.0)
        self.__download_transfer_label = tk.StringVar(value="")
        self.__download_transfer_pct_var = tk.StringVar(value="0%")
        self.__download_progress = ttk.Progressbar(
            self.__frame_download,
            variable=self.__download_transfer_var,
            orient="horizontal",
            length=400,
        )
        self.__download_progress.grid(row=0, column=0, sticky="ew", pady=2)
        self.__download_file_label = tk.Label(
            self.__frame_download, textvariable=self.__download_transfer_label
        )
        self.__download_file_label.grid(
            row=1, column=0, sticky="w", padx=5, pady=(0, 5)
        )
        self.__download_transfer_pct_label = tk.Label(
            self.__frame_download, textvariable=self.__download_transfer_pct_var
        )
        self.__download_transfer_pct_label.grid(
            row=1, column=0, sticky="e", padx=(200, 5)
        )

        self.__download_decrypt_var = tk.DoubleVar(value=0.0)
        self.__download_decrypt_label = tk.StringVar(value="")
        self.__download_decrypt_pct_var = tk.StringVar(value="0%")
        self.__decrypt_progress = ttk.Progressbar(
            self.__frame_download,
            variable=self.__download_decrypt_var,
            orient="horizontal",
            length=400,
        )
        self.__decrypt_progress.grid(row=2, column=0, sticky="ew", pady=2)
        self.__decrypt_label = tk.Label(
            self.__frame_download, textvariable=self.__download_decrypt_label
        )
        self.__decrypt_label.grid(row=3, column=0, sticky="w", padx=5, pady=(0, 5))
        self.__download_decrypt_pct_label = tk.Label(
            self.__frame_download, textvariable=self.__download_decrypt_pct_var
        )
        self.__download_decrypt_pct_label.grid(
            row=3, column=0, sticky="e", padx=(200, 5)
        )

        # Download pending queue
        self.__download_queue_listbox = self._create_scrollable_list(
            self.__frame_download, row=4, column=0
        )

        # Download cancel button
        self.__download_cancel_btn = ttk.Button(
            self.__frame_download,
            text="Cancel All Downloads",
            command=self.__cancel_all_downloads,
        )
        self.__download_cancel_btn.grid(row=5, column=0, sticky="w", padx=5, pady=5)

        # Download frame grid configuration
        self.__frame_download.grid_rowconfigure(4, weight=1)
        self.__frame_download.grid_columnconfigure(0, weight=1)

        # Transferts tab grid configuration
        self.__frame_transferts.grid_rowconfigure(0, weight=1)
        self.__frame_transferts.grid_rowconfigure(1, weight=1)
        self.__frame_transferts.grid_columnconfigure(0, weight=1)

        # Add Transferts frame directly to TransferFrame (no tab)
        self.__frame_transferts.grid(row=0, column=0, sticky="nsew")

    def _create_scrollable_list(self, master, row, column):
        """Create a scrollable listbox with scrollbar.

        Args:
            master: Parent widget
            row: Grid row position
            column: Grid column position
        Returns:
            Listbox widget
        """
        frame = tk.Frame(master)
        frame.grid(row=row, column=column, sticky="nsew", padx=5, pady=5)

        scrollbar = ttk.Scrollbar(frame)
        scrollbar.grid(row=0, column=1, sticky="ns")

        listbox = tk.Listbox(
            frame,
            yscrollcommand=scrollbar.set,
            height=5,
        )
        listbox.grid(row=0, column=0, sticky="nsew")
        scrollbar.config(command=listbox.yview)

        # Configure grid weights for vertical expansion
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        return listbox

    def grid(self, *args, **kwargs):
        """Grid layout for this frame."""
        super().grid(*args, **kwargs)

    def _register_progress_manager_callbacks(self):
        """Register callback functions with ProgressManager."""
        self.__transfer_handler.progress_manager.register_callbacks(
            download_transfer_callback=self.on_download_transfer_progress,
            download_decrypt_callback=self.on_download_decrypt_progress,
            download_reset_callback=self.on_download_reset,
            upload_encrypt_callback=self.on_upload_encrypt_progress,
            upload_transfer_callback=self.on_upload_transfer_progress,
            upload_reset_callback=self.on_upload_reset,
        )

    def _update_download_queue(self, courant, q: list):
        """Update the download queue listbox in Transferts tab.

        Uses incremental updates to avoid flickering from full rebuilds.

        Args:
            courant: Currently downloading item or None
            q: Queue of pending downloads
        """
        # Get current items in listbox
        current_items = list(self.__download_queue_listbox.get(0, tk.END))

        # Build list of new items with mode indicators
        new_items = []
        for item in q:
            mode_str = ""
            # Try to get inline mode from ProgressManager via tuuid
            if hasattr(item, "tuuid") and self.__transfer_handler:
                is_inline = (
                    self.__transfer_handler.progress_manager.get_download_inline_mode(
                        item.tuuid
                    )
                )
                mode_str = " [INLINE]" if is_inline else " [2PHASE]"
            new_items.append(item.nom + mode_str)

        # Only update if items actually changed
        if current_items != new_items:
            self.__download_queue_listbox.delete(0, tk.END)
            for item in new_items:
                self.__download_queue_listbox.insert(tk.END, item)

    def _update_upload_queue(self, courant, q: list):
        """Update the upload queue listbox in Transferts tab.

        Uses incremental updates to avoid flickering from full rebuilds.

        Args:
            courant: Currently uploading item or None
            q: Queue of pending uploads
        """
        # Get current items in listbox
        current_items = list(self.__upload_queue_listbox.get(0, tk.END))

        # Build list of new items
        new_items = [str(item.path) for item in q]

        # Only update if items actually changed
        if current_items != new_items:
            self.__upload_queue_listbox.delete(0, tk.END)
            for item in new_items:
                self.__upload_queue_listbox.insert(tk.END, item)

    # Callback methods for ProgressManager
    def on_upload_encrypt_progress(self, filename: str, progress: float):
        """Callback for upload encryption progress."""
        self.__upload_encrypt_var.set(progress)
        self.__upload_encrypt_label.set(f"[File: {filename}]")
        self.__upload_encrypt_pct_var.set(f"{int(progress)}%")

    def on_upload_reset(self, filename: str):
        """Callback to reset upload transfer progress before new upload."""
        self.__upload_transfer_var.set(0.0)
        self.__upload_transfer_label.set("")
        self.__upload_transfer_pct_var.set("0%")

    def on_upload_transfer_progress(self, filename: str, progress: float):
        """Callback for upload transfer progress."""
        self.__upload_transfer_var.set(progress)
        size_info = self._get_upload_size_info(filename)
        if size_info:
            self.__upload_transfer_label.set(f"[File: {filename} - {size_info}]")
        else:
            self.__upload_transfer_label.set(f"[File: {filename}]")
        self.__upload_transfer_pct_var.set(f"{int(progress)}%")

    def on_download_transfer_progress(self, filename: str, progress: float):
        """Callback for download transfer progress."""
        self.__download_transfer_var.set(progress)

        # Get mode indicator from current download
        mode_label = ""
        if self.__transfer_handler and self.__transfer_handler.progress_manager:
            current_download = (
                self.__transfer_handler.progress_manager.get_current_download()
            )
            if current_download:
                is_inline = current_download.get("inline", False)
                mode_label = " [INLINE]" if is_inline else " [2PHASE]"

        size_info = self._get_download_size_info(filename)
        if size_info:
            self.__download_transfer_label.set(
                f"[File: {filename} - {size_info}]" + mode_label
            )
        else:
            self.__download_transfer_label.set(f"[File: {filename}]" + mode_label)
        self.__download_transfer_pct_var.set(f"{int(progress)}%")

    def on_download_reset(self, filename: str):
        """Callback to reset download decrypt progress before new decryption."""
        self.__download_decrypt_var.set(0.0)
        self.__download_decrypt_label.set("")
        self.__download_decrypt_pct_var.set("0%")

    def on_download_decrypt_progress(self, filename: str, progress: float):
        """Callback for download decryption progress."""
        self.__download_decrypt_var.set(progress)

        # Get mode indicator from current download
        mode_label = ""
        if self.__transfer_handler and self.__transfer_handler.progress_manager:
            current_download = (
                self.__transfer_handler.progress_manager.get_current_download()
            )
            if current_download:
                is_inline = current_download.get("inline", False)
                mode_label = " [INLINE]" if is_inline else " [2PHASE]"

        self.__download_decrypt_label.set(f"[File: {filename}]" + mode_label)
        self.__download_decrypt_pct_var.set(f"{int(progress)}%")

    def _get_upload_size_info(self, filename: str) -> str:
        """Get size info for upload file."""
        # TODO: Get actual size from upload queue
        return self._format_size(0)

    def _get_download_size_info(self, filename: str) -> str:
        """Get size info for download file."""
        # TODO: Get actual size from download queue
        return self._format_size(0)

    def __cancel_all_uploads(self):
        """Cancel all uploads and clear the upload UI."""
        self.__transfer_handler.uploader.cancel_all_uploads()
        # Clear upload progress UI
        self.__upload_encrypt_var.set(0.0)
        self.__upload_encrypt_label.set("")
        self.__upload_encrypt_pct_var.set("0%")
        self.__upload_transfer_var.set(0.0)
        self.__upload_transfer_label.set("")
        self.__upload_transfer_pct_var.set("0%")

    def __cancel_all_downloads(self):
        """Cancel all downloads and clear the download UI."""
        self.__transfer_handler.downloader.cancel_all_downloads()
        # Clear download progress UI
        self.__download_transfer_var.set(0.0)
        self.__download_transfer_label.set("")
        self.__download_transfer_pct_var.set("0%")
        self.__download_decrypt_var.set(0.0)
        self.__download_decrypt_label.set("")
        self.__download_decrypt_pct_var.set("0%")
