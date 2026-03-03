"""GUI Frame for File Transfers.

This module contains the TransferFrame class for the tkinter GUI.
Core transfer logic is in FileTransfer.py (no tkinter dependency).
"""

import logging

# Import tkinter at module level for GUI frames (they are only used in GUI mode)
import tkinter as tk
from tkinter import ttk

from tksample1.Downloader import DownloadFichier
from tksample1.NavigationFrame import NavigationFrame
from tksample1.Uploader import UploadFichier


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

        # Create notebook for tabs
        self.__notebook = ttk.Notebook(self)
        self.__notebook.grid(row=0, column=0, sticky="nsew")

        # Configure grid weights for TransferFrame
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create Transferts tab
        self.__create_transferts_tab()

        # Create Files tab (keep existing behavior for now)
        self.__create_files_tab()

    def _format_size(self, size: int) -> str:
        """Format size in human-readable format."""
        return NavigationFrame._format_size(size)

    def __create_transferts_tab(self):
        """Create the Transferts tab with progress bars and pending queues."""
        self.__frame_transferts = tk.Frame(self.__notebook)

        # Upload Section
        self.__frame_upload = tk.LabelFrame(self.__frame_transferts, text="Uploads")
        self.__frame_upload.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Upload progress bars (2-phase: Encrypting + Uploading)
        self.__upload_encrypt_var = tk.DoubleVar(value=0.0)
        self.__upload_encrypt_label = tk.StringVar(value="")
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

        self.__upload_transfer_var = tk.DoubleVar(value=0.0)
        self.__upload_transfer_label = tk.StringVar(value="")
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

        self.__download_decrypt_var = tk.DoubleVar(value=0.0)
        self.__download_decrypt_label = tk.StringVar(value="")
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

        # Add tab to notebook
        self.__notebook.add(self.__frame_transferts, text="Transferts")

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

    def __create_files_tab(self):
        """Create the Files tab with existing treeview behavior."""
        self.__frame_files = tk.Frame(self.__notebook)

        self.__frame_upload_old = tk.Frame(master=self.__frame_files)
        self.upload_status_var = tk.StringVar(
            master=self.__frame_upload_old, value="Upload ..."
        )
        self.__upload_status_label = tk.Label(
            master=self.__frame_upload_old,
            textvariable=self.upload_status_var,
            justify="left",
        )
        self.__upload_status_label.grid(row=0, column=0)
        self.__treeview_upload = self.__add_treeview(self.__frame_upload_old)

        self.__frame_download_old = tk.Frame(master=self.__frame_files)
        self.download_status_var = tk.StringVar(
            master=self.__frame_download_old, value="Download ..."
        )
        self.__download_status_label = tk.Label(
            master=self.__frame_download_old,
            textvariable=self.download_status_var,
            justify="left",
        )
        self.__download_status_label.grid(row=0, column=0)
        self.__treeview_download = self.__add_treeview(self.__frame_download_old)

        self.__frame_upload_old.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.__frame_download_old.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        self.__frame_files.grid_rowconfigure(0, weight=1)
        self.__frame_files.grid_rowconfigure(1, weight=1)
        self.__frame_files.grid_columnconfigure(0, weight=1)

        self.__frame_upload_old.grid_rowconfigure(1, weight=1)
        self.__frame_upload_old.grid_columnconfigure(0, weight=1)

        self.__frame_download_old.grid_rowconfigure(1, weight=1)
        self.__frame_download_old.grid_columnconfigure(0, weight=1)

        # Add Files tab to notebook
        self.__notebook.add(self.__frame_files, text="Files")

    def __add_treeview(self, master):
        """Create and configure a treeview widget.

        Args:
            master: Parent widget for the treeview

        Returns:
            Configured Treeview widget
        """
        from tkinter import ttk

        treeview = ttk.Treeview(master=master, columns=("taille", "etat"), height=10)
        treeview["columns"] = ("taille", "etat")

        treeview.heading("taille", text="Taille")
        treeview.heading("etat", text="Etat")

        # Use dynamic widths for responsive layout
        treeview.column("#0", width=400, minwidth=200)  # Changed from fixed 600
        treeview.column("taille", width=100, anchor="se")
        treeview.column("etat", width=75)

        treeview.grid(row=1, column=0, sticky="nsew")

        return treeview

    def grid(self, *args, **kwargs):
        """Grid layout for this frame."""
        super().grid(*args, **kwargs)

    def refresh_upload(self, courant, q: list):
        """Refresh the upload treeview with current uploads (Files tab).

        Args:
            courant: Currently uploading item or None
            q: Queue of pending uploads
        """
        self.__treeview_upload.delete(*self.__treeview_upload.get_children())
        if courant is not None:
            nom_fichier = str(courant.path)
            self.__treeview_upload.insert(
                "",
                "end",
                iid=nom_fichier,
                text=nom_fichier,
                values=(courant.taille, "En cours"),
            )
        for item in q:
            path_item = str(item.path)
            if isinstance(item, UploadFichier):
                self.__treeview_upload.insert(
                    "",
                    "end",
                    iid=path_item,
                    text=path_item,
                    values=(item.taille, "Attente"),
                )
            else:
                item.preparer_taille()
                self.__treeview_upload.insert(
                    "",
                    "end",
                    iid=path_item,
                    text=path_item,
                    values=(item.taille, "Attente"),
                )

    def refresh_download(self, courant, q: list):
        """Refresh the download treeview with current downloads (Files tab).

        Args:
            courant: Currently downloading item or None
            q: Queue of pending downloads
        """
        self.__treeview_download.delete(*self.__treeview_download.get_children())
        if courant is not None:
            nom_fichier = courant.nom
            try:
                taille = str(courant.taille_chiffree)
            except AttributeError:
                courant.preparer_taille(self.__transfer_handler.connexion)
                taille = "N/D"
            self.__treeview_download.insert(
                "",
                "end",
                iid=courant.tuuid,
                text=nom_fichier,
                values=(taille, "En cours"),
            )
        for item in q:
            nom_item = item.nom
            if isinstance(item, DownloadFichier):
                self.__treeview_download.insert(
                    "",
                    "end",
                    iid=item.tuuid,
                    text=nom_item,
                    values=(item.taille_chiffree, "Attente"),
                )
            else:
                courant.preparer_taille(self.__transfer_handler.connexion)
                taille = "N/D"
                self.__treeview_download.insert(
                    "", "end", iid=item.tuuid, text=nom_item, values=(taille, "Attente")
                )

    def _register_progress_manager_callbacks(self):
        """Register callback functions with ProgressManager."""
        self.__transfer_handler.progress_manager.register_callbacks(
            download_transfer_callback=self.on_download_transfer_progress,
            download_decrypt_callback=self.on_download_decrypt_progress,
            upload_encrypt_callback=self.on_upload_encrypt_progress,
            upload_transfer_callback=self.on_upload_transfer_progress,
        )

    def _update_download_queue(self, courant, q: list):
        """Update the download queue listbox in Transferts tab.

        Args:
            courant: Currently downloading item or None
            q: Queue of pending downloads
        """
        self.__download_queue_listbox.delete(0, tk.END)

        # Add pending items to listbox
        for item in q:
            nom_item = item.nom
            self.__download_queue_listbox.insert(tk.END, nom_item)

    def _update_upload_queue(self, courant, q: list):
        """Update the upload queue listbox in Transferts tab.

        Args:
            courant: Currently uploading item or None
            q: Queue of pending uploads
        """
        self.__upload_queue_listbox.delete(0, tk.END)

        # Add pending items to listbox
        for item in q:
            path_item = str(item.path)
            self.__upload_queue_listbox.insert(tk.END, path_item)

    # Callback methods for ProgressManager
    def on_upload_encrypt_progress(self, filename: str, progress: float):
        """Callback for upload encryption progress."""
        self.__upload_encrypt_var.set(progress)
        self.__upload_encrypt_label.set(f"[File: {filename}]")

    def on_upload_transfer_progress(self, filename: str, progress: float):
        """Callback for upload transfer progress."""
        self.__upload_transfer_var.set(progress)
        size_info = self._get_upload_size_info(filename)
        if size_info:
            self.__upload_transfer_label.set(f"[File: {filename} - {size_info}]")
        else:
            self.__upload_transfer_label.set(f"[File: {filename}]")

    def on_download_transfer_progress(self, filename: str, progress: float):
        """Callback for download transfer progress."""
        self.__download_transfer_var.set(progress)
        size_info = self._get_download_size_info(filename)
        if size_info:
            self.__download_transfer_label.set(f"[File: {filename} - {size_info}]")
        else:
            self.__download_transfer_label.set(f"[File: {filename}]")

    def on_download_decrypt_progress(self, filename: str, progress: float):
        """Callback for download decryption progress."""
        self.__download_decrypt_var.set(progress)
        self.__download_decrypt_label.set(f"[File: {filename}]")

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
        self.__upload_transfer_var.set(0.0)
        self.__upload_transfer_label.set("")

    def __cancel_all_downloads(self):
        """Cancel all downloads and clear the download UI."""
        self.__transfer_handler.downloader.cancel_all_downloads()
        # Clear download progress UI
        self.__download_transfer_var.set(0.0)
        self.__download_transfer_label.set("")
        self.__download_decrypt_var.set(0.0)
        self.__download_decrypt_label.set("")
