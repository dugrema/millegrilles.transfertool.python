"""GUI Frame for File Transfers.

This module contains the TransferFrame class for the tkinter GUI.
Core transfer logic is in FileTransfer.py (no tkinter dependency).
"""

import logging

# Import tkinter at module level for GUI frames (they are only used in GUI mode)
import tkinter as tk
from tkinter import ttk

from tksample1.Downloader import DownloadFichier
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

        # Call super().__init__() first before creating child widgets
        super().__init__(*args, **kwargs)

        self.__frame_upload = tk.Frame(master=self)
        self.upload_status_var = tk.StringVar(
            master=self.__frame_upload, value="Upload ..."
        )
        self.__upload_status_label = tk.Label(
            master=self.__frame_upload,
            textvariable=self.upload_status_var,
            justify="left",
        )
        self.__upload_status_label.grid(row=0, column=0)
        self.__treeview_upload = self.__add_treeview(self.__frame_upload)

        self.__frame_download = tk.Frame(master=self)
        self.download_status_var = tk.StringVar(
            master=self.__frame_download, value="Download ..."
        )
        self.__download_status_label = tk.Label(
            master=self.__frame_download,
            textvariable=self.download_status_var,
            justify="left",
        )
        self.__download_status_label.grid(row=0, column=0)
        self.__treeview_download = self.__add_treeview(self.__frame_download)

        # Configure grid weights for TransferFrame
        self.grid_rowconfigure(0, weight=1)  # Upload frame - expand
        self.grid_rowconfigure(1, weight=1)  # Download frame - expand
        self.grid_columnconfigure(0, weight=1)

        # Configure upload frame weights
        self.__frame_upload.grid_rowconfigure(1, weight=1)  # Treeview expands
        self.__frame_upload.grid_columnconfigure(0, weight=1)

        # Configure download frame weights
        self.__frame_download.grid_rowconfigure(1, weight=1)  # Treeview expands
        self.__frame_download.grid_columnconfigure(0, weight=1)

        self.add_widgets()

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

    def add_widgets(self):
        """Add widgets to layout."""
        self.__frame_upload.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=5,
            pady=5,
        )
        self.__frame_download.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=5,
            pady=5,
        )

    def grid(self, *args, **kwargs):
        """Grid layout for this frame."""
        super().grid(*args, **kwargs)

    def refresh_upload(self, courant, q: list):
        """Refresh the upload treeview with current uploads.

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
        """Refresh the download treeview with current downloads.

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
