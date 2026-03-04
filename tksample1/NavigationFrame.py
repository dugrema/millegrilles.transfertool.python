"""GUI Frame for File Navigation.

This module contains the NavigationFrame class for the tkinter GUI.
Core navigation logic is in Navigation.py (no tkinter dependency).
"""

import datetime
import logging
import pathlib

# Import tkinter at module level for GUI frames (they are only used in GUI mode)
import tkinter as tk
from tkinter import ttk
from typing import Optional

import pytz


class NavigationFrame(tk.Frame):
    """GUI frame for file system navigation controls."""

    @staticmethod
    def _format_size(size: int) -> str:
        """Format size in human-readable format."""
        size_float = float(size)
        for unit in ["B", "KB", "MB", "GB"]:
            if size_float < 1024:
                return f"{size_float:.1f}{unit}"
            size_float /= 1024
        return f"{size_float:.1f}TB"

    def __init__(self, navigation, *args, **kwargs):
        """Initialize the navigation frame.

        Args:
            navigation: Navigation instance for handling navigation logic
            *args: Arguments passed to tk.Frame
            **kwargs: Keyword arguments passed to tk.Frame
        """
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        super().__init__(*args, **kwargs)
        self.__navigation = navigation
        self.__repertoire = None

        # Add inline mode toggle
        self.__inline_var = tk.BooleanVar(value=False)

        self.__frame_actions = tk.Frame(master=self)
        self.__btn_creer_collection = tk.Button(
            master=self.__frame_actions,
            text="+ Collection",
            command=self.btn_creer_collection,
        )
        self.__btn_creer_collection.grid(row=0, column=0)
        self.__btn_download = tk.Button(
            master=self.__frame_actions,
            text="Download",
            command=self.btn_download_handler,
        )
        self.__btn_download.grid(row=0, column=1)
        self.__btn_upload = tk.Button(
            master=self.__frame_actions, text="Upload", command=self.btn_upload_handler
        )
        self.__btn_upload.grid(row=0, column=2)
        self.__btn_upload_dir = tk.Button(
            master=self.__frame_actions,
            text="Upload Dir",
            command=self.btn_upload_dir_handler,
        )
        self.__btn_upload_dir.grid(row=0, column=3)
        self.__btn_refresh = tk.Button(
            master=self.__frame_actions, text="Refresh", command=self.btn_refresh
        )
        self.__btn_refresh.grid(row=0, column=4)

        # Add inline mode checkbox
        self.__chk_inline = ttk.Checkbutton(
            master=self.__frame_actions,
            text="Inline",
            variable=self.__inline_var,
            command=self.__on_inline_toggle,
        )
        self.__chk_inline.grid(row=0, column=5, padx=5)

        self.__frame_breadcrumb = tk.Frame(master=self)
        self.__breadcrumb_path = pathlib.Path("Favoris/")
        self.breadcrumb = tk.StringVar(
            master=self.__frame_breadcrumb, value=str(self.__breadcrumb_path)
        )
        self.__breadcrumb_label = tk.Label(
            master=self.__frame_breadcrumb, textvariable=self.breadcrumb, justify="left"
        )
        self.__btn_up = tk.Button(
            master=self.__frame_breadcrumb, text="Up", command=self.btn_up_handler
        )

        # Configure grid layout for breadcrumb frame - Up button fixed on left, breadcrumb expands
        self.__frame_breadcrumb.grid_columnconfigure(
            0, weight=0
        )  # Up button - fixed width
        self.__frame_breadcrumb.grid_columnconfigure(1, weight=1)  # Breadcrumb - expand
        self.__frame_breadcrumb.grid_columnconfigure(2, weight=1)  # Spacer on right

        self.__btn_up.grid(row=0, column=0, sticky="w", padx=(5, 5))
        self.__breadcrumb_label.grid(row=0, column=1, sticky="ew", padx=(0, 5))

        self.__dir_frame = ttk.Frame(master=self)
        self.dirlist = ttk.Treeview(
            master=self.__dir_frame, columns=("taille", "type", "date"), height=25
        )
        self.dirlist["columns"] = ("taille", "type", "date")

        self.dirlist.heading("#0", text="Nom", anchor="w")
        self.dirlist.heading("taille", text="Taille")
        self.dirlist.heading("type", text="Type")
        self.dirlist.heading("date", text="Date")

        # Use dynamic widths for responsive layout
        self.dirlist.column("#0", width=400, minwidth=200)  # Changed from fixed 440
        self.dirlist.column("taille", width=50, anchor="se")
        self.dirlist.column("type", width=100)
        self.dirlist.column("date", width=110)

        # Configure grid weights for NavigationFrame
        self.grid_rowconfigure(0, weight=0)  # Actions - fixed height
        self.grid_rowconfigure(1, weight=0)  # Breadcrumb - fixed height
        self.grid_rowconfigure(2, weight=1)  # Directory frame - expand
        self.grid_columnconfigure(0, weight=1)  # Expand horizontally

        # Configure dir_frame weights
        self.__dir_frame.grid_rowconfigure(0, weight=1)
        self.__dir_frame.grid_columnconfigure(0, weight=1)

        self.dirlist.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=(0, 5))

        # Calling pack method w.r.to vertical
        # scrollbar
        verscrlbar = ttk.Scrollbar(
            self.__dir_frame, orient="vertical", command=self.dirlist.yview
        )
        # Configuring treeview
        verscrlbar.pack(side=tk.LEFT, fill="y")
        self.dirlist.configure(xscrollcommand=verscrlbar.set)

        self.grid()
        self.widget_bind()

    def grid(self, *args, **kwargs):
        """Grid layout for this frame."""
        self.__frame_actions.grid(row=0, column=0, sticky="w")
        self.__frame_breadcrumb.grid(row=1, column=0, sticky="w", padx=(5, 0))
        self.__dir_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)

        super().grid(*args, **kwargs)

    def widget_bind(self):
        """Bind mouse events to treeview."""
        self.dirlist.bind("<Button-3>", self.dirlist_rightclick_fichier)
        self.dirlist.bind("<Double-Button-1>", self.dirlist_doubleclick_fichier)

    def btn_up_handler(self):
        """Handle up button click."""
        self.__navigation.naviguer_up()

    def btn_download_handler(self):
        """Handle download button click."""
        selection = self.dirlist.selection()
        for tuuid in selection:
            inline_mode = self.__inline_var.get()
            self.__navigation.ajouter_download(tuuid, inline=inline_mode)

    def __on_inline_toggle(self):
        """Handle inline mode toggle - could update UI indicators."""
        # Optional: Update status bar or add visual indicator
        pass

    def btn_upload_handler(self):
        """Handle upload button click."""
        import tkinter.filedialog

        fichiers = tkinter.filedialog.askopenfilenames()
        for fichier in fichiers:
            self.__navigation.upload_fichier(fichier)

    def btn_upload_dir_handler(self):
        """Handle upload directory button click."""
        import tkinter.filedialog

        path_dir = tkinter.filedialog.askdirectory()
        if path_dir != "":
            self.__navigation.upload_directory(path_dir)

    def btn_refresh(self):
        """Handle refresh button click."""
        if self.__repertoire is not None:
            cuuid = self.__repertoire.cuuid
            self.__navigation.changer_cuuid(cuuid)

    def btn_creer_collection(self):
        """Handle create collection button click."""
        import tkinter.simpledialog

        nom_collection = tkinter.simpledialog.askstring(  # type: ignore
            title="Creer repertoire", prompt="Nom du repertoire"
        )
        self.__navigation.creer_collection(nom_collection)

    def set_breadcrumb(self, breadcrumb):
        """Set the breadcrumb path display.

        Args:
            breadcrumb: Either pathlib.Path or str representing current path
        """
        if isinstance(breadcrumb, pathlib.Path):
            breadcrumb = str(breadcrumb)
        self.breadcrumb.set(breadcrumb)

    def set_erreur(self, erreur: Optional[Exception]):
        """Set error display in treeview.

        Args:
            erreur: Exception or None
        """
        children = self.dirlist.get_children()
        if len(children) > 0:
            for c in children:
                self.dirlist.delete(c)
        if erreur is not None:
            self.dirlist.insert(
                "", "end", iid="Erreur", text="Erreur chargement, Refresh"
            )

    def clear_treeview(self):
        """Clear treeview content during navigation (thread-safe)."""
        self.after(0, self._clear_treeview_internal)

    def _clear_treeview_internal(self):
        """Internal method to clear treeview on main thread."""
        for item in self.dirlist.get_children():
            self.dirlist.delete(item)

    def afficher_repertoire(self, repertoire):
        """Display directory contents in treeview.

        Args:
            repertoire: Repertoire object containing file and directory info
        """
        self.__repertoire = repertoire
        children = self.dirlist.get_children()
        if len(children) > 0:
            self.dirlist.delete(*children)

        def sort_nom(item):
            metadata = item["metadata"]
            if item["type_node"] == "Fichier":
                tn = "2"
            else:
                tn = "1"
            # Case-insensitive sorting by name, matching CLI ls behavior
            name = metadata.get("nom") or item["tuuid"]
            return tn + name.lower()

        fichiers_tries = sorted(self.__repertoire.fichiers, key=sort_nom)

        for fichier in fichiers_tries:
            metadata = fichier["metadata"]
            nom_fichier = metadata.get("nom") or fichier["tuuid"]
            taille_fichier = ""
            type_node = fichier["type_node"]
            tuuid = fichier["tuuid"]
            if type_node in ["Collection", "Repertoire"]:
                type_fichier = "Repertoire"
                date_fichier = datetime.datetime.fromtimestamp(
                    fichier["derniere_modification"], tz=pytz.UTC
                )
                date_fichier_str = date_fichier.strftime("%Y-%m-%d %H:%M")
            else:
                version_courante = fichier["version_courante"]
                taille_fichier = self._format_size(version_courante["taille"])
                type_fichier = "Fichier"
                date_fichier = datetime.datetime.fromtimestamp(
                    metadata["dateFichier"], tz=pytz.UTC
                )
                date_fichier_str = date_fichier.strftime("%Y-%m-%d %H:%M")
            self.dirlist.insert(
                "",
                "end",
                iid=tuuid,
                text=nom_fichier,
                values=(taille_fichier, type_fichier, date_fichier_str),
            )

    def dirlist_rightclick_fichier(self, event):
        """Handle right-click on file in treeview."""
        pass

    def dirlist_doubleclick_fichier(self, event):
        """Handle double-click on file in treeview."""
        tuuid = self.dirlist.focus()
        item = self.dirlist.item(tuuid)
        values = item["values"]
        if values[1] != "Fichier":
            self.__navigation.changer_cuuid(tuuid)
        else:
            inline_mode = self.__inline_var.get()
            self.__navigation.ajouter_download(tuuid, inline=inline_mode)
