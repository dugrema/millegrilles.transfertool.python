"""GUI Frame for Connection Management.

This module contains the ConnectionFrame class for the tkinter GUI.
Connection logic is in AuthUsager.py (no tkinter dependency).
"""

import logging
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional
from urllib.parse import urlparse


class ConnectionFrame(tk.Frame):
    """GUI frame for connection management controls."""

    def __init__(self, auth, *args, **kwargs):
        """Initialize the connection frame.

        Args:
            auth: Authentification instance for handling authentication logic
            *args: Arguments passed to tk.Frame
            **kwargs: Keyword arguments passed to tk.Frame
        """
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.auth = auth

        # Configure grid weights for responsive layout
        self.grid_rowconfigure(0, weight=0)  # Username - fixed height
        self.grid_rowconfigure(1, weight=0)  # Server URL - fixed height
        self.grid_rowconfigure(2, weight=0)  # Filehost selection - fixed height
        self.grid_rowconfigure(3, weight=0)  # TOTP code - fixed height
        self.grid_rowconfigure(4, weight=0)  # Status - fixed height
        self.grid_rowconfigure(5, weight=0)  # Buttons - fixed height
        self.grid_columnconfigure(0, weight=0)  # Labels - fixed width
        self.grid_columnconfigure(1, weight=1)  # Inputs - expand

        # Username input
        self.label_username = tk.Label(master=self, text="Nom usager:")
        self.username_entry = tk.Entry(master=self, width=30)

        # Server URL input
        self.label_server_url = tk.Label(master=self, text="URL serveur:")
        self.url_entry = tk.Entry(master=self, width=60)

        # Filehost selection dropdown
        self.label_filehost = tk.Label(master=self, text="Filehost:")
        self.filehost_var = tk.StringVar(master=self)
        self.filehost_combo = ttk.Combobox(
            master=self,
            textvariable=self.filehost_var,
            width=40,
            state="disabled",  # Disabled until connected
        )

        # TOTP code input
        self.label_totp = tk.Label(master=self, text="Code TOTP:")
        self.totp_entry = tk.Entry(master=self, width=12, show="●")

        # Connection status label
        self.status_var = tk.StringVar(master=self, value="Déconnecté")
        self.status_label = tk.Label(
            master=self,
            textvariable=self.status_var,
            font=("TkDefaultFont", 10, "bold"),
        )

        # Button frame
        self.button_frame = tk.Frame(master=self)
        self.connect_button = tk.Button(
            master=self.button_frame,
            text="Connecter",
            command=self.btn_connect,
            width=12,
        )
        self.disconnect_button = tk.Button(
            master=self.button_frame,
            text="Déconnecter",
            command=self.btn_disconnect,
            width=12,
            state=tk.DISABLED,  # Disabled when not connected
        )

        # Grid layout
        self.label_username.grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        self.label_server_url.grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.url_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        self.label_filehost.grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.filehost_combo.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        self.label_totp.grid(row=3, column=0, sticky="e", padx=5, pady=5)
        self.totp_entry.grid(row=3, column=1, sticky="w", padx=5, pady=5)

        self.status_label.grid(row=4, column=0, columnspan=2, sticky="w", pady=10)

        self.button_frame.grid(row=5, column=0, columnspan=2, sticky="w", pady=5)
        self.connect_button.grid(row=0, column=0, padx=5)
        self.disconnect_button.grid(row=0, column=1, padx=5)

        # Initialize with saved credentials if available
        self._load_saved_credentials()

    def _load_saved_credentials(self):
        """Load saved credentials from configuration."""
        # Check if auth has saved credentials
        if hasattr(self.auth, "get_saved_username"):
            username = self.auth.get_saved_username()
            if username:
                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(0, username)

        if hasattr(self.auth, "get_saved_url"):
            url = self.auth.get_saved_url()
            if url:
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, url)

    def set_connection_status(
        self, connected: bool, code_activation: Optional[str] = None
    ):
        """Set the connection status label.

        Args:
            connected: True if connected, False otherwise
            code_activation: Optional activation code to display
        """
        try:
            if code_activation:
                self.status_var.set(f"Code activation : {code_activation}")
            elif connected:
                self.populate_filehost_dropdown()
                self.status_var.set("Connecté")
                self.disconnect_button.config(state=tk.NORMAL)
                self.connect_button.config(state=tk.DISABLED)
            else:
                self.status_var.set("Déconnecté")
                self.disconnect_button.config(state=tk.DISABLED)
                self.connect_button.config(state=tk.NORMAL)
        except RuntimeError:
            pass  # Widget destroyed

    def btn_connect(self):
        """Handle connection button click with optional TOTP."""
        username = self.username_entry.get().strip()
        server_url = self.url_entry.get().strip()
        totp_code = self.totp_entry.get().strip() or None  # None if empty

        if not username:
            self._show_error("Nom usager requis")
            return

        if not server_url:
            self._show_error("URL serveur requise")
            return

        # Validate TOTP code if provided
        from tksample1.TotpValidation import validate_totp_code

        if totp_code:
            is_valid, error_msg = validate_totp_code(totp_code)
            if not is_valid:
                self._show_error(error_msg)
                return

        # Call auth with optional TOTP
        self.auth.authentifier(username, server_url, totp_code=totp_code)
        self.set_connection_status(connected=True)

        # Clear TOTP field after authentication attempt
        self.totp_entry.delete(0, tk.END)

    def switch_to_tab(self, tab_index: int):
        """Switch notebook tab after successful auto-connect.

        Args:
            tab_index: Index of the tab to switch to (0=Connection, 1=Navigation, 2=Transferts)
        """
        try:
            notebook = self.master
            if hasattr(notebook, "select"):
                notebook.select(tab_index)
        except RuntimeError:
            pass  # Widget destroyed

    def btn_disconnect(self):
        """Handle disconnection button click."""
        self.auth.effacer_usager()
        self.auth.deconnecter()
        self.set_connection_status(connected=False)
        self.__logger.info("Usager déconnecté, configuration supprimée")

    def populate_filehost_dropdown(self):
        """Populate filehost dropdown with available filehosts."""
        filehosts = self.auth.get_filehosts()
        if filehosts:
            self.filehost_combo.config(state="normal")
            self.filehost_combo.delete(0, "end")

            options = []
            for idx, fh in enumerate(filehosts):
                url = fh.get("url_external", "Unknown")
                hostname = urlparse(url).hostname or "Unknown"
                marker = (
                    " (auto)" if idx == self.auth.get_current_filehost_idx() else ""
                )
                options.append(f"{hostname}{marker}")

            self.filehost_combo["values"] = options
            self.filehost_combo.current(self.auth.get_current_filehost_idx())
            self.filehost_combo.config(state="readonly")  # Dropdown, not editable

            # Bind selection change
            self.filehost_combo.bind("<<ComboboxSelected>>", self.on_filehost_selected)
            self.__logger.info(
                f"Populated filehost dropdown with {len(filehosts)} options"
            )

    def on_filehost_selected(self, event):
        """Handle filehost selection change."""
        new_idx = self.filehost_combo.current()
        if new_idx >= 0:
            success = self.auth.set_filehost_idx(new_idx)
            if success:
                selected_fh = self.auth.get_current_filehost()
                url = selected_fh.get("url_external", "Unknown")
                hostname = urlparse(url).hostname or "Unknown"
                self.status_var.set(f"Connecté - Filehost: {hostname}")
                self.__logger.info(f"Filehost changed to: {hostname}")
            else:
                # Restore previous selection on error
                prev_idx = self.auth.get_current_filehost_idx()
                self.filehost_combo.current(prev_idx)

    def _show_error(self, message: str):
        """Show error message to user.

        Args:
            message: Error message to display
        """
        messagebox.showerror("Erreur", message)
        self.__logger.error(message)
