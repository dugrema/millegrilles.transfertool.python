"""GUI Frame for User Authentication.

This module contains the AuthFrame class for the tkinter GUI.
Core authentication logic is in AuthUsager.py (no tkinter dependency).
"""

import logging

# Import tkinter at module level for GUI frames (they are only used in GUI mode)
import tkinter as tk


class AuthFrame(tk.Frame):
    """GUI frame for user authentication controls."""

    def __init__(self, auth, *args, **kwargs):
        """Initialize the authentication frame.

        Args:
            auth: Authentification instance for handling authentication logic
            *args: Arguments passed to tk.Frame
            **kwargs: Keyword arguments passed to tk.Frame
        """
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.auth = auth
        self.label_nomusager = tk.Label(master=self, text="Nom usager")
        self.entry_nomusager = tk.Entry(master=self, width=20)
        self.label_url_serveur = tk.Label(master=self, text="URL serveur")
        self.entry_serveur = tk.Entry(master=self, width=60)
        self.button_connecter = tk.Button(
            master=self, text="Connecter", command=self.btn_connecter_usager
        )
        self.button_deconnecter = tk.Button(
            master=self, text="Deconnecter", command=self.btn_deconnecter_usager
        )

        self.etat = tk.StringVar(master=self, value="Deconnecte")
        self.__etat_label = tk.Label(master=self, textvariable=self.etat)

    def pack(self):
        """Pack layout for this frame."""
        self.label_nomusager.pack()
        self.entry_nomusager.pack()
        self.label_url_serveur.pack()
        self.entry_serveur.pack()
        self.button_connecter.pack()
        self.button_deconnecter.pack()
        self.__etat_label.pack()
        super().pack()

    def grid(self, *args, **kwargs):
        """Grid layout for this frame."""
        self.label_nomusager.grid(row=0, column=0)
        self.entry_nomusager.grid(row=0, column=1, columnspan=2)
        self.label_url_serveur.grid(row=1, column=0)
        self.entry_serveur.grid(row=1, column=1, columnspan=2)
        self.button_connecter.grid(row=2, column=0)
        self.button_deconnecter.grid(row=2, column=1)
        self.__etat_label.grid(row=2, column=2)
        super().grid(*args, **kwargs)

    def set_etat(self, connecte=False, code_activation=None):
        """Set the connection status label.

        Args:
            connecte: True if connected, False otherwise
            code_activation: Optional activation code to display
        """
        if code_activation:
            self.etat.set("Code activation : %s" % code_activation)
            return

        try:
            if connecte:
                self.etat.set("Connecte")
            else:
                self.etat.set("Deconnecte")
        except RuntimeError:
            pass  # Fermeture

    def btn_connecter_usager(self):
        """Handle user connection button click."""
        nom_usager = self.entry_nomusager.get()
        valeur_url = self.entry_serveur.get()
        self.auth.authentifier(nom_usager, valeur_url)
        self.set_etat(connecte=True)

    def btn_deconnecter_usager(self):
        """Handle user disconnection button click."""
        self.auth.effacer_usager()
        self.auth.deconnecter()
        self.set_etat(connecte=False)
        self.__logger.info("Usager deconnecte, configuration supprimee")
