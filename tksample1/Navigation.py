import datetime
import json
import logging
import pathlib
import tkinter as tk
import tkinter.filedialog
from json import JSONDecodeError
from threading import Event, Thread
from tkinter import ttk
from typing import Optional

import multibase
import pytz
from millegrilles_messages.chiffrage.DechiffrageUtils import (
    dechiffrer_document_secrete,
    dechiffrer_reponse,
)

from tksample1.AuthUsager import Authentification

LOGGER = logging.getLogger(__name__)


class Repertoire:
    def __init__(self, fichiers: list, cuuid: Optional[str] = None):
        self.fichiers = fichiers
        self.cuuid = cuuid


class Navigation:
    # def __init__(self, stop_event, connexion: Authentification, downloader, uploader):
    def __init__(self, stop_event, connexion: Authentification, transfer_handler):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event
        self.frame = None
        self.connexion = connexion
        self.transfer_handler = transfer_handler
        self.nav_frame = None

        transfer_handler.set_navigation(self)

        self.__event_dirty = Event()
        self.__en_erreur: Optional[Exception] = None

        self.breadcrumb = list()

        self.__cuuid_a_charger = None
        self.__repertoire = None
        self.__current_cuuid = None

        self.__thread = Thread(name="Navigation", target=self.run, daemon=False)
        self.__thread.start()

    def quit(self):
        self.__event_dirty.set()

    def naviguer_up(self):
        """Navigate to parent directory in the breadcrumb"""
        if len(self.breadcrumb) > 0:
            self.breadcrumb.pop()
            # Reload the parent directory
            if len(self.breadcrumb) > 0:
                parent = self.breadcrumb[-1]
                cuuid = parent.get("tuuid")
            else:
                cuuid = None
            # Use background thread pattern like changer_cuuid()
            self.__cuuid_a_charger = cuuid
            self.__event_dirty.set()
            # Background thread will process navigation and update breadcrumb display

    def changer_cuuid(self, cuuid):
        """Wrapper to change the current directory cuuid"""
        self.__cuuid_a_charger = cuuid
        self.__event_dirty.set()
        # The background thread will process this and update the UI

    def ajouter_download(self, tuuid):
        """Wrapper to add a download"""
        if self.__repertoire is None:
            return
        tuuid_node = [
            f for f in self.__repertoire.fichiers if f["tuuid"] == tuuid
        ].pop()
        if tuuid_node["type_node"] == "Fichier":
            self.transfer_handler.ajouter_download_fichier(tuuid_node)
        else:
            self.transfer_handler.ajouter_download_repertoire(tuuid_node)

    def upload_fichier(self, fichier):
        """Wrapper to upload a file"""
        # Get current directory cuuid (last in breadcrumb or None)
        cuuid_parent = None
        if len(self.breadcrumb) > 0:
            cuuid_parent = self.breadcrumb[-1].get("tuuid")
        self.transfer_handler.ajouter_upload(cuuid_parent, fichier)

    def upload_directory(self, path_dir):
        """Wrapper to upload a directory"""
        cuuid_parent = None
        if len(self.breadcrumb) > 0:
            cuuid_parent = self.breadcrumb[-1].get("tuuid")
        self.transfer_handler.ajouter_upload(cuuid_parent, path_dir)

    def creer_collection(self, nom):
        """Wrapper to create a collection"""
        cuuid_parent = None
        if len(self.breadcrumb) > 0:
            cuuid_parent = self.breadcrumb[-1].get("tuuid")
        return self.transfer_handler.creer_collection(nom, cuuid_parent)

    def refresh(self):
        """Refresh the current view by reloading the current directory"""
        # Store current cuuid and trigger reload
        if len(self.breadcrumb) > 0:
            self.__current_cuuid = self.breadcrumb[-1].get("tuuid")
        else:
            self.__current_cuuid = None
        self.__cuuid_a_charger = self.__current_cuuid
        self.__event_dirty.set()

    def __set_erreur(self, erreur: Optional[Exception]):
        self.__en_erreur = erreur
        if erreur is not None:
            # Ajuster l'ecran
            self.nav_frame.set_erreur(erreur)  # type: ignore

    def run(self):
        self.__event_dirty.set()

        while self.__stop_event.is_set() is False:
            self.connexion.connect_event.wait()
            if self.__stop_event.is_set():
                return  # Stopping

            self.__event_dirty.wait()
            if self.__stop_event.is_set():
                return  # Stopping

            self.__event_dirty.clear()

            try:
                # Charger le repertoire with the stored cuuid
                cuuid_to_load = self.__cuuid_a_charger
                self.__charger_cuuid(cuuid_to_load)
            except Exception as e:
                self.__logger.exception("Erreur navigation")
                self.__set_erreur(e)

    def __charger_cuuid(self, cuuid: Optional[str] = None):
        # self.__event_dirty.clear()
        cuuid = cuuid or self.__cuuid_a_charger
        self.__cuuid_a_charger = None
        self.__set_erreur(None)

        # Disable treeview during navigation by clearing content
        if self.nav_frame is not None:
            self.nav_frame.clear_treeview()  # type: ignore

        if cuuid is None:
            # Navigate to root level - clear breadcrumb
            self.breadcrumb.clear()
            try:
                self.__repertoire = sync_collection(self.connexion)
                if self.nav_frame is not None:
                    self.nav_frame.afficher_repertoire(self.__repertoire)  # type: ignore
                    # Update breadcrumb display after loading
                    breadcrumb_path = pathlib.Path("Favoris")
                    self.nav_frame.set_breadcrumb(str(breadcrumb_path))  # type: ignore
            except Exception as e:
                self.__logger.exception("Erreur navigation root")
                self.__set_erreur(e)
        else:
            try:
                if self.breadcrumb[-1]["tuuid"] != cuuid:
                    append_cuuid = True
                else:
                    append_cuuid = False
            except IndexError:
                append_cuuid = True

            if append_cuuid and self.__repertoire is not None:
                # Changer breadcrumb, ajouter repertoire selectionne
                repertoire = [
                    c for c in self.__repertoire.fichiers if c["tuuid"] == cuuid
                ].pop()
                self.breadcrumb.append(repertoire)

            # Recuperer contenu du repertoire
            try:
                self.__repertoire = sync_collection(self.connexion, cuuid)
                if self.nav_frame is not None:
                    self.nav_frame.afficher_repertoire(self.__repertoire)  # type: ignore
                    # Update breadcrumb display after loading (works for both navigation up and down)
                    breadcrumb_path = (
                        pathlib.Path(
                            "Favoris", *[p["metadata"]["nom"] for p in self.breadcrumb]
                        )
                        if len(self.breadcrumb) > 0
                        else pathlib.Path("Favoris")
                    )
                    self.nav_frame.set_breadcrumb(str(breadcrumb_path))  # type: ignore
            except Exception as e:
                self.__logger.exception("Erreur navigation repertoire")
                self.__set_erreur(e)


class NavigationFrame(tk.Frame):
    def __init__(self, navigation, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__navigation = navigation
        self.__repertoire = None

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

        self.__frame_transfer_status = tk.Frame(master=self)
        self.upload_status_var = tk.StringVar(
            master=self.__frame_transfer_status, value="Upload inactif"
        )
        self.download_status_var = tk.StringVar(
            master=self.__frame_transfer_status, value="Download inactif"
        )
        self.__upload_status_label = tk.Label(
            master=self.__frame_transfer_status,
            textvariable=self.upload_status_var,
            justify="left",
        )
        self.__download_status_label = tk.Label(
            master=self.__frame_transfer_status,
            textvariable=self.download_status_var,
            justify="left",
        )
        self.__upload_status_label.pack(fill=tk.X)
        self.__download_status_label.pack(fill=tk.X)

        self.__dir_frame = ttk.Frame(master=self)
        self.dirlist = ttk.Treeview(
            master=self.__dir_frame, columns=("taille", "type", "date"), height=25
        )
        self.dirlist["columns"] = ("taille", "type", "date")

        self.dirlist.heading("taille", text="Taille")
        self.dirlist.heading("type", text="Type")
        self.dirlist.heading("date", text="Date")

        # Use dynamic widths for responsive layout
        self.dirlist.column("#0", width=400, minwidth=200)  # Changed from fixed 440
        self.dirlist.column("taille", width=90, anchor="se")
        self.dirlist.column("type", width=100)
        self.dirlist.column("date", width=145)

        # Configure grid weights for NavigationFrame
        self.grid_rowconfigure(0, weight=0)  # Actions - fixed height
        self.grid_rowconfigure(1, weight=0)  # Breadcrumb - fixed height
        self.grid_rowconfigure(2, weight=0)  # Transfer status - fixed height
        self.grid_rowconfigure(3, weight=1)  # Directory frame - expand
        self.grid_columnconfigure(0, weight=1)  # Expand horizontally

        # Configure dir_frame weights
        self.__dir_frame.grid_rowconfigure(0, weight=1)
        self.__dir_frame.grid_columnconfigure(0, weight=1)

        self.dirlist.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

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
        self.__frame_actions.grid(row=0, column=0, sticky="w")
        self.__frame_breadcrumb.grid(row=1, column=0, sticky="w", padx=(5, 0))
        self.__frame_transfer_status.grid(row=2, column=0, sticky="w")
        self.__dir_frame.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)

        super().grid(*args, **kwargs)

    def widget_bind(self):
        self.dirlist.bind("<Button-3>", self.dirlist_rightclick_fichier)
        self.dirlist.bind("<Double-Button-1>", self.dirlist_doubleclick_fichier)

    def btn_up_handler(self):
        self.__navigation.naviguer_up()

    def btn_download_handler(self):
        selection = self.dirlist.selection()
        for tuuid in selection:
            self.__navigation.ajouter_download(tuuid)

    def btn_upload_handler(self):
        fichiers = tkinter.filedialog.askopenfilenames()
        for fichier in fichiers:
            self.__navigation.upload_fichier(fichier)

    def btn_upload_dir_handler(self):
        path_dir = tkinter.filedialog.askdirectory()
        if path_dir != "":
            self.__navigation.upload_directory(path_dir)

    def btn_refresh(self):
        if self.__repertoire is not None:
            cuuid = self.__repertoire.cuuid
            self.__navigation.changer_cuuid(cuuid)

    def btn_creer_collection(self):
        nom_collection = tkinter.simpledialog.askstring(  # type: ignore
            title="Creer repertoire", prompt="Nom du repertoire"
        )
        self.__navigation.creer_collection(nom_collection)

    def set_breadcrumb(self, breadcrumb):
        # breadcrumb can be either pathlib.Path or str
        if isinstance(breadcrumb, pathlib.Path):
            breadcrumb = str(breadcrumb)
        self.breadcrumb.set(breadcrumb)

    def set_erreur(self, erreur: Optional[Exception]):
        children = self.dirlist.get_children()
        if len(children) > 0:
            for c in children:
                self.dirlist.delete(c)
        if erreur is not None:
            self.dirlist.insert(
                "", "end", iid="Erreur", text="Erreur chargement, Refresh"
            )

    def clear_treeview(self):
        """Clear treeview content during navigation (thread-safe)"""
        self.after(0, self._clear_treeview_internal)

    def _clear_treeview_internal(self):
        """Internal method to clear treeview on main thread"""
        # Clear all items from treeview
        for item in self.dirlist.get_children():
            self.dirlist.delete(item)

    def afficher_repertoire(self, repertoire):
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
            return tn + (metadata.get("nom") or item["tuuid"])

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
            else:
                version_courante = fichier["version_courante"]
                taille_fichier = version_courante["taille"]
                type_fichier = "Fichier"
                date_fichier = datetime.datetime.fromtimestamp(
                    metadata["dateFichier"], tz=pytz.UTC
                )
            self.dirlist.insert(
                "",
                "end",
                iid=tuuid,
                text=nom_fichier,
                values=(taille_fichier, type_fichier, date_fichier),
            )

    def dirlist_rightclick_fichier(self, event):
        pass

    def dirlist_doubleclick_fichier(self, event):
        tuuid = self.dirlist.focus()
        item = self.dirlist.item(tuuid)
        values = item["values"]
        if values[1] != "Fichier":
            self.__navigation.changer_cuuid(tuuid)
        else:
            self.__navigation.ajouter_download(tuuid)

    def set_download_status(self, status: str):
        self.download_status_var.set(status)

    def set_upload_status(self, status: str):
        self.upload_status_var.set(status)


def sync_collection(connexion: Authentification, cuuid: Optional[str] = None):
    skip = 0
    fichiers_complet = list()
    while True:
        requete = {
            "skip": skip,
            "cuuid": cuuid,
            "syncDate": None,
        }

        reponse_sync = connexion.request(requete, "GrosFichiers", "syncDirectory")
        decrypted_content = None
        try:
            contenu_sync = json.loads(reponse_sync["contenu"])
            if contenu_sync["ok"] is not True:
                raise Exception(
                    f"Error calling requete.GrosFichiers.syncDirectory: {contenu_sync.get('err')}"
                )
            decrypted_content = contenu_sync
        except JSONDecodeError:
            # Likely encrypted response (good)
            decrypted_content = dechiffrer_reponse(connexion.clecert, reponse_sync)  # type: ignore
            if decrypted_content is None:
                raise Exception("Decryption failed")

        keys = decrypted_content["keys"]  # type: ignore
        received_files = [
            f for f in decrypted_content["files"] if f["supprime"] is False
        ]  # type: ignore
        decrypted_keys, decrypted_files = decrypt_files(keys, received_files)
        fichiers_complet.extend(decrypted_files)

        skip += len(decrypted_content["files"])  # type: ignore

        if decrypted_content["complete"] is True:  # type: ignore
            break

    if len(fichiers_complet) == 0:
        # Aucun fichier a charger (repertoire vide)
        return Repertoire(list(), cuuid)

    rep = Repertoire(fichiers_complet, cuuid)

    return rep


def decrypt_files(keys: list[dict], received_files: list[dict]):
    decrypted_keys = dict()
    decrypted_files = list()

    for key in keys:
        key_copy = key.copy()
        key_copy["secret_key"] = multibase.decode(f"m{key['cle_secrete_base64']}")
        decrypted_keys[key_copy["cle_id"]] = key_copy

    for file in received_files:
        encrypted_metadata = file["metadata"]
        try:
            cle_id = (
                encrypted_metadata.get("cle_id")
                or encrypted_metadata.get("ref_hachage_bytes")
                or file["version_courante"]["fuuid"]
            )
            decryption_key = decrypted_keys[cle_id]
        except KeyError:
            LOGGER.info(f"Missing decryption key for {file['tuuid']}")
            continue
        try:
            secret_key = decryption_key["secret_key"]
            decrypted_metadata = dechiffrer_document_secrete(
                secret_key, encrypted_metadata
            )
            file = file.copy()
            file["metadata"] = decrypted_metadata
            file["secret_key"] = secret_key
            if decryption_key.get("nonce"):
                file["key_info"] = {
                    "nonce": decryption_key["nonce"],
                    "format": decryption_key.get("format"),
                }
            decrypted_files.append(file)
        except Exception:
            LOGGER.warning(f"Error decrypting file tuuid {file['tuuid']}")

    return decrypted_keys.values(), decrypted_files
