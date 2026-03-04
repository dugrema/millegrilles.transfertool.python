import datetime
import json
import logging
import pathlib
from json import JSONDecodeError
from threading import Event, Thread
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

    def ajouter_download(self, tuuid, inline: bool = False):
        """Wrapper to add a download

        Args:
            tuuid: The tuuid of the file or directory to download
            inline: If True, download and decrypt in single pass (faster for small files)
        """
        if self.__repertoire is None:
            return
        tuuid_node = [
            f for f in self.__repertoire.fichiers if f["tuuid"] == tuuid
        ].pop()
        if tuuid_node["type_node"] == "Fichier":
            self.transfer_handler.ajouter_download_fichier(tuuid_node, inline=inline)
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
            if self.nav_frame is not None:
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
                            "Favoris",
                            *[p["metadata"]["nom"] for p in self.breadcrumb],
                        )
                        if len(self.breadcrumb) > 0
                        else pathlib.Path("Favoris")
                    )
                    self.nav_frame.set_breadcrumb(str(breadcrumb_path))  # type: ignore
            except Exception as e:
                self.__logger.exception("Erreur navigation repertoire")
                self.__set_erreur(e)


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
