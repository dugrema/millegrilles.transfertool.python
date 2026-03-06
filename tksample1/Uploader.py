from __future__ import annotations

import datetime
import json
import logging
import mimetypes
import os.path
import pathlib
import tempfile
import time
import warnings
from threading import Event, Lock, Thread
from typing import Optional, Union
from urllib import parse

import requests
import socketio.exceptions
import urllib3.exceptions
from millegrilles_messages.chiffrage.Mgs4 import (
    CipherMgs4,
    chiffrer_document,
    chiffrer_document_nouveau,
)
from millegrilles_messages.chiffrage.SignatureDomaines import SignatureDomaines
from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_messages.messages.Hachage import Hacheur
from wakepy import keep

from tksample1.AuthUsager import Authentification
from tksample1.Navigation import Repertoire, sync_collection
from tksample1.ProgressManager import ProgressManager

# Suppress wakepy ActivationWarning when DBus services are not available
warnings.filterwarnings(
    "ignore",
    message="Could not activate wakepy Mode",
)
# Suppress urllib3 InsecureRequestWarning for unverified HTTPS requests
warnings.filterwarnings(
    "ignore",
    message="Unverified HTTPS request",
    category=urllib3.exceptions.InsecureRequestWarning,
)


class CancelledUploadException(Exception):
    """Custom exception for cancelled uploads."""

    pass


class UploadRepertoire:
    def __init__(
        self,
        cuuid_parent: str,
        path_dir: pathlib.Path,
        parent: Optional[UploadRepertoire] = None,  # type: ignore[no-redef]
    ):
        self.__cuuid_parent = cuuid_parent
        self.__path_dir = path_dir
        self.__parent = parent
        self.taille = None
        self.nombre_sous_fichiers = None
        self.__taille_uploade = 0
        self.fichiers_uploades = 0

        # Progress tracking attributes for GUI
        self.taille_originale = 0  # Will be calculated
        self.taille_chiffree = 0  # Encrypted size
        self.taille_uploadee = 0  # Cumulative uploaded bytes

        self.upload_complete = Event()
        self.__cancel_event = Event()

    def cancel(self):
        """Cancel the upload."""
        self.__cancel_event.set()

    def is_cancelled(self):
        """Check if the upload has been cancelled."""
        return self.__cancel_event.is_set()

    def cancel_event(self):
        """Get the cancel event for checking during upload."""
        return self.__cancel_event

    def add_chunk_uploade(self, taille: int):
        if self.__parent is not None:
            self.__parent.add_chunk_uploade(taille)
        else:
            self.__taille_uploade += taille

    def add_fichiers_traite(self, compte: int):
        self.fichiers_uploades += compte

    @property
    def taille_uploade(self):
        return self.__taille_uploade

    @property
    def cuuid_parent(self):
        return self.__cuuid_parent

    @property
    def path(self):
        return self.__path_dir

    def preparer_taille(self):
        if self.taille is None:
            taille_rep, nombre_fichiers_reps = self.__preparer_recursif(self.__path_dir)
            self.taille = taille_rep
            self.nombre_sous_fichiers = nombre_fichiers_reps

    def __preparer_recursif(self, path_rep: pathlib.Path) -> tuple[int, int]:
        compte_fichiers = 0
        taille_fichiers = 0
        for f in path_rep.iterdir():
            if f.is_file():
                taille_fichiers += f.stat().st_size
                compte_fichiers += 1
            else:
                taille_rep, nombre_fichiers_reps = self.__preparer_recursif(f)
                compte_fichiers += nombre_fichiers_reps
                taille_fichiers += taille_rep

        return taille_fichiers, compte_fichiers

    def wait(self):
        """Wait for upload to complete."""
        self.upload_complete.wait()


class UploadFichier:
    def __init__(
        self,
        cuuid: str,
        path_fichier: pathlib.Path,
        parent: Optional[UploadRepertoire] = None,  # type: ignore
    ):
        self.cuuid = cuuid
        self.__path_fichier = path_fichier
        self.__parent = parent
        self.taille = path_fichier.stat().st_size
        self.__taille_uploade = 0

        # Progress tracking attributes for GUI
        self.taille_originale = self.taille  # Original file size
        self.taille_chiffree = 0  # Encrypted size (will be set during encryption)
        self.taille_uploadee = 0  # Cumulative uploaded bytes

        self.batch_token = None
        self.upload_complete = Event()
        self.__cancel_event = Event()

    def cancel(self):
        """Cancel the upload."""
        self.__cancel_event.set()

    def is_cancelled(self):
        """Check if the upload has been cancelled."""
        return self.__cancel_event.is_set()

    def cancel_event(self):
        """Get the cancel event for checking during upload."""
        return self.__cancel_event

    def add_chunk_uploade(self, taille: int):
        if self.__parent:
            self.__parent.add_chunk_uploade(taille)
        else:
            self.__taille_uploade += taille

    def reset_taille_uploade(self):
        self.add_chunk_uploade(-1 * self.__taille_uploade)
        self.__taille_uploade = 0

    @property
    def taille_uploade(self):
        return self.__taille_uploade

    @property
    def path(self):
        return self.__path_fichier

    @property
    def mimetype(self):
        guess = mimetypes.guess_type(self.__path_fichier)[0]
        if guess is None:
            return "application/octet-stream"
        return guess

    def wait(self):
        """Wait for upload to complete."""
        self.upload_complete.wait()


UPLOAD_SPLIT_SIZE = 100_000_000


class Uploader:
    def __init__(
        self,
        stop_event,
        connexion: Authentification,
        progress_manager: Optional[ProgressManager] = None,
        progress_wrapper=None,
        transfer_handler=None,
    ):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event
        self.__connexion = connexion
        self.__tmp_path = connexion.tmp_path
        self.__upload_queue = list()
        self.__upload_pret = Event()

        self.__https_session: Optional[requests.Session] = None
        self.__certificats_chiffrage: Optional[list[EnveloppeCertificat]] = None

        self.__navigation = None
        self.__upload_en_cours: Optional[Union[UploadFichier, UploadRepertoire]] = None
        self.__event_upload_in_progress = Event()
        self.__progress_wrapper = (
            progress_wrapper  # CLI progress bar wrapper (deprecated)
        )
        self.__progress_manager = progress_manager  # GUI progress manager
        self.__transfer_handler = transfer_handler

        # Track active uploads for cancellation
        self.__active_uploads: list = []
        self.__active_uploads_lock = Lock()

        self.__thread = Thread(name="uploader", target=self.upload_thread, daemon=False)
        self.__thread.start()
        # self.__thread_label = Thread(name="uploader_label", target=self.__upload_label_thread, daemon=False)
        # self.__thread_label.start()

        self.__init_mime_types()

    def __update_progress(self, phase: str, delta: int):
        """Update progress for the specified phase.

        Args:
            phase: Either 'encrypt' or 'transfer'
            delta: Bytes processed in this update (incremental)
        """
        # Update CLI progress wrapper
        if self.__progress_wrapper:
            if phase == "encrypt":
                self.__progress_wrapper.update_encrypt(delta)
            elif phase == "transfer":
                self.__progress_wrapper.update_transfer(delta)

        # Track cumulative progress for ProgressManager
        if self.__progress_manager and self.__upload_en_cours:
            filename = getattr(
                self.__upload_en_cours, "path", pathlib.Path("unknown")
            ).name

            if phase == "encrypt":
                # Update cumulative encrypted size
                if hasattr(self.__upload_en_cours, "taille_chiffree"):
                    self.__upload_en_cours.taille_chiffree += delta

                    # Calculate percentage - use original file size as denominator
                    if hasattr(self.__upload_en_cours, "taille_originale"):
                        progress = (
                            self.__upload_en_cours.taille_chiffree
                            / self.__upload_en_cours.taille_originale
                        ) * 100
                        self.__progress_manager.update_upload_encrypt(
                            filename, progress
                        )

            elif phase == "transfer":
                # Update cumulative uploaded size
                self.__upload_en_cours.taille_uploadee += delta

                # Calculate percentage - use encrypted size as denominator
                if hasattr(self.__upload_en_cours, "taille_chiffree"):
                    progress = min(
                        100.0,
                        (
                            self.__upload_en_cours.taille_uploadee
                            / max(1, self.__upload_en_cours.taille_chiffree)
                        )
                        * 100,
                    )
                    self.__progress_manager.update_upload_transfer(filename, progress)

    def __init_mime_types(self):
        import tksample1

        path_module = pathlib.Path(os.path.abspath(tksample1.__file__))
        path_json = pathlib.Path(path_module.parent, "mimetypes.json")
        with open(path_json) as fichier:
            json_mt = json.load(fichier)
            for ext, mt in json_mt.items():
                mimetypes.add_type(mt, "." + ext)

    def set_navigation(self, navigation):
        self.__navigation = navigation

    def get_active_uploads(self):
        """Get list of active uploads (currently being processed or queued).

        Returns:
            List of UploadFichier or UploadRepertoire instances
        """
        with self.__active_uploads_lock:
            # Return only uploads that are not yet complete
            return [u for u in self.__active_uploads if not u.upload_complete.is_set()]

    def cancel_upload(self, upload_item):
        """Cancel a specific upload.

        Args:
            upload_item: UploadFichier or UploadRepertoire instance to cancel

        Returns:
            True if cancellation was initiated, False if upload not found
        """
        with self.__active_uploads_lock:
            if upload_item in self.__active_uploads:
                upload_item.cancel()
                return True
        return False

    def cancel_all_uploads(self):
        """Cancel all active uploads."""
        with self.__active_uploads_lock:
            for upload_item in self.__active_uploads:
                if not upload_item.upload_complete.is_set():
                    upload_item.cancel()

    def _remove_completed_upload(self, upload_item):
        """Remove a completed or cancelled upload from active list.

        Args:
            upload_item: UploadFichier or UploadRepertoire instance
        """
        with self.__active_uploads_lock:
            if upload_item in self.__active_uploads:
                self.__active_uploads.remove(upload_item)

        # Remove from ProgressManager queue
        if self.__progress_manager:
            filename = getattr(upload_item, "path", pathlib.Path("unknown")).name
            self.__progress_manager.remove_from_upload_queue(filename)

    @property
    def progress_wrapper(self):
        """Get the progress wrapper for CLI mode."""
        return self.__progress_wrapper

    @progress_wrapper.setter
    def progress_wrapper(self, value):
        """Set the progress wrapper for CLI mode."""
        self.__progress_wrapper = value

    @property
    def progress_manager(self):
        """Get the progress manager for GUI mode."""
        return self.__progress_manager

    @progress_manager.setter
    def progress_manager(self, value):
        """Set the progress manager for GUI mode."""
        self.__progress_manager = value

    def quit(self):
        self.__upload_pret.set()

    def set_url_upload(self, url_upload: parse.ParseResult):
        self.__url_upload = url_upload

    def ajouter_upload(
        self, cuuid_parent: str, path_upload: str | pathlib.Path
    ) -> UploadFichier | UploadRepertoire:
        path_upload = pathlib.Path(path_upload)  # type: ignore
        if path_upload.is_dir():  # type: ignore
            upload_item = UploadRepertoire(cuuid_parent, path_upload)  # type: ignore
        else:  # type: ignore
            upload_item = UploadFichier(cuuid_parent, path_upload)  # type: ignore
        self.__upload_queue.append(upload_item)
        self.__upload_pret.set()

        # Track active upload for cancellation
        with self.__active_uploads_lock:
            self.__active_uploads.append(upload_item)

        # Add to ProgressManager queue for GUI display
        if self.__progress_manager:
            file_size = (
                upload_item.path.stat().st_size if not path_upload.is_dir() else 0
            )
            self.__progress_manager.add_to_upload_queue(
                {
                    "filename": upload_item.path.name,
                    "size": file_size,
                }
            )

        # Notify TransferHandler to update UI
        if self.__transfer_handler:
            self.__transfer_handler.set_upload_dirty()

        return upload_item  # type: ignore

    def upload_thread(self):
        try:
            while self.__stop_event.is_set() is False:
                # self.update_upload_status()
                self.__event_upload_in_progress.clear()
                if self.__navigation is not None:
                    self.__navigation.refresh()
                self.__upload_pret.wait()
                self.__upload_pret.clear()

                with keep.running():  # Empecher sleep mode
                    while True:
                        # self.update_upload_status()
                        try:
                            self.__upload_en_cours = self.__upload_queue.pop(0)
                            self.__event_upload_in_progress.set()

                            # Set current upload in ProgressManager
                            if self.__progress_manager and self.__upload_en_cours:
                                item_name = getattr(
                                    self.__upload_en_cours,
                                    "path",
                                    pathlib.Path("unknown"),
                                ).name
                                self.__progress_manager.set_current_upload(
                                    {"filename": item_name}
                                )
                        except IndexError:
                            break
                        else:
                            if self.__stop_event.is_set():
                                return  # Stopping
                            # Check if this specific upload has been cancelled
                            if (
                                self.__upload_en_cours is not None
                                and self.__upload_en_cours.is_cancelled()
                            ):
                                self.__logger.info(
                                    "Upload cancelled before starting: %s",
                                    self.__upload_en_cours.path,
                                )
                                self._remove_completed_upload(self.__upload_en_cours)
                                continue
                            try:
                                # self.update_upload_status()
                                if isinstance(self.__upload_en_cours, UploadFichier):
                                    self.upload_fichier(self.__upload_en_cours)
                                elif isinstance(
                                    self.__upload_en_cours, UploadRepertoire
                                ):
                                    self.upload_repertoire(self.__upload_en_cours)
                                else:
                                    self.__logger.error(
                                        "Type upload non supporte : %s"
                                        % self.__upload_en_cours
                                    )
                            except Exception:  # type: ignore
                                self.__logger.exception("Erreur upload")
                            finally:
                                # Reset current upload in ProgressManager
                                if self.__progress_manager:
                                    self.__progress_manager.set_current_upload(None)
                                self.__upload_en_cours = None
        except Exception:  # type: ignore
            self.__logger.exception("upload_thread interrompue par error")
            self.__stop_event.set()  # Causer l'arret de l'application
            self.__upload_queue.clear()
        finally:
            self.__upload_en_cours = None  # S'assurer que le label est mis a Inactif

    def upload_status(self):
        status = self.__upload_status()
        return status, self.__upload_en_cours, self.__upload_queue

    def __upload_status(self):
        if isinstance(self.__upload_en_cours, UploadRepertoire):
            if self.__upload_en_cours.taille is None:
                self.__upload_en_cours.preparer_taille()

        if self.__upload_en_cours is not None:
            try:
                progres = int(
                    self.__upload_en_cours.taille_uploade
                    * 100.0
                    / self.__upload_en_cours.taille  # type: ignore
                )  # type: ignore
                fichiers_restants = len(self.__upload_queue)
                if isinstance(self.__upload_en_cours, UploadRepertoire):
                    if self.__upload_en_cours.nombre_sous_fichiers is not None:
                        fichiers_restants += (
                            self.__upload_en_cours.nombre_sous_fichiers
                            - self.__upload_en_cours.fichiers_uploades
                        )
                if fichiers_restants > 0:
                    return "Uploading %d%% (%d fichiers restants)" % (
                        progres,
                        fichiers_restants,
                    )
                else:
                    return "Uploading %d%%" % progres
            except Exception:
                self.__logger.debug("Erreur update upload")
                return "Uploading ..."
        elif len(self.__upload_queue) > 0:
            return "Uploading ..."
        else:
            return "Upload inactif"

    def upload_repertoire(
        self, upload: UploadRepertoire, rep_parent: Optional[Repertoire] = None
    ):
        # Check if upload has been cancelled before starting
        if upload.is_cancelled():
            self.__logger.info("Upload cancelled: %s", upload.path)
            upload.upload_complete.set()
            self._remove_completed_upload(upload)
            return

        if rep_parent is None:
            cuuid_parent = upload.cuuid_parent
            while True:
                if self.__stop_event.is_set() is True or upload.is_cancelled():
                    if upload.is_cancelled():
                        self.__logger.info("Upload cancelled: %s", upload.path)
                    return  # Stopping
                try:
                    rep_parent = sync_collection(self.__connexion, cuuid_parent)
                    break
                except socketio.exceptions.TimeoutError:
                    self.__logger.exception(
                        "upload_repertoire Erreur sync collection (1), retry dans 20 secondes"
                    )
                    time.sleep(20)
        else:
            cuuid_parent = rep_parent.cuuid

        # Verifier si le repertoire existe deja dans le parent
        nom_repertoire = upload.path.name

        try:
            rep_existant = [
                f for f in rep_parent.fichiers if f["metadata"]["nom"] == nom_repertoire
            ].pop()
            cuuid_courant = rep_existant["tuuid"]
            while True:
                if self.__stop_event.is_set() is True or upload.is_cancelled():
                    if upload.is_cancelled():
                        self.__logger.info("Upload cancelled: %s", upload.path)
                    return  # Stopping
                try:
                    rep_courant = sync_collection(self.__connexion, cuuid_courant)
                    break
                except socketio.exceptions.TimeoutError:
                    self.__logger.exception(
                        "upload_repertoire Erreur sync collection (2), retry dans 20 secondes"
                    )
                    time.sleep(20)

        except IndexError:
            rep_existant = None
            while True:
                if self.__stop_event.is_set() is True or upload.is_cancelled():
                    if upload.is_cancelled():
                        self.__logger.info("Upload cancelled: %s", upload.path)
                    return  # Stopping
                try:
                    # Creer repertoire
                    cuuid_courant = self.creer_collection(nom_repertoire, cuuid_parent)
                    rep_courant = Repertoire(list(), cuuid_courant)
                    break
                except socketio.exceptions.TimeoutError:
                    self.__logger.exception(
                        "upload_repertoire Erreur sync collection (1), retry dans 20 secondes"
                    )
                    time.sleep(20)

        # Generer dict des fichiers/sous-repertoires
        rep_map = dict()
        for item in rep_courant.fichiers:
            rep_map[item["metadata"]["nom"]] = item

        path_src = pathlib.Path(upload.path)
        liste_sous_items = list()
        for t in path_src.iterdir():
            liste_sous_items.append(t)

        # Trier contenu du repertoire : repertoires alphabetiques puis fichiers alphabetiques
        liste_sous_items = sorted(liste_sous_items, key=path_key)

        for t in liste_sous_items:
            nom_item = t.name
            if t.is_dir():
                # Check for cancellation before processing subdirectory
                if upload.is_cancelled():
                    self.__logger.info("Upload cancelled: %s", upload.path)
                    break
                rep_item = UploadRepertoire(cuuid_courant, t, upload)
                try:
                    item = rep_map[nom_item]
                    # Repertoire existe
                    try:
                        self.upload_repertoire(rep_item, rep_courant)
                    except CancelledUploadException:
                        self.__logger.info("Upload cancelled: %s", upload.path)
                        upload.upload_complete.set()
                        self._remove_completed_upload(upload)
                        return
                except KeyError:
                    # Nouveau repertoire
                    while True:
                        if self.__stop_event.is_set() is True or upload.is_cancelled():
                            if upload.is_cancelled():
                                self.__logger.info("Upload cancelled: %s", upload.path)
                            return  # Stopping
                        try:
                            self.creer_collection(nom_item, cuuid_courant)
                            break
                        except socketio.exceptions.TimeoutError:
                            self.__logger.exception(
                                "upload_repertoire Erreur creer collection (2), retry dans 20 secondes"
                            )
                            time.sleep(20)
                    try:
                        self.upload_repertoire(
                            rep_item, None
                        )  # Parent none force resync
                    except CancelledUploadException:
                        self.__logger.info("Upload cancelled: %s", upload.path)
                        upload.upload_complete.set()
                        self._remove_completed_upload(upload)
                        return
            else:
                # Fichier
                # Check for cancellation before processing file
                if upload.is_cancelled():
                    self.__logger.info("Upload cancelled: %s", upload.path)
                    break
                try:
                    item = rep_map[nom_item]
                    # Fichier existe, on l'ignore (TODO : verifier hachage si changement)
                except KeyError:
                    fichier_item = UploadFichier(cuuid_courant, t, upload)
                    try:
                        self.upload_fichier(fichier_item)
                    except CancelledUploadException:
                        self.__logger.info("Upload cancelled: %s", upload.path)
                        upload.upload_complete.set()
                        self._remove_completed_upload(upload)
                        return
                upload.add_fichiers_traite(1)

        upload.upload_complete.set()
        self._remove_completed_upload(upload)

    def upload_fichier(self, upload: UploadFichier):
        # Check if upload has been cancelled before starting
        if upload.is_cancelled():
            self.__logger.info("Upload cancelled: %s", upload.path)
            raise CancelledUploadException()

        retry_count = 0
        interval_retry = datetime.timedelta(seconds=20)
        while self.__stop_event.is_set() is False:
            try:
                if retry_count > 0:
                    self.__logger.info(
                        "Upload fichier %s retry %d" % (upload.path, retry_count)
                    )
                    upload.reset_taille_uploade()
                self.__upload_fichier_1pass(upload)
                upload.upload_complete.set()
                self._remove_completed_upload(upload)
                break
            except CancelledUploadException:
                # Upload was cancelled, don't retry
                self.__logger.info("Upload cancelled: %s", upload.path)
                upload.upload_complete.set()
                self._remove_completed_upload(upload)
                break
            except Exception:
                self.__logger.exception(
                    "Erreur upload fichier - retry in %s" % interval_retry
                )
                if upload.batch_token is not None:
                    # Delete le contenu partiellement uploade
                    batch_id = upload.batch_token["batchId"]
                    url_collections = self.__connexion.url_collections
                    if url_collections is not None and self.__https_session is not None:
                        url_put = f"https://{url_collections.hostname}:444{url_collections.path}/fichiers/upload/{batch_id}"
                        headers = {"x-token-jwt": upload.batch_token["token"]}
                        response = self.__https_session.delete(url_put, headers=headers)
                        if response.status_code not in (200, 404):
                            self.__logger.warning(
                                "Erreur suppression upload partiel, code : %d"
                                % response.status_code
                            )

                    # Reset token
                    upload.batch_token = None

                # Check for cancellation before retry
                if upload.is_cancelled():
                    self.__logger.info(
                        "Upload cancelled during retry wait: %s", upload.path
                    )
                    break

                # Attendre pour retry
                self.__stop_event.wait(timeout=interval_retry.seconds)
                retry_count += 1
        else:
            upload.upload_complete.set()
            self._remove_completed_upload(upload)

    def __upload_fichier_1pass(self, upload: UploadFichier):
        if self.__certificats_chiffrage is None:
            self.__certificats_chiffrage = self.__connexion.get_certificats_chiffrage()

        if self.__https_session is None:
            # Initialiser holder de session https
            self.__https_session = self.__connexion.get_https_session(certs=False)
            self.__connexion.authenticate(self.__https_session)

        # First pass, encrypt the file / get the fuuid
        if self.__connexion.ca is None:
            raise Exception("CA certificate not available")
        cle_ca = self.__connexion.ca.get_public_x25519()
        cipher = CipherMgs4(cle_ca)

        hacheur = Hacheur(hashing_code="blake2b-512", encoding="base58btc")

        # Reset color state before starting new upload
        if self.__progress_manager:
            self.__progress_manager.reset_upload_encrypt_complete(upload.path.name)
            self.__progress_manager.reset_upload_transfer_complete(upload.path.name)

        with tempfile.NamedTemporaryFile(dir=self.__tmp_path, delete=False) as tmpfile:
            with open(upload.path, "rb") as fichier:
                while cipher.hachage is None:
                    # Preparer chiffrage
                    prepare_file(
                        self.__stop_event,
                        fichier,
                        tmpfile,
                        cipher,
                        hacheur,
                        upload=upload,
                        on_progress=lambda current: self.__update_progress(
                            "encrypt", current
                        ),
                    )
            hachage_original = hacheur.finalize()
            secret_key = cipher.cle_secrete
            info_dechiffrage = cipher.get_info_dechiffrage(self.__certificats_chiffrage)
            fuuid = info_dechiffrage["hachage_bytes"]
            encrypted_size = cipher.taille_chiffree

            # Transition progress bar from encrypt to upload phase
            if self.__progress_wrapper:
                # The progress_wrapper might be an UploadProgressBar or just a ProgressBarWrapper
                if hasattr(self.__progress_wrapper, "transition_to_upload"):
                    self.__progress_wrapper.transition_to_upload()  # type: ignore[attr-defined]
                else:
                    # Fallback for ProgressBarWrapper - pass encrypted size as total
                    self.__progress_wrapper.transition_to_transfer_phase(
                        total=encrypted_size, desc="Uploading"
                    )

            # Set upload encrypt progress to 100% before starting transfer
            if self.__progress_manager:
                self.__progress_manager.set_upload_encrypt_final(upload.path.name)

            # Reset upload transfer progress bar before starting new upload
            if self.__progress_manager:
                self.__progress_manager.reset_upload_transfer(upload.path.name)

            # Preparer transaction
            stat_fichier = upload.path.stat()
            taille = stat_fichier.st_size
            date_fichier = int(stat_fichier.st_ctime)

            debut_upload = datetime.datetime.now()
            # Move pointer back to beginning of file
            tmpfile.seek(0)
            tmp_name = tmpfile.name
            while True:
                position = tmpfile.tell()
                if position == encrypted_size:
                    break  # Done
                stream = file_iterator(
                    self.__stop_event,
                    tmpfile,
                    UPLOAD_SPLIT_SIZE,
                    upload,
                    on_progress=lambda current: self.__update_progress(
                        "transfer", current
                    ),
                )
                url_put = f"{self.__connexion.filehost_url}/files/{fuuid}/{position}"
                response = self.__https_session.put(url_put, data=stream)
                response.raise_for_status()

            # Set upload transfer progress to 100% when upload is complete
            if self.__progress_manager:
                self.__progress_manager.set_upload_transfer_final(upload.path.name)

        fuuid_rechiffre = cipher.hachage
        # Clean up temporary file
        try:
            os.unlink(tmp_name)
        except Exception:
            pass
        if fuuid != fuuid_rechiffre:
            raise Exception("Digest uploaded mismatches initial value (fuuid)")
        cle_ca_chiffree = info_dechiffrage["cle"]
        cles_chiffrees = info_dechiffrage["cles"]
        taille_chiffree = cipher.taille_chiffree
        taille_dechiffree = cipher.taille_dechiffree

        # Signer cle secrete pour GrosFichiers
        signature_cle = SignatureDomaines.signer_domaines(
            secret_key, ["GrosFichiers"], cle_ca_chiffree
        )

        # Preparer et chiffrer la transaction
        data_dechiffre_transaction = {
            "nom": upload.path.name,
            "taille": taille,
            "dateFichier": date_fichier,
            "hachage_original": hachage_original,
        }
        doc_chiffre = chiffrer_document(
            secret_key, signature_cle.get_cle_ref(), data_dechiffre_transaction
        )
        transaction = {
            "cle_id": signature_cle.get_cle_ref(),
            "cuuid": upload.cuuid,
            "format": "mgs4",
            "fuuid": fuuid,
            "metadata": doc_chiffre,
            "mimetype": upload.mimetype,
            "nonce": info_dechiffrage["header"],
            "taille": taille_dechiffree,
        }

        transaction_cle = {
            "signature": signature_cle.to_dict(),
            "cles": cles_chiffrees,
        }
        if self.__connexion.formatteur is None:
            raise Exception("Formatter not available")
        transaction_cle, message_id = self.__connexion.formatteur.signer_message(
            Constantes.KIND_COMMANDE,
            transaction_cle,
            domaine="MaitreDesCles",
            action="ajouterCleDomaines",
            ajouter_chaine_certs=True,
        )
        self.__connexion.command(
            transaction,
            "GrosFichiers",
            "nouvelleVersion",
            attachments={"cle": transaction_cle},
        )

        url_confirmation = f"{self.__connexion.filehost_url}/files/{fuuid}"
        confirmation_response = self.__https_session.post(url_confirmation, timeout=300)

        if confirmation_response.status_code == 401:
            # Authenticate and retry
            self.__connexion.authenticate(self.__https_session)
            confirmation_response = self.__https_session.post(
                url_confirmation, timeout=300
            )

        # Note: should handle codes 200, 201 and 202 differently later on (200=>DONE, 202=>ONGOING)
        confirmation_response.raise_for_status()

        fin_upload = datetime.datetime.now()
        duree_upload = fin_upload - debut_upload
        self.__logger.debug(
            "%s Fin upload %s (%d bytes), duree %s"
            % (fin_upload, upload.path.name, taille_chiffree, duree_upload)
        )

    def creer_collection(self, nom: str, cuuid_parent: Optional[str] = None) -> str:
        metadata = {"nom": nom}
        if self.__connexion.ca is None:
            raise Exception("CA certificate not available")
        cipher, doc_chiffre = chiffrer_document_nouveau(self.__connexion.ca, metadata)
        info_dechiffrage = cipher.get_info_dechiffrage(
            self.__connexion.get_certificats_chiffrage()
        )
        if info_dechiffrage is None:
            raise Exception("Failed to get decryption info")
        cle_ca = info_dechiffrage["cle"]
        cles_dechiffrage = info_dechiffrage["cles"]

        # Signer cle
        signature_cle = SignatureDomaines.signer_domaines(
            cipher.cle_secrete, ["GrosFichiers"], cle_ca
        )

        # Ajouter information de cle a metadata de la collection
        doc_chiffre["cle_id"] = signature_cle.get_cle_ref()
        doc_chiffre["format"] = "mgs4"
        doc_chiffre["verification"] = info_dechiffrage["hachage_bytes"]

        transaction = {"metadata": doc_chiffre}

        if cuuid_parent:
            transaction["cuuid"] = cuuid_parent
        else:
            transaction["favoris"] = True

        commande_cle = {
            "signature": signature_cle.to_dict(),
            "cles": cles_dechiffrage,
        }
        if self.__connexion.formatteur is None:
            raise Exception("Formatter not available")
        commande_cle, message_id = self.__connexion.formatteur.signer_message(
            Constantes.KIND_COMMANDE,
            commande_cle,
            domaine="MaitreDesCles",
            action="ajouterCleDomaines",
            ajouter_chaine_certs=True,
        )

        reponse = self.__connexion.command(
            transaction,
            "GrosFichiers",
            "nouvelleCollection",
            attachments={"cle": commande_cle},
        )

        if reponse is None:
            raise Exception("No response from server")
        contenu = json.loads(reponse["contenu"])
        cuuid = contenu["tuuid"]

        return cuuid


UPLOAD_CHUNK_SIZE = 64 * 1024


# def file_iterator(stop_event: Event, fp, cipher, hacheur, maxsize, upload: UploadFichier):
#     current_output_size = 0
#     maxsize = maxsize - UPLOAD_CHUNK_SIZE
#     while current_output_size < maxsize:
#         if stop_event.is_set():
#             raise Exception("Stopping")
#         chunk = fp.read(UPLOAD_CHUNK_SIZE)
#         if len(chunk) == 0:
#             chunk = cipher.finalize()
#             yield chunk
#             return
#         chunk_size = len(chunk)
#         upload.add_chunk_uploade(chunk_size)
#         hacheur.update(chunk)
#         chunk = cipher.update(chunk)
#         if len(chunk) > 0:
#             current_output_size += len(chunk)
#             yield chunk


def file_iterator(
    stop_event: Event, fp, maxsize, upload: UploadFichier, on_progress=None
):
    """
    Iterate over file in chunks for upload.

    Args:
        stop_event: Event to check for cancellation
        fp: File pointer to read from
        maxsize: Maximum size to read
        upload: UploadFichier instance to track upload progress
        on_progress: Optional callback(current_bytes) for progress updates
    """
    current_output_size = 0
    maxsize = maxsize - UPLOAD_CHUNK_SIZE
    while current_output_size < maxsize:
        if stop_event.is_set() or upload.is_cancelled():
            raise Exception("Stopping")
        chunk = fp.read(UPLOAD_CHUNK_SIZE)
        if len(chunk) == 0:
            yield chunk
            return
        chunk_size = len(chunk)
        upload.add_chunk_uploade(chunk_size)
        if on_progress:
            on_progress(chunk_size)
        if len(chunk) > 0:
            current_output_size += len(chunk)
            yield chunk


def prepare_file(
    stop_event: Event, fp, fp_out, cipher, hacheur, upload=None, on_progress=None
) -> int:
    """
    Encrypt a file and write to output.

    Args:
        stop_event: Event to check for cancellation
        fp: Input file pointer
        fp_out: Output file pointer
        cipher: Cipher object for encryption
        hacheur: Hasher object for computing digest
        upload: UploadFichier instance for cancellation checking
        on_progress: Optional callback(current_bytes, total_bytes) for progress updates

    Returns:
        Total bytes encrypted
    """
    current_output_size = 0
    while True:
        if stop_event.is_set() or (upload is not None and upload.is_cancelled()):
            raise CancelledUploadException()
        chunk = fp.read(UPLOAD_CHUNK_SIZE)
        if len(chunk) == 0:
            chunk = cipher.finalize()
            if len(chunk) > 0:
                fp_out.write(chunk)
            return current_output_size
        hacheur.update(chunk)
        chunk = cipher.update(chunk)
        if len(chunk) > 0:
            current_output_size += len(chunk)
            fp_out.write(chunk)
            if on_progress:
                on_progress(len(chunk))


def path_key(item: pathlib.Path):
    if item.is_dir():
        key_type = 1
    elif item.is_file():
        key_type = 2
    else:
        key_type = 3
    return key_type, item.name
