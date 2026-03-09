import logging
import pathlib
import time
import warnings
from enum import Enum, auto
from threading import Event, Lock, Thread
from typing import Optional, Union
from urllib import parse

import requests
import urllib3.exceptions
from millegrilles_messages.chiffrage.Mgs4 import DecipherMgs4
from requests import HTTPError
from wakepy import keep

from tksample1.AuthUsager import Authentification
from tksample1.exceptions import (
    DownloadFailedException,
    DownloadPausedException,
    DownloadRetryException,
)
from tksample1.Navigation import sync_collection
from tksample1.ProgressBar import DownloadProgressBar
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


class DownloadState(Enum):
    """Enum representing the state of a download."""

    IDLE = auto()
    DOWNLOADING = auto()
    PAUSED = auto()
    RESUMING = auto()
    RETRYING = auto()
    COMPLETED = auto()
    CANCELLED = auto()
    FAILED = auto()


class CancelledDownloadException(Exception):
    """Custom exception for cancelled downloads."""

    pass


class DownloadFichier:
    def __init__(self, download_info, destination: pathlib.Path, inline: bool = False):
        self.__info = download_info
        self.cle_secrete = download_info["secret_key"]
        metadata = download_info["metadata"]
        version_courante = download_info["version_courante"]
        self.fuuid = version_courante["fuuid"]
        self.nom = metadata["nom"]
        self.taille_chiffree = version_courante["taille"]

        try:
            self.nonce: str = version_courante["nonce"]
            self.format: str = version_courante["format"]
        except KeyError:
            key_info = download_info["key_info"]
            self.nonce = key_info["nonce"]
            self.format = key_info["format"]

        self.path_destination = destination
        self.inline = inline

        self.download_complete = Event()
        self.__cancel_event = Event()

        self.taille_recue = 0
        self.taille_dechiffree = 0

        # Phase 1: State tracking for pause/resume
        self.state = DownloadState.IDLE
        self.__pause_event = Event()
        self.__resume_event = Event()
        self.retry_count = 0
        self.last_error: Optional[Exception] = None
        self.can_resume = not inline  # Inline mode cannot be paused
        self.partial_download_path: Optional[pathlib.Path] = None

    def cancel(self):
        """Cancel the download and update state."""
        self.__cancel_event.set()
        if self.state not in (
            DownloadState.COMPLETED,
            DownloadState.CANCELLED,
            DownloadState.FAILED,
        ):
            self.state = DownloadState.CANCELLED

    def is_cancelled(self):
        """Check if the download has been cancelled."""
        return self.__cancel_event.is_set()

    def cancel_event(self):
        """Get the cancel event for checking during download."""
        return self.__cancel_event

    def wait(self):
        return self.download_complete.wait()

    @property
    def tuuid(self):
        return self.__info["tuuid"]

    def pause(self) -> bool:
        """Pause the download. Returns True if pause was successful."""
        if not self.can_be_paused():
            return False
        if self.state == DownloadState.DOWNLOADING:
            self.state = DownloadState.PAUSED
            self.__pause_event.set()
            return True
        return False

    def resume(self) -> bool:
        """Resume a paused download. Returns True if resume was successful."""
        if self.state == DownloadState.PAUSED:
            self.state = DownloadState.RESUMING
            self.__resume_event.set()
            return True
        return False

    def is_paused(self) -> bool:
        """Check if the download is paused."""
        return self.state == DownloadState.PAUSED

    def can_be_paused(self) -> bool:
        """Check if this download can be paused."""
        return self.can_resume and self.state == DownloadState.DOWNLOADING


class DownloadRepertoire:
    def __init__(self, repertoire, destination: pathlib.Path, inline: bool = False):
        self.__info = repertoire
        metadata = repertoire["metadata"]
        self.cuuid = repertoire["tuuid"]
        self.nom = metadata["nom"]
        self.download_complete = Event()
        self.__cancel_event = Event()
        self.repertoire = None
        self.destination = destination
        self.inline = inline

        # Progress tracking attributes for GUI (same as DownloadFichier)
        self.taille_chiffree = 0  # Total encrypted size (calculated later)
        self.taille_recue = 0  # Cumulative received bytes
        self.taille_dechiffree = 0  # Cumulative decrypted bytes

        # Recursive progress tracking
        self.total_files = 0  # Total number of files in directory tree
        self.completed_files = 0  # Number of files completed

    def cancel(self):
        """Cancel the directory download."""
        self.__cancel_event.set()

    def is_cancelled(self):
        """Check if the download has been cancelled."""
        return self.__cancel_event.is_set()

    def cancel_event(self):
        """Get the cancel event for checking during download."""
        return self.__cancel_event

    def wait(self):
        return self.download_complete.wait()

    @property
    def tuuid(self):
        return self.__info["tuuid"]

    def preparer_taille(self, connexion):
        # connexion.call()  # TODO Charger stats du repertoire pour obtenir taille totale
        pass


class Downloader:
    def __init__(
        self,
        stop_event: Event,
        connexion: Authentification,
        progress_manager: Optional[ProgressManager] = None,
        progress_wrapper=None,  # CLI progress bar wrapper (deprecated)
        transfer_handler=None,
    ):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event
        self.__connexion = connexion
        self.__download_queue = list()
        self.__download_pret = Event()
        self.__url_download: Optional[parse.ParseResult] = None

        self.__download_en_cours: Optional[
            Union[DownloadFichier, DownloadRepertoire]
        ] = None
        self.__event_download_in_progress = Event()
        self.__navigation = None
        self.__https_session: Optional[requests.Session] = None
        self.__progress_wrapper = (
            progress_wrapper  # CLI progress bar wrapper (deprecated)
        )
        self.__progress_manager = progress_manager  # GUI progress manager
        self.__transfer_handler = transfer_handler

        # Track active downloads for cancellation
        self.__active_downloads: list = []
        self.__active_downloads_lock = Lock()

        # Start the download thread
        self.__thread = Thread(
            name="downloader", target=self.download_thread, daemon=False
        )
        self.__thread.start()

    def __update_progress(self, phase: str, delta: int):
        """Update progress for the specified phase.

        Args:
            phase: Either 'transfer' or 'encrypt'
            delta: Bytes processed in this update (incremental)
        """
        # Update CLI progress wrapper
        if self.__progress_wrapper:
            if phase == "transfer":
                self.__progress_wrapper.update_transfer(delta)
            elif phase == "encrypt":
                self.__progress_wrapper.update_encrypt(delta)

        # Track cumulative progress for ProgressManager
        if self.__progress_manager and self.__download_en_cours:
            filename = getattr(self.__download_en_cours, "nom", "unknown")

            if phase == "transfer":
                # Update cumulative received size
                self.__download_en_cours.taille_recue += delta

                # Calculate percentage (capped at 100%)
                if hasattr(self.__download_en_cours, "taille_chiffree"):
                    progress = min(
                        100.0,
                        (
                            self.__download_en_cours.taille_recue
                            / max(1, self.__download_en_cours.taille_chiffree)
                        )
                        * 100,
                    )
                    self.__progress_manager.update_download_transfer(filename, progress)

            elif phase == "encrypt":
                # Update cumulative decrypted size
                self.__download_en_cours.taille_dechiffree += delta

                # Calculate percentage - use total encrypted size as denominator
                # (decrypted data size is typically similar to encrypted size)
                if hasattr(self.__download_en_cours, "taille_chiffree"):
                    progress = min(
                        100.0,
                        (
                            self.__download_en_cours.taille_dechiffree
                            / max(1, self.__download_en_cours.taille_chiffree)
                        )
                        * 100,
                    )
                    self.__progress_manager.update_download_decrypt(filename, progress)

    def quit(self):
        self.__download_pret.set()

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

    def set_navigation(self, navigation):
        self.__navigation = navigation

    def set_url_download(self, url_download: parse.ParseResult):
        self.__url_download = url_download

    def ajouter_download_fichier(
        self, download, destination=None, inline: bool = False
    ) -> DownloadFichier:
        destination = destination or self.__connexion.download_path
        if destination.exists() is False:
            destination.mkdir()

        download_item = DownloadFichier(download, destination, inline=inline)
        self.__download_queue.append(download_item)
        self.__download_pret.set()

        # Track active download
        with self.__active_downloads_lock:
            self.__active_downloads.append(download_item)

        # Add to ProgressManager queue for GUI display
        if self.__progress_manager:
            self.__progress_manager.add_to_download_queue(
                {
                    "filename": download_item.nom,
                    "size": download_item.taille_chiffree,
                    "tuuid": download_item.tuuid,
                    "inline": download_item.inline,
                }
            )

        # Notify TransferHandler to update UI
        if self.__transfer_handler:
            self.__transfer_handler.set_download_dirty()

        return download_item

    def ajouter_download_repertoire(
        self, repertoire, destination=None, inline: bool = False
    ):
        destination = destination or self.__connexion.download_path
        if destination.exists() is False:
            destination.mkdir()

        download_item = DownloadRepertoire(repertoire, destination, inline)
        self.__download_queue.append(download_item)
        self.__download_pret.set()

        # Track active download
        with self.__active_downloads_lock:
            self.__active_downloads.append(download_item)

        # Add to ProgressManager queue for GUI display
        if self.__progress_manager:
            self.__progress_manager.add_to_download_queue(
                {"filename": download_item.nom, "size": 0, "tuuid": download_item.tuuid}
            )

        # Notify TransferHandler to update UI
        if self.__transfer_handler:
            self.__transfer_handler.set_download_dirty()

        return download_item

    def get_active_downloads(self):
        """Get list of active downloads (currently being processed or queued).

        Returns:
            List of DownloadFichier or DownloadRepertoire instances
        """
        with self.__active_downloads_lock:
            # Return only downloads that are not yet complete
            return [
                d for d in self.__active_downloads if not d.download_complete.is_set()
            ]

    def cancel_download(self, download_item):
        """Cancel a specific download.

        Args:
            download_item: DownloadFichier or DownloadRepertoire instance to cancel

        Returns:
            True if cancellation was initiated, False if download not found
        """
        with self.__active_downloads_lock:
            if download_item in self.__active_downloads:
                download_item.cancel()
                return True
        return False

    def cancel_all_downloads(self):
        """Cancel all active downloads."""
        with self.__active_downloads_lock:
            for download_item in self.__active_downloads:
                if not download_item.download_complete.is_set():
                    download_item.cancel()

    def _remove_completed_download(self, download_item):
        """Remove a completed or cancelled download from active list.

        Args:
            download_item: DownloadFichier or DownloadRepertoire instance
        """
        with self.__active_downloads_lock:
            if download_item in self.__active_downloads:
                self.__active_downloads.remove(download_item)

        # Also remove from ProgressManager queue
        if self.__progress_manager:
            self.__progress_manager.remove_from_download_queue(download_item.tuuid)

    def download_thread(self):
        while self.__stop_event.is_set() is False:
            # self.update_download_status()
            self.__event_download_in_progress.clear()
            self.__download_pret.wait()
            self.__download_pret.clear()

            with keep.running():  # Empecher mode sleep
                while True:
                    try:
                        self.__download_en_cours = self.__download_queue.pop(0)
                        self.__event_download_in_progress.set()
                    except IndexError:
                        break
                    else:
                        if self.__stop_event.is_set():
                            return  # Stopping
                        if self.__download_en_cours is not None:
                            item_name = self.__download_en_cours.nom
                        else:
                            item_name = "unknown"
                        try:
                            # Set as current in ProgressManager before starting download
                            if self.__progress_manager and self.__download_en_cours:
                                item_name = self.__download_en_cours.nom
                                tuuid = self.__download_en_cours.tuuid
                                self.__progress_manager.set_current_download(
                                    {"filename": item_name, "tuuid": tuuid}
                                )

                            if isinstance(self.__download_en_cours, DownloadFichier):
                                self.download_fichier(self.__download_en_cours)
                                self.__logger.debug(
                                    "Fin download fichier %s" % item_name
                                )
                            elif isinstance(
                                self.__download_en_cours, DownloadRepertoire
                            ):
                                self.download_repertoire(self.__download_en_cours)
                                self.__logger.debug(
                                    "Fin download repertoire %s" % item_name
                                )
                            else:
                                self.__logger.error(
                                    "Type download non supporte : %s"
                                    % self.__download_en_cours
                                )
                        except CancelledDownloadException:
                            # Download was cancelled - set complete event to release wait()
                            self.__download_en_cours.download_complete.set()
                            pass
                        except Exception:
                            self.__logger.exception(
                                "Erreur download fichier %s" % item_name
                            )
                        finally:
                            # Clear current download from ProgressManager after completion
                            if self.__progress_manager:
                                self.__progress_manager.set_current_download(None)
                            self.__download_en_cours = None

    # def __download_label_thread(self):
    #     while self.__stop_event.is_set() is False:
    #         self.__event_download_in_progress.wait(timeout=5)
    #
    #         # if isinstance(self.__download_en_cours, DownloadRepertoire):
    #         #     if self.__download_en_cours.taille is None:
    #         #         self.__download_en_cours.preparer_taille()
    #
    #         self.update_download_status()
    #         time.sleep(1)
    #
    # def update_download_status(self):
    #     if self.__navigation is None:
    #         return  # Pas initialise
    #
    #     if self.__download_en_cours is not None:
    #         # try:
    #         #     progres = int(self.__download_en_cours.taille_downloade * 100.0 / self.__download_en_cours.taille)
    #         #     fichiers_restants = len(self.__download_queue)
    #         #     if isinstance(self.__download_en_cours, DownloadRepertoire):
    #         #         fichiers_restants += self.__download_en_cours.nombre_sous_fichiers - self.__download_en_cours.fichiers_uploades
    #         #     if fichiers_restants > 0:
    #         #         self.__navigation.set_upload_status(
    #         #             'Download %d%% (%d fichiers restants)' % (progres, fichiers_restants))
    #         #     else:
    #         #         self.__navigation.set_upload_status('Uploading %d%%' % progres)
    #         # except Exception as e:
    #         #     self.__logger.debug("Erreur update upload : %s" % e)
    #         self.__navigation.set_download_status('Downloading ...')
    #     elif len(self.__download_queue) > 0:
    #         self.__navigation.set_download_status('Downloading ...')
    #     else:
    #         self.__navigation.set_download_status('Download inactif')

    def download_status(self):
        status = self.__download_status()
        return status, self.__download_en_cours, self.__download_queue

    def __download_status(self):
        if self.__download_en_cours is not None:
            try:
                if isinstance(self.__download_en_cours, DownloadFichier):
                    progres = int(
                        self.__download_en_cours.taille_recue
                        * 100.0
                        / self.__download_en_cours.taille_chiffree
                    )
                    return "Downloading %d%%" % progres
                else:
                    return "Downloading ..."
            except Exception as e:
                self.__logger.debug("Erreur update upload : %s" % e)
                return "Downloading ..."
        elif len(self.__download_queue) > 0:
            return "Downloading ..."
        else:
            return "Download inactif"

    def _calculate_directory_size(self, repertoire_info, connexion):
        """
        Calculate total encrypted size of a directory and all nested contents.

        Args:
            repertoire_info: Directory metadata dict with tuuid and metadata
            connexion: Authentification instance

        Returns:
            tuple: (total_size, total_file_count)
        """
        total_size = 0
        total_files = 0

        # Fetch directory contents
        rep = sync_collection(connexion, repertoire_info["tuuid"])

        for item in rep.fichiers:
            if item["type_node"] == "Fichier":
                # File: add its encrypted size
                encrypted_size = item.get("version_courante", {}).get("taille", 0)
                total_size += encrypted_size
                total_files += 1
            elif item["type_node"] in ["Collection", "Repertoire"]:
                # Subdirectory: recursively calculate
                sub_size, sub_files = self._calculate_directory_size(item, connexion)
                total_size += sub_size
                total_files += sub_files

        # Handle empty directories: use placeholder size to avoid division by zero
        if total_files == 0:
            total_size = 1
            total_files = 1

        return total_size, total_files

    def download_repertoire(self, item: DownloadRepertoire):
        tuuid = item.cuuid

        # Check for cancellation before starting
        if item.is_cancelled():
            raise CancelledDownloadException()

        # Pre-calculate total size and file count
        total_size, total_files = self._calculate_directory_size(
            {"tuuid": tuuid, "metadata": {"nom": item.nom}}, self.__connexion
        )
        item.taille_chiffree = total_size
        item.total_files = total_files
        item.completed_files = 0

        # Check for cancellation after pre-calculation
        if item.is_cancelled():
            raise CancelledDownloadException()

        # Set as current download in ProgressManager (directory level)
        if self.__progress_manager:
            self.__progress_manager.set_current_download(
                {"filename": item.nom, "tuuid": item.tuuid}
            )

        rep = sync_collection(self.__connexion, tuuid)

        # Generer les downloads
        path_destination = pathlib.Path(item.destination, item.nom)
        path_destination.mkdir(exist_ok=True)

        try:
            for t in rep.fichiers:
                # Check for cancellation before processing each item
                if item.is_cancelled():
                    raise CancelledDownloadException()

                type_node = t["type_node"]
                if type_node == "Fichier":
                    try:
                        download_fichier = DownloadFichier(
                            t, path_destination, item.inline
                        )
                    except KeyError:
                        self.__logger.warning("Cle fichier manquante, skip : %s" % t)
                    else:
                        try:
                            # Create individual progress bar for this file
                            progress_bar = DownloadProgressBar(download_fichier.nom)

                            # Save current progress wrapper and set this file's wrapper
                            old_progress_wrapper = self.__progress_wrapper
                            self.__progress_wrapper = progress_bar.wrapper

                            # Get encrypted size from file info
                            encrypted_size = t.get("version_courante", {}).get(
                                "taille", None
                            )

                            # Start download phase
                            progress_bar.start_download(encrypted_size)

                            # Download the file
                            self.download_fichier(download_fichier)

                            # Transition to decrypt is handled by download_fichier
                            # Close progress bar after decryption completes
                            progress_bar.close()

                            # Restore old progress wrapper
                            self.__progress_wrapper = old_progress_wrapper

                            # *** NEW: Aggregate progress to parent directory ***
                            if self.__progress_manager and item.taille_chiffree > 0:
                                # Add file's received size to directory cumulative
                                item.taille_recue += download_fichier.taille_recue
                                item.taille_dechiffree += (
                                    download_fichier.taille_dechiffree
                                )

                                # Calculate directory-level progress percentage
                                transfer_progress = (
                                    item.taille_recue / item.taille_chiffree
                                ) * 100
                                decrypt_progress = (
                                    item.taille_dechiffree / item.taille_chiffree
                                ) * 100

                                # Report progress for the directory (not individual file)
                                self.__progress_manager.update_download_transfer(
                                    item.nom, min(100.0, transfer_progress)
                                )
                                self.__progress_manager.update_download_decrypt(
                                    item.nom, min(100.0, decrypt_progress)
                                )

                                # Track completed file count
                                item.completed_files += 1

                        except FileExistsError:
                            pass  # OK
                else:
                    # Download recursif des sous-repertoires
                    download_repertoire = DownloadRepertoire(
                        t, path_destination, item.inline
                    )
                    self.download_repertoire(download_repertoire)

                    # *** NEW: Aggregate subdirectory progress to parent ***
                    if self.__progress_manager:
                        item.taille_recue += download_repertoire.taille_recue
                        item.taille_dechiffree += download_repertoire.taille_dechiffree

                        # Update parent progress
                        if item.taille_chiffree > 0:
                            transfer_progress = (
                                item.taille_recue / item.taille_chiffree
                            ) * 100
                            decrypt_progress = (
                                item.taille_dechiffree / item.taille_chiffree
                            ) * 100

                            self.__progress_manager.update_download_transfer(
                                item.nom, min(100.0, transfer_progress)
                            )
                            self.__progress_manager.update_download_decrypt(
                                item.nom, min(100.0, decrypt_progress)
                            )

            # Mark directory download as complete
            item.download_complete.set()

            # *** NEW: Set final progress to 100% ***
            if self.__progress_manager:
                self.__progress_manager.set_download_transfer_complete(item.nom)
                self.__progress_manager.set_download_decrypt_complete(item.nom)
        except Exception as e:
            # Check if it's a cancellation
            if "cancelled" in str(e).lower():
                self.__logger.info(
                    "Directory download cancelled, cleaning up %s" % path_destination
                )
                # Clean up partially downloaded directory
                if path_destination.exists():
                    import shutil

                    shutil.rmtree(path_destination)
            raise

        # Remove from active downloads
        self._remove_completed_download(item)

    def download_fichier(self, item: DownloadFichier):
        """Dispatch to appropriate download method based on inline flag."""
        if item.inline:
            self._download_fichier_inline(item)
        else:
            self._download_fichier_twophase(item)

    def _download_fichier_inline(self, item: DownloadFichier):
        """Download and decrypt file in single pass (inline mode)."""
        self.__connexion.connect_event.wait()
        if self.__stop_event.is_set():
            raise Exception("Stopping")

        if item.is_cancelled():
            raise CancelledDownloadException()

        # Reset color state before starting new download
        if self.__progress_manager:
            self.__progress_manager.reset_download_transfer_complete(item.nom)
            self.__progress_manager.reset_download_decrypt_complete(item.nom)

        if item.format != "mgs4":
            raise Exception("Format de chiffrage non supporte")

        if self.__https_session is None:
            https_session = requests.Session()
            https_session.verify = False
            https_session.cert = None
            self.__https_session = https_session

        url_fichier = f"{self.__connexion.filehost_url}/files/{item.fuuid}"
        path_reception = pathlib.Path(item.path_destination, item.nom)
        path_reception_work = pathlib.Path(item.path_destination, item.nom + ".work")

        self.__logger.debug(
            "Debut inline download fichier %s (taille : %d)"
            % (path_reception_work, item.taille_chiffree)
        )

        try:
            # Download and decrypt in single pass
            decipher = DecipherMgs4(item.cle_secrete, item.nonce)
            with open(path_reception_work, "wb") as output:
                response = self.__https_session.get(url_fichier, stream=True)
                try:
                    response.raise_for_status()
                except HTTPError as e:
                    if e.response.status_code == 401:
                        self.__connexion.authenticate(self.__https_session)
                        response = self.__https_session.get(url_fichier, stream=True)
                        response.raise_for_status()
                    else:
                        raise e

                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if item.is_cancelled():
                        raise CancelledDownloadException()
                    if self.__stop_event.is_set():
                        raise Exception("Stopping")

                    # Decrypt chunk immediately
                    chunk_dechiffre = decipher.update(chunk)
                    if chunk_dechiffre:
                        output.write(chunk_dechiffre)
                        item.taille_dechiffree += len(chunk_dechiffre)

                    # Update progress
                    if self.__progress_wrapper:
                        self.__update_progress("transfer", len(chunk_dechiffre))
                    elif self.__progress_manager:
                        self.__update_progress("transfer", len(chunk_dechiffre))

            # Finalize decryption
            chunk_final = decipher.finalize()
            if chunk_final:
                with open(path_reception_work, "ab") as output:
                    output.write(chunk_final)
                    item.taille_dechiffree += len(chunk_final)
                    if self.__progress_wrapper:
                        self.__update_progress("transfer", len(chunk_final))
                    elif self.__progress_manager:
                        self.__update_progress("transfer", len(chunk_final))

            # Check for cancellation before finalization
            if item.is_cancelled():
                path_reception_work.unlink()
                raise CancelledDownloadException()

            # Rename work file to final destination
            if path_reception.exists():
                raise FileExistsError()
            path_reception_work.rename(path_reception)

            self.__logger.debug("Fichier %s dechiffre OK (inline)" % path_reception)

            # Set final progress to 100% for inline mode
            if self.__progress_manager:
                self.__progress_manager.set_download_transfer_final(item.nom)

            # Signal download completion
            item.download_complete.set()

        except FileExistsError:
            self.__logger.warning("Fichier %s existe deja" % path_reception)
            item.download_complete.set()
            return
        except Exception:
            if path_reception_work.exists():
                path_reception_work.unlink()
            raise

    def _download_fichier_twophase(self, item: DownloadFichier):
        """Download then decrypt file (traditional two-phase mode) with pause/resume support."""
        self.__connexion.connect_event.wait()
        if self.__stop_event.is_set():
            raise Exception("Stopping")

        if item.is_cancelled():
            raise CancelledDownloadException()

        # Reset color state before starting new download
        if self.__progress_manager:
            self.__progress_manager.reset_download_transfer_complete(item.nom)
            self.__progress_manager.reset_download_decrypt_complete(item.nom)

        if item.format != "mgs4":
            raise Exception("Format de chiffrage non supporte")

        if self.__https_session is None:
            https_session = requests.Session()
            https_session.verify = False
            https_session.cert = None
            self.__https_session = https_session

        url_fichier = f"{self.__connexion.filehost_url}/files/{item.fuuid}"

        path_reception = pathlib.Path(item.path_destination, item.nom)
        path_reception_work = pathlib.Path(item.path_destination, item.nom + ".work")
        item.partial_download_path = path_reception_work

        try:
            if path_reception.exists():
                raise FileExistsError()
        except FileExistsError:
            self.__logger.warning("Fichier %s existe deja" % path_reception_work)
            item.download_complete.set()
            return

        # Phase 3: Check for partial download and initialize resume state
        total_bytes_received = 0
        headers = {}
        is_resume = False

        if path_reception_work.exists():
            existing_size = path_reception_work.stat().st_size

            # Task 4: Validate partial download integrity
            if existing_size >= item.taille_chiffree:
                # Case B: File is complete, skip download and go to decryption
                self.__logger.info(
                    "Resume complete, proceeding to decryption for %s" % item.nom
                )
                total_bytes_received = existing_size
                item.state = DownloadState.RESUMING
                is_resume = True
            elif existing_size > 0:
                # Case A: Valid partial download, resume from existing size
                self.__logger.info(
                    "Resuming download for %s from %d bytes (%.1f%%)"
                    % (
                        item.nom,
                        existing_size,
                        (existing_size / item.taille_chiffree) * 100,
                    )
                )
                headers["Range"] = "bytes=%d-" % existing_size
                total_bytes_received = existing_size
                item.state = DownloadState.RESUMING
                is_resume = True
                self.__connexion.authenticate(self.__https_session)
            else:
                # Case A: Corrupt file (0 bytes), delete and restart
                self.__logger.warning(
                    "Corrupt partial download detected, restarting for %s" % item.nom
                )
                path_reception_work.unlink()
        else:
            # Fresh download
            item.state = DownloadState.DOWNLOADING

        # Task 3: Initialize progress bar at correct percentage for resume
        if self.__progress_manager and is_resume:
            progress = (total_bytes_received / max(1, item.taille_chiffree)) * 100
            self.__progress_manager.update_download_transfer(item.nom, progress)

        self.__logger.debug(
            "Debut download fichier %s (taille : %d)"
            % (path_reception_work, item.taille_chiffree)
        )
        chunks_done = 0

        # Download loop with retry mechanism
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                # Task 1: Properly determine file mode based on download state
                if path_reception_work.exists():
                    file_mode = "ab"  # Append mode for resume/retry
                else:
                    file_mode = "xb"  # Exclusive create for fresh download

                with open(path_reception_work, file_mode) as output:
                    response = self.__https_session.get(
                        url_fichier, stream=True, headers=headers
                    )
                    try:
                        response.raise_for_status()
                    except HTTPError as e:
                        if e.response.status_code == 401:
                            self.__connexion.authenticate(self.__https_session)
                            response = self.__https_session.get(
                                url_fichier, stream=True, headers=headers
                            )
                            response.raise_for_status()
                        elif e.response.status_code in [500, 502, 503, 504]:
                            # Server error, retry
                            raise
                        elif e.response.status_code == 200:
                            # Task 4: Server doesn't support Range requests (returns 200 instead of 206)
                            self.__logger.warning(
                                "Server returned 200 OK instead of 206 Partial Content for %s. Restarting download from beginning."
                                % item.nom
                            )
                            if path_reception_work.exists():
                                path_reception_work.unlink()
                            raise DownloadRetryException(
                                "Server doesn't support Range requests",
                                retry_count=retry_count,
                                last_error=e,
                            )
                        else:
                            raise e

                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        # Check for cancellation
                        if item.is_cancelled():
                            path_reception_work.unlink()
                            raise CancelledDownloadException()

                        # Check for global stop
                        if self.__stop_event.is_set():
                            path_reception_work.unlink()
                            raise Exception("Stopping")

                        # *** NEW: Check for pause ***
                        if item._DownloadFichier__pause_event.is_set():
                            # Flush buffer to disk before pausing
                            self.__logger.info("Download paused, saving progress")
                            output.flush()
                            item.state = DownloadState.PAUSED

                            # Wait for resume signal (5 minute timeout)
                            item._DownloadFichier__resume_event.wait(timeout=300)
                            if item._DownloadFichier__resume_event.is_set():
                                item.state = DownloadState.DOWNLOADING
                                item._DownloadFichier__resume_event.clear()
                            else:
                                raise TimeoutError("Resume timeout exceeded")

                        # Write chunk and update progress
                        output.write(chunk)
                        total_bytes_received += len(chunk)
                        item.taille_recue = total_bytes_received
                        chunks_done += 1

                        # Update progress bar
                        if self.__progress_wrapper:
                            self.__update_progress("transfer", len(chunk))
                        elif self.__progress_manager:
                            self.__update_progress("transfer", len(chunk))

                    # Task 6: Log successful resume completion
                    if is_resume and total_bytes_received == item.taille_chiffree:
                        self.__logger.info(
                            "Successfully resumed download for %s" % item.nom
                        )

                    # Task 5: Clear last_error on successful download completion
                    if item.last_error is not None:
                        item.last_error = None

                # Download completed successfully
                # Task 5: Transition state based on download scenario
                if is_resume:
                    item.state = DownloadState.RESUMING
                else:
                    item.state = DownloadState.DOWNLOADING

                # Task 5: Clear last_error and reset retry_count on successful completion
                if item.last_error is not None:
                    item.last_error = None
                item.retry_count = 0

                break

            except DownloadRetryException as e:
                # Special case: Server doesn't support Range requests
                item.last_error = e
                if path_reception_work.exists():
                    path_reception_work.unlink()
                # Restart fresh download (no retry, just restart)
                item.state = DownloadState.DOWNLOADING
                item.retry_count = 0
                is_resume = False
                headers = {}
                total_bytes_received = 0
                retry_count = max_retries  # Exit retry loop, restart fresh

            except (requests.RequestException, OSError, TimeoutError) as e:
                # Connection error or other download failure
                item.last_error = e
                retry_count += 1

                # Task 5: Update state and clear errors on resume scenarios
                if retry_count < max_retries:
                    item.state = DownloadState.RETRYING
                    self.__logger.warning(
                        "Download failed, retrying (%d/%d)... Error: %s"
                        % (retry_count, max_retries, e)
                    )

                    # Retry every 15 seconds with exponential backoff
                    wait_time = 15 * (2 ** (retry_count - 1))
                    time.sleep(min(wait_time, 120))  # Cap at 2 minutes

                    # Clear pause/resume events for retry
                    item._DownloadFichier__pause_event.clear()
                    item._DownloadFichier__resume_event.set()

                    # Update total_bytes_received to include what we received
                    # For retry, we need to recalculate based on existing file
                    if path_reception_work.exists():
                        total_bytes_received = path_reception_work.stat().st_size
                        headers["Range"] = "bytes=%d-" % total_bytes_received
                else:
                    # Too many retries, mark as failed
                    item.state = DownloadState.FAILED
                    if path_reception_work.exists():
                        path_reception_work.unlink()
                    raise DownloadFailedException(
                        "Download failed after %d retries: %s" % (retry_count, e),
                        item.last_error,
                    )

        # Task 4: Case B - Skip download if file already complete
        if is_resume and total_bytes_received >= item.taille_chiffree:
            # File was already complete, skip download phase
            self.__logger.info(
                "File already complete, proceeding directly to decryption"
            )
            item.state = DownloadState.DOWNLOADING
        self.__logger.debug(
            "Download fichier %s complete, dechiffrage en cours" % path_reception_work
        )

        # Transition progress bar from download to decrypt phase
        if self.__progress_wrapper:
            if hasattr(self.__progress_wrapper, "transition_to_decrypt"):
                self.__progress_wrapper.transition_to_decrypt()
            else:
                self.__progress_wrapper.transition_to_encrypt_phase(
                    total=item.taille_chiffree, desc="Decrypting"
                )

        # Check for cancellation before decryption
        if item.is_cancelled():
            path_reception_work.unlink()
            raise CancelledDownloadException()

        # Set download transfer progress to 100% and mark complete for Feature 1 and 2
        if self.__progress_manager:
            self.__progress_manager.set_download_transfer_final(
                getattr(item, "nom", "unknown")
            )

        # Reset download decrypt progress bar before starting new decryption
        if self.__progress_manager:
            self.__progress_manager.reset_download_decrypt(
                getattr(item, "nom", "unknown")
            )

        try:
            dechiffrer_in_place(
                item,
                path_reception_work,
                self.__progress_wrapper,
                self.__progress_manager,
            )
        except Exception as e:
            if "cancelled" in str(e).lower():
                self.__logger.info(
                    "Download cancelled, removing %s" % path_reception_work
                )
            else:
                self.__logger.exception(
                    "Erreur dechiffrage, on supprime %s" % path_reception_work
                )
            if path_reception_work.exists():
                path_reception_work.unlink()
            raise e

        # Check for cancellation before finalizing
        if item.is_cancelled():
            raise CancelledDownloadException()

        # Marquer le fichier comme pret (dechiffre)
        path_reception_work.rename(path_reception)
        self.__logger.debug("Fichier %s dechiffre OK" % path_reception)

        item.download_complete.set()

        # Remove from active downloads
        self._remove_completed_download(item)

        self._remove_completed_download(item)


def dechiffrer_in_place(
    item,
    path_reception,
    progress_wrapper=None,  # CLI progress bar wrapper (deprecated)
    progress_manager=None,  # GUI progress manager
):
    """
    Dechiffre un fichier en reutilisant l'espace deja occupe (overwrite).
    :param item: DownloadFichier instance
    :param path_reception: Path to the encrypted file
    :param progress_wrapper: Optional ProgressBarWrapper for progress updates (CLI)
    :param progress_manager: Optional ProgressManager for progress updates (GUI)
    :return:
    """
    with open(path_reception, "rb+") as fichier:
        decipher = DecipherMgs4(item.cle_secrete, item.nonce)
        position_read = 0
        position_write = 0
        while True:
            # Check for cancellation
            if item.is_cancelled():
                raise CancelledDownloadException()

            chunk = fichier.read(64 * 1024)
            if chunk is None or len(chunk) == 0:
                break
            position_read += len(chunk)
            item.taille_dechiffree = position_read

            chunk_dechiffre = decipher.update(chunk)
            if chunk_dechiffre:
                fichier.seek(position_write)
                fichier.write(chunk_dechiffre)
                position_write += len(chunk_dechiffre)
                fichier.seek(position_read)
                if progress_wrapper:
                    progress_wrapper.update_encrypt(len(chunk_dechiffre))

                # Also report to ProgressManager if available
                if progress_manager:
                    filename = getattr(item, "nom", "unknown")
                    progress = (
                        position_write / max(1, getattr(item, "taille_chiffree", 1))
                    ) * 100
                    progress_manager.update_download_decrypt(filename, progress)

        # Check for cancellation before finalization
        if item.is_cancelled():
            raise CancelledDownloadException()

        chunk_dechiffre = decipher.finalize()
        if chunk_dechiffre:
            fichier.seek(position_write)
            fichier.write(chunk_dechiffre)
            position_write += len(chunk_dechiffre)
            if progress_wrapper:
                progress_wrapper.update_encrypt(len(chunk_dechiffre))

            # Set download decrypt progress to 100% and mark complete for Feature 1 and 2
            if progress_manager:
                filename = getattr(item, "nom", "unknown")
                progress_manager.set_download_decrypt_final(filename)

        # Tronquer fichier a la position d'ecriture courante
        fichier.truncate()
