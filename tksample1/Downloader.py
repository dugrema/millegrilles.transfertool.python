import logging
import pathlib
import warnings
from threading import Event, Lock, Thread
from typing import Optional, Union
from urllib import parse

import requests
import urllib3.exceptions
from millegrilles_messages.chiffrage.Mgs4 import DecipherMgs4
from requests import HTTPError
from wakepy import keep

from tksample1.AuthUsager import Authentification
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

    def cancel(self):
        """Cancel the download."""
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


class DownloadRepertoire:
    def __init__(self, repertoire, destination: pathlib.Path):
        self.__info = repertoire
        metadata = repertoire["metadata"]
        self.cuuid = repertoire["tuuid"]
        self.nom = metadata["nom"]
        self.download_complete = Event()
        self.__cancel_event = Event()
        self.repertoire = None
        self.destination = destination

        # Progress tracking attributes for GUI
        self.taille_recue = 0  # Cumulative received bytes
        self.taille_dechiffree = 0  # Cumulative decrypted bytes
        self.taille_chiffree = 0  # Total encrypted size (for percentage calculation)

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

    def ajouter_download_repertoire(self, repertoire, destination=None):
        destination = destination or self.__connexion.download_path
        if destination.exists() is False:
            destination.mkdir()

        download_item = DownloadRepertoire(repertoire, destination)
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

    def download_repertoire(self, item: DownloadRepertoire):
        tuuid = item.cuuid

        # Check for cancellation before starting
        if item.is_cancelled():
            raise CancelledDownloadException()

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
                        download_fichier = DownloadFichier(t, path_destination)
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

                        except FileExistsError:
                            pass  # OK
                else:
                    # Download recursif des sous-repertoires
                    download_repertoire = DownloadRepertoire(t, path_destination)
                    self.download_repertoire(download_repertoire)

            # Mark directory download as complete
            item.download_complete.set()
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
        """Download then decrypt file (traditional two-phase mode)."""
        self.__connexion.connect_event.wait()
        if self.__stop_event.is_set():
            raise Exception("Stopping")

        if item.is_cancelled():
            raise CancelledDownloadException()

        if item.format != "mgs4":
            raise Exception("Format de chiffrage non supporte")

        if self.__https_session is None:
            https_session = requests.Session()
            https_session.verify = False
            https_session.cert = None
            self.__https_session = https_session

        url_fichier = f"{self.__connexion.filehost_url}/files/{item.fuuid}"

        path_reception = pathlib.Path(item.path_destination, item.nom)
        if path_reception.exists():
            raise FileExistsError()

        path_reception_work = pathlib.Path(item.path_destination, item.nom + ".work")
        self.__logger.debug(
            "Debut download fichier %s (taille : %d)"
            % (path_reception_work, item.taille_chiffree)
        )
        chunks_done = 0
        try:
            with open(path_reception_work, "xb") as output:
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
                    output.write(chunk)
                    chunks_done += 1
                    if self.__progress_wrapper:
                        self.__update_progress("transfer", len(chunk))
                    elif self.__progress_manager:
                        self.__update_progress("transfer", len(chunk))
                    if self.__stop_event.is_set() is True:
                        path_reception_work.unlink()
                        raise Exception("Stopping")
                    if item.is_cancelled():
                        path_reception_work.unlink()
                        raise CancelledDownloadException()
        except FileExistsError:
            self.__logger.warning("Fichier %s existe deja" % path_reception_work)
            item.download_complete.set()
            return
        else:
            self.__logger.debug(
                "Download fichier %s complete, dechiffrage en cours"
                % path_reception_work
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

        # Set download transfer progress to 100% before starting decryption
        if self.__progress_manager:
            self.__progress_manager.set_download_transfer_complete(
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

            # Set download decrypt progress to 100% when decryption is complete
            if progress_manager:
                filename = getattr(item, "nom", "unknown")
                progress_manager.set_download_decrypt_complete(filename)

        # Tronquer fichier a la position d'ecriture courante
        fichier.truncate()
