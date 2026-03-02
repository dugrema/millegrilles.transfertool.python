import logging
from threading import Event, Thread
from typing import Optional

from tksample1.AuthUsager import Authentification
from tksample1.Downloader import Downloader, DownloadFichier
from tksample1.Uploader import Uploader, UploadFichier


class TransferHandler:
    def __init__(self, stop_event, connexion: Authentification):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event
        self.frame: Optional[object] = None
        self.connexion = connexion
        self.transfer_frame = None  # type: ignore[assignment]

        self.downloader = Downloader(self.__stop_event, connexion)
        self.uploader = Uploader(self.__stop_event, connexion)

        self.__navigation = None

        self.__transfer_dirty = Event()
        self.__download_dirty = False
        self.__upload_dirty = False

        self.__thread_status = Thread(
            name="TransferStatus", target=self.thread_status, daemon=False
        )
        self.__thread_status.start()

    def quit(self):
        self.uploader.quit()
        self.downloader.quit()

    def set_navigation(self, navigation):
        self.__navigation = navigation
        self.downloader.set_navigation(navigation)
        self.uploader.set_navigation(navigation)

    def set_upload_dirty(self):
        self.__upload_dirty = True
        self.__transfer_dirty.set()

    def set_download_dirty(self):
        self.__download_dirty = True
        self.__transfer_dirty.set()

    def ajouter_download_fichier(self, download, destination=None) -> DownloadFichier:
        return self.downloader.ajouter_download_fichier(download, destination)

    def ajouter_download_repertoire(self, repertoire, destination=None):
        return self.downloader.ajouter_download_repertoire(repertoire, destination)

    def ajouter_upload(self, cuuid_parent: str, path_upload: str):
        return self.uploader.ajouter_upload(cuuid_parent, path_upload)

    def creer_collection(self, nom: str, cuuid_parent: Optional[str] = None) -> str:
        return self.uploader.creer_collection(nom, cuuid_parent)

    def thread_status(self):
        upload_comp = None
        upload_q_comp = None
        download_comp = None
        download_q_comp = None
        while self.__stop_event.is_set() is False:
            self.__transfer_dirty.clear()
            try:
                if self.transfer_frame is not None:  # type: ignore
                    # Update status
                    # status_download = 'Download inactif'
                    status_download, download_en_cours, q_download = (
                        self.downloader.download_status()
                    )
                    self.transfer_frame.download_status_var.set(status_download)  # type: ignore

                    status_upload, upload_en_cours, q_upload = (
                        self.uploader.upload_status()
                    )
                    self.transfer_frame.upload_status_var.set(status_upload)  # type: ignore
                    if upload_comp is not upload_en_cours:
                        upload_comp = upload_en_cours
                        self.__upload_dirty = True
                    if upload_q_comp != q_upload:
                        upload_q_comp = q_upload.copy()
                        self.__upload_dirty = True

                    if self.__upload_dirty:
                        self.__upload_dirty = False
                        # Refresh liste uploads
                        self.transfer_frame.refresh_upload(upload_en_cours, q_upload)  # type: ignore

                    if download_comp is not download_en_cours:
                        download_comp = download_en_cours
                        self.__download_dirty = True
                    if download_q_comp != q_download:
                        download_q_comp = q_download.copy()
                        self.__download_dirty = True

                    if self.__download_dirty:
                        self.__download_dirty = False
                        # Refresh liste downloads
                        self.transfer_frame.refresh_download(  # type: ignore
                            download_en_cours, q_download
                        )
            except Exception:
                self.__logger.exception("Erreur refresh transferts")
                self.__transfer_dirty.wait(timeout=10)

            self.__transfer_dirty.wait(timeout=1)
