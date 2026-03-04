import logging
from threading import Event, Thread
from typing import Optional

from tksample1.AuthUsager import Authentification
from tksample1.Downloader import Downloader, DownloadFichier
from tksample1.ProgressBar import ProgressBarWrapper
from tksample1.ProgressManager import ProgressManager
from tksample1.Uploader import Uploader


class TransferHandler:
    def __init__(
        self,
        stop_event,
        connexion: Authentification,
    ):
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event
        self.frame: Optional[object] = None
        self.connexion = connexion
        self.transfer_frame = None  # type: ignore[assignment]

        self.progress_manager = ProgressManager()

        self.downloader = Downloader(
            self.__stop_event, connexion, self.progress_manager, transfer_handler=self
        )
        self.uploader = Uploader(
            self.__stop_event, connexion, self.progress_manager, transfer_handler=self
        )

        self.__navigation = None

        self.__transfer_dirty = Event()
        self.__download_dirty = False
        self.__upload_dirty = False

        self.__thread_status = Thread(
            name="TransferStatus", target=self.thread_status, daemon=True
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
        self.__logger.debug(f"Upload dirty flag set")

    def set_download_dirty(self):
        self.__download_dirty = True
        self.__transfer_dirty.set()
        self.__logger.debug(f"Download dirty flag set")

    def ajouter_download_fichier(self, download, destination=None) -> DownloadFichier:
        return self.downloader.ajouter_download_fichier(download, destination)

    def ajouter_download_repertoire(self, repertoire, destination=None):
        return self.downloader.ajouter_download_repertoire(repertoire, destination)

    def ajouter_upload(self, cuuid_parent: str, path_upload: str):
        return self.uploader.ajouter_upload(cuuid_parent, path_upload)

    def set_progress_wrappers(
        self,
        uploader_progress_wrapper: Optional[ProgressBarWrapper] = None,
        downloader_progress_wrapper: Optional[ProgressBarWrapper] = None,
    ):
        """
        Set progress wrappers for CLI mode.

        Args:
            uploader_progress_wrapper: ProgressBarWrapper instance for upload progress
            downloader_progress_wrapper: ProgressBarWrapper instance for download progress
        """
        if uploader_progress_wrapper is not None:
            self.uploader.progress_wrapper = uploader_progress_wrapper
        if downloader_progress_wrapper is not None:
            self.downloader.progress_wrapper = downloader_progress_wrapper

    def creer_collection(self, nom: str, cuuid_parent: Optional[str] = None) -> str:
        return self.uploader.creer_collection(nom, cuuid_parent)

    def thread_status(self):
        """
        Background thread for updating transfer status.

        Optimized to:
        - Only update queues when there are actual changes
        - Reduce update frequency when idle (5 seconds instead of 1 second)
        - Prevent unnecessary UI redraws
        """
        upload_comp = None
        upload_q_comp = None
        download_comp = None
        download_q_comp = None

        # Track whether we have active transfers to adjust update frequency
        has_active_transfer = False

        while self.__stop_event.is_set() is False:
            self.__transfer_dirty.clear()
            try:
                if self.transfer_frame is not None:  # type: ignore
                    # Get status
                    status_download, download_en_cours, q_download = (
                        self.downloader.download_status()
                    )
                    status_upload, upload_en_cours, q_upload = (
                        self.uploader.upload_status()
                    )
                    self.__logger.debug(
                        f"thread_status check: download queue size={len(q_download)}, upload queue size={len(q_upload)}"
                    )

                    # Track whether we have active transfers
                    previous_has_active = has_active_transfer
                    has_active_transfer = (
                        download_en_cours is not None
                        or upload_en_cours is not None
                        or len(q_download) > 0
                        or len(q_upload) > 0
                    )

                    # Determine if queue actually changed (not just reference equality)
                    upload_changed = False
                    download_changed = False

                    # Check upload changes
                    if upload_comp is not upload_en_cours:
                        upload_comp = upload_en_cours
                        upload_changed = True

                    # Compare upload queue by length and content
                    if not upload_changed:
                        # Handle initial state when upload_q_comp is None
                        if upload_q_comp is None and len(q_upload) > 0:
                            upload_changed = True
                            upload_q_comp = q_upload.copy()
                        elif upload_q_comp is not None:
                            # Compare based on identifying attributes, not object references
                            upload_tuuids = [
                                getattr(item, "tuuid", None) or item.path.name
                                for item in upload_q_comp
                            ]
                            current_upload_tuuids = [
                                getattr(item, "tuuid", None) or item.path.name
                                for item in q_upload
                            ]
                            if len(upload_q_comp) != len(q_upload):
                                upload_changed = True
                                upload_q_comp = q_upload.copy()
                            elif upload_tuuids != current_upload_tuuids:
                                upload_changed = True
                                upload_q_comp = q_upload.copy()

                    # Check download changes
                    if download_comp is not download_en_cours:
                        download_comp = download_en_cours
                        download_changed = True

                    # Compare download queue by length and content
                    if not download_changed:
                        # Handle initial state when download_q_comp is None
                        if download_q_comp is None and len(q_download) > 0:
                            download_changed = True
                            download_q_comp = q_download.copy()
                        elif download_q_comp is not None:
                            # Compare based on identifying attributes, not object references
                            download_tuuids = [
                                getattr(item, "tuuid", None) or item.nom
                                for item in download_q_comp
                            ]
                            current_download_tuuids = [
                                getattr(item, "tuuid", None) or item.nom
                                for item in q_download
                            ]
                            if len(download_q_comp) != len(q_download):
                                download_changed = True
                                download_q_comp = q_download.copy()
                            elif download_tuuids != current_download_tuuids:
                                download_changed = True
                                download_q_comp = q_download.copy()

                    # Only update UI if there are actual changes
                    if upload_changed or download_changed:
                        if upload_changed:
                            self.__logger.debug(f"Updating upload queue UI")
                            self.transfer_frame._update_upload_queue(
                                upload_en_cours, q_upload
                            )
                        if download_changed:
                            self.__logger.debug(f"Updating download queue UI")
                            self.transfer_frame._update_download_queue(
                                download_en_cours, q_download
                            )

                    # Reset dirty flags
                    self.__upload_dirty = False
                    self.__download_dirty = False

            except Exception:
                self.__logger.exception("Erreur refresh transferts")
                # Longer timeout on error to avoid tight loop
                self.__transfer_dirty.wait(timeout=5)
                continue

            # Dynamic timeout: 5 seconds when idle, 1 second when active
            # This reduces unnecessary UI updates when there's no activity
            timeout = 5.0 if not has_active_transfer else 1.0
            self.__transfer_dirty.wait(timeout=timeout)
