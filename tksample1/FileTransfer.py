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
        self.__transfer_dirty.set()

    def set_download_dirty(self):
        self.__download_dirty = True
        self.__transfer_dirty.set()

    def ajouter_download_fichier(
        self, download, destination=None, inline: bool = False
    ) -> DownloadFichier:
        return self.downloader.ajouter_download_fichier(
            download, destination, inline=inline
        )

    def ajouter_download_repertoire(
        self, repertoire, destination=None, inline: bool = False
    ):
        return self.downloader.ajouter_download_repertoire(
            repertoire, destination, inline=inline
        )

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

    def pause_download(self, tuuid: str):
        """Pause a download by tuuid.

        Args:
            tuuid: The tuuid of the download to pause
        """
        return self.downloader.pause_download(tuuid)

    def resume_download(self, tuuid: str):
        """Resume a paused download by tuuid.

        Args:
            tuuid: The tuuid of the download to resume
        """
        return self.downloader.resume_download(tuuid)

    def cancel_download(self, tuuid: str):
        """Cancel a download by tuuid.

        Args:
            tuuid: The tuuid of the download to cancel
        """
        return self.downloader.cancel_download(tuuid)

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
                    # Get status from ProgressManager for queue consistency
                    download_en_cours = self.progress_manager.get_current_download()
                    q_download = self.progress_manager.get_download_queue()
                    upload_en_cours = self.progress_manager.get_current_upload()
                    q_upload = self.progress_manager.get_upload_queue()

                    # Track whether we have active transfers
                    has_active_transfer = (
                        download_en_cours is not None
                        or upload_en_cours is not None
                        or len(q_download) > 0
                        or len(q_upload) > 0
                    )
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

                    def _get_item_identifier(item):
                        """Get identifier from download or upload object."""
                        tuuid = getattr(item, "tuuid", None)
                        if tuuid:
                            return tuuid
                        # Fallback to name attributes based on object type
                        if hasattr(item, "nom"):
                            return item.nom
                        elif hasattr(item, "path"):
                            return item.path.name
                        return str(item)

                    # Compare upload queue by length and content
                    if not upload_changed:
                        # Handle initial state when upload_q_comp is None
                        if upload_q_comp is None and len(q_upload) > 0:
                            upload_changed = True
                            upload_q_comp = q_upload.copy()
                        elif upload_q_comp is not None:
                            # Compare based on identifying attributes, not object references

                            upload_tuuids = [
                                _get_item_identifier(item) for item in upload_q_comp
                            ]
                            current_upload_tuuids = [
                                _get_item_identifier(item) for item in q_upload
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
                                _get_item_identifier(item) for item in download_q_comp
                            ]
                            current_download_tuuids = [
                                _get_item_identifier(item) for item in q_download
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
                            self.transfer_frame._update_upload_queue(
                                upload_en_cours, q_upload
                            )
                        if download_changed:
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
