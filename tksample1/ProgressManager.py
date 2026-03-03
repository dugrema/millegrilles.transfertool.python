"""Progress Manager for File Transfers.

This module provides a ProgressManager class that coordinates progress updates
for upload and download operations, managing queues and callback notifications.
"""

import logging
import tkinter as tk
from threading import Lock
from typing import Callable, Optional


class ProgressManager:
    """
    Manages progress tracking and queue state for file transfers.

    Coordinates progress updates for upload and download operations,
    maintaining pending queues and notifying registered callbacks.
    """

    def __init__(self, root: Optional[tk.Tk] = None):
        """Initialize the ProgressManager.

        Args:
            root: Optional tkinter root reference for thread-safe GUI updates
        """
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__lock = Lock()
        self._root = root

        # Callbacks for download progress updates
        self.__download_transfer_callback: Optional[Callable[[str, float], None]] = None
        self.__download_decrypt_callback: Optional[Callable[[str, float], None]] = None

        # Callbacks for upload progress updates
        self.__upload_encrypt_callback: Optional[Callable[[str, float], None]] = None
        self.__upload_transfer_callback: Optional[Callable[[str, float], None]] = None

        # Download queue and current transfer
        self.__download_queue: list = []
        self.__current_download: Optional[dict] = None

        # Upload queue and current transfer
        self.__upload_queue: list = []
        self.__current_upload: Optional[dict] = None

    def register_callbacks(
        self,
        download_transfer_callback: Optional[Callable[[str, float], None]] = None,
        download_decrypt_callback: Optional[Callable[[str, float], None]] = None,
        upload_encrypt_callback: Optional[Callable[[str, float], None]] = None,
        upload_transfer_callback: Optional[Callable[[str, float], None]] = None,
    ):
        """Register callback functions for progress updates.

        Args:
            download_transfer_callback: Called with (filename, progress_percentage) during download
            download_decrypt_callback: Called with (filename, progress_percentage) during decryption
            upload_encrypt_callback: Called with (filename, progress_percentage) during encryption
            upload_transfer_callback: Called with (filename, progress_percentage) during upload
        """
        with self.__lock:
            if download_transfer_callback is not None:
                self.__download_transfer_callback = download_transfer_callback
            if download_decrypt_callback is not None:
                self.__download_decrypt_callback = download_decrypt_callback
            if upload_encrypt_callback is not None:
                self.__upload_encrypt_callback = upload_encrypt_callback
            if upload_transfer_callback is not None:
                self.__upload_transfer_callback = upload_transfer_callback

    def _invoke_callback(self, callback: Callable, *args):
        """Invoke callback in a thread-safe manner using tkinter's after().

        Args:
            callback: The callback function to invoke
            *args: Arguments to pass to the callback
        """
        if self._root is not None:
            # Use tkinter's after() for thread-safe GUI updates
            self._root.after(0, callback, *args)
        else:
            # Fallback for backward compatibility (not thread-safe)
            callback(*args)

    # Download queue management
    def add_to_download_queue(self, item: dict):
        """Add an item to the download queue.

        Args:
            item: Dictionary containing 'filename', 'size', and 'tuuid'
        """
        with self.__lock:
            self.__download_queue.append(item)

    def remove_from_download_queue(self, tuuid: str):
        """Remove an item from the download queue by tuuid.

        Args:
            tuuid: The tuuid of the item to remove
        """
        with self.__lock:
            self.__download_queue = [
                item for item in self.__download_queue if item.get("tuuid") != tuuid
            ]

    def set_current_download(self, item: Optional[dict]):
        """Set the current download in progress.

        Args:
            item: Dictionary containing 'filename', 'size', and 'tuuid'
        """
        with self.__lock:
            self.__current_download = item

    def get_download_queue(self) -> list:
        """Get a copy of the download queue.

        Returns:
            List of download items in queue
        """
        with self.__lock:
            return self.__download_queue.copy()

    def get_current_download(self) -> Optional[dict]:
        """Get the current download in progress.

        Returns:
            Dictionary with current download info, or None if no download
        """
        with self.__lock:
            return self.__current_download

    # Upload queue management
    def add_to_upload_queue(self, item: dict):
        """Add an item to the upload queue.

        Args:
            item: Dictionary containing 'filename', 'size', and 'tuuid'
        """
        with self.__lock:
            self.__upload_queue.append(item)

    def remove_from_upload_queue(self, tuuid: str):
        """Remove an item from the upload queue by tuuid.

        Args:
            tuuid: The tuuid of the item to remove
        """
        with self.__lock:
            self.__upload_queue = [
                item for item in self.__upload_queue if item.get("tuuid") != tuuid
            ]

    def set_current_upload(self, item: Optional[dict]):
        """Set the current upload in progress.

        Args:
            item: Dictionary containing 'filename', 'size', and 'tuuid'
        """
        with self.__lock:
            self.__current_upload = item

    def get_upload_queue(self) -> list:
        """Get a copy of the upload queue.

        Returns:
            List of upload items in queue
        """
        with self.__lock:
            return self.__upload_queue.copy()

    def get_current_upload(self) -> Optional[dict]:
        """Get the current upload in progress.

        Returns:
            Dictionary with current upload info, or None if no upload
        """
        with self.__lock:
            return self.__current_upload

    # Progress update methods
    def update_download_transfer(self, filename: str, progress: float):
        """Report download transfer progress.

        Args:
            filename: Name of the file being downloaded
            progress: Progress percentage (0-100)
        """
        if self.__download_transfer_callback is not None:
            self._invoke_callback(self.__download_transfer_callback, filename, progress)

    def update_download_decrypt(self, filename: str, progress: float):
        """Report download decryption progress.

        Args:
            filename: Name of the file being decrypted
            progress: Progress percentage (0-100)
        """
        if self.__download_decrypt_callback is not None:
            self._invoke_callback(self.__download_decrypt_callback, filename, progress)

    def update_upload_encrypt(self, filename: str, progress: float):
        """Report upload encryption progress.

        Args:
            filename: Name of the file being encrypted
            progress: Progress percentage (0-100)
        """
        if self.__upload_encrypt_callback is not None:
            self._invoke_callback(self.__upload_encrypt_callback, filename, progress)

    def update_upload_transfer(self, filename: str, progress: float):
        """Report upload transfer progress.

        Args:
            filename: Name of the file being uploaded
            progress: Progress percentage (0-100)
        """
        if self.__upload_transfer_callback is not None:
            self._invoke_callback(self.__upload_transfer_callback, filename, progress)

    # Get status for queue display
    def get_download_status(self) -> tuple:
        """Get download status for display.

        Returns:
            Tuple of (current_download, queue_list)
        """
        return self.get_current_download(), self.get_download_queue()

    def get_upload_status(self) -> tuple:
        """Get upload status for display.

        Returns:
            Tuple of (current_upload, queue_list)
        """
        return self.get_current_upload(), self.get_upload_queue()
