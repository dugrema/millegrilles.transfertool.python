"""Progress Manager for File Transfers.

This module provides a ProgressManager class that coordinates progress updates
for upload and download operations, managing queues and callback notifications.
"""

import logging
import time
from threading import Lock
from typing import Any, Callable, Optional


class ProgressManager:
    """
    Manages progress tracking and queue state for file transfers.

    Coordinates progress updates for upload and download operations,
    maintaining pending queues and notifying registered callbacks.
    """

    def __init__(self, root: Optional[Any] = None):
        """Initialize the ProgressManager.

        Args:
            root: Optional tkinter root reference for thread-safe GUI updates
        """
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__lock = Lock()
        self._root = root

        # Throttling mechanism for progress updates
        # Minimum interval between progress updates (in seconds)
        self.__min_update_interval = 0.1  # 100ms
        self.__last_update_time: dict = {}

        # Callbacks for download progress updates
        self.__download_transfer_callback: Optional[Callable[[str, float], None]] = None
        self.__download_decrypt_callback: Optional[Callable[[str, float], None]] = None
        self.__download_reset_callback: Optional[Callable[[str], None]] = None

        # Callbacks for upload progress updates
        self.__upload_encrypt_callback: Optional[Callable[[str, float], None]] = None
        self.__upload_transfer_callback: Optional[Callable[[str, float], None]] = None
        self.__upload_reset_callback: Optional[Callable[[str], None]] = None

        # Callbacks for progress bar color updates (Feature 2)
        self.__download_transfer_color_callback: Optional[
            Callable[[str, bool], None]
        ] = None
        self.__download_decrypt_color_callback: Optional[
            Callable[[str, bool], None]
        ] = None
        self.__upload_encrypt_color_callback: Optional[Callable[[str, bool], None]] = (
            None
        )
        self.__upload_transfer_color_callback: Optional[Callable[[str, bool], None]] = (
            None
        )

        # Color state tracking for completion (Feature 2)
        self.__download_transfer_complete: set = set()
        self.__download_decrypt_complete: set = set()
        self.__upload_encrypt_complete: set = set()
        self.__upload_transfer_complete: set = set()

        # Download queue and current transfer
        self.__download_queue: list = []
        self.__current_download: Optional[dict] = None
        self.__download_queue_inline: dict = {}  # Track inline mode for each tuuid

        # Upload queue and current transfer
        self.__upload_queue: list = []
        self.__current_upload: Optional[dict] = None

    def register_callbacks(
        self,
        download_transfer_callback: Optional[Callable[[str, float], None]] = None,
        download_decrypt_callback: Optional[Callable[[str, float], None]] = None,
        download_reset_callback: Optional[Callable[[str], None]] = None,
        upload_encrypt_callback: Optional[Callable[[str, float], None]] = None,
        upload_transfer_callback: Optional[Callable[[str, float], None]] = None,
        upload_reset_callback: Optional[Callable[[str], None]] = None,
        # Feature 2: Color callbacks
        download_transfer_color_callback: Optional[Callable[[str, bool], None]] = None,
        download_decrypt_color_callback: Optional[Callable[[str, bool], None]] = None,
        upload_encrypt_color_callback: Optional[Callable[[str, bool], None]] = None,
        upload_transfer_color_callback: Optional[Callable[[str, bool], None]] = None,
    ):
        """Register callback functions for progress updates.

        Args:
            download_transfer_callback: Called with (filename, progress_percentage) during download
            download_decrypt_callback: Called with (filename, progress_percentage) during decryption
            download_reset_callback: Called with (filename) before starting new download decryption
            upload_encrypt_callback: Called with (filename, progress_percentage) during encryption
            upload_transfer_callback: Called with (filename, progress_percentage) during upload
            upload_reset_callback: Called with (filename) before starting new upload transfer
            download_transfer_color_callback: Called with (filename, is_complete) for download transfer color
            download_decrypt_color_callback: Called with (filename, is_complete) for decrypt color
            upload_encrypt_color_callback: Called with (filename, is_complete) for encryption color
            upload_transfer_color_callback: Called with (filename, is_complete) for upload transfer color
        """
        with self.__lock:
            if download_transfer_callback is not None:
                self.__download_transfer_callback = download_transfer_callback
            if download_decrypt_callback is not None:
                self.__download_decrypt_callback = download_decrypt_callback
            if download_reset_callback is not None:
                self.__download_reset_callback = download_reset_callback
            if upload_encrypt_callback is not None:
                self.__upload_encrypt_callback = upload_encrypt_callback
            if upload_transfer_callback is not None:
                self.__upload_transfer_callback = upload_transfer_callback
            if upload_reset_callback is not None:
                self.__upload_reset_callback = upload_reset_callback

            # Feature 2: Color callbacks
            if download_transfer_color_callback is not None:
                self.__download_transfer_color_callback = (
                    download_transfer_color_callback
                )
            if download_decrypt_color_callback is not None:
                self.__download_decrypt_color_callback = download_decrypt_color_callback
            if upload_encrypt_color_callback is not None:
                self.__upload_encrypt_color_callback = upload_encrypt_color_callback
            if upload_transfer_color_callback is not None:
                self.__upload_transfer_color_callback = upload_transfer_color_callback

    def _invoke_callback(self, callback: Callable, *args):
        """Invoke callback in a thread-safe manner using tkinter's after().

        Args:
            callback: The callback function to invoke
            *args: Arguments to pass to the callback
        """
        if self._root is not None:
            # Use tkinter's after() for thread-safe GUI updates
            import tkinter as tk

            if isinstance(self._root, tk.Tk):
                self._root.after(0, callback, *args)
            else:
                callback(*args)
        else:
            # Fallback for backward compatibility (not thread-safe)
            callback(*args)

    # Download queue management
    def add_to_download_queue(self, item: dict):
        """Add an item to the download queue.

        Args:
            item: Dictionary containing 'filename', 'size', 'tuuid', and optionally 'inline'
        """
        with self.__lock:
            self.__download_queue.append(item)
            # Track inline mode for this download
            if "tuuid" in item:
                self.__download_queue_inline[item["tuuid"]] = item.get("inline", False)

    def remove_from_download_queue(self, tuuid: str):
        """Remove an item from the download queue by tuuid.

        Args:
            tuuid: The tuuid of the item to remove
        """
        with self.__lock:
            self.__download_queue = [
                item for item in self.__download_queue if item.get("tuuid") != tuuid
            ]
            # Also remove inline tracking
            if tuuid in self.__download_queue_inline:
                del self.__download_queue_inline[tuuid]

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

    def get_download_inline_mode(self, tuuid: str) -> bool:
        """Get the inline mode for a specific download.

        Args:
            tuuid: The tuuid of the download

        Returns:
            True if inline mode, False if two-phase mode
        """
        with self.__lock:
            return self.__download_queue_inline.get(tuuid, False)

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
            if self._should_update("download_transfer"):
                self._invoke_callback(
                    self.__download_transfer_callback, filename, progress
                )

    def update_download_decrypt(self, filename: str, progress: float):
        """Report download decryption progress.

        Args:
            filename: Name of the file being decrypted
            progress: Progress percentage (0-100)
        """
        if self.__download_decrypt_callback is not None:
            if self._should_update("download_decrypt"):
                self._invoke_callback(
                    self.__download_decrypt_callback, filename, progress
                )

    def reset_download_decrypt(self, filename: str):
        """Reset download decryption progress bar before starting new decryption.

        Args:
            filename: Name of the file being decrypted
        """
        if self.__download_reset_callback is not None:
            self._invoke_callback(self.__download_reset_callback, filename)

    def set_download_transfer_complete(self, filename: str):
        """Set download transfer progress to 100% before starting decryption.

        Args:
            filename: Name of the file being downloaded
        """
        if self.__download_transfer_callback is not None:
            self._invoke_callback(self.__download_transfer_callback, filename, 100.0)

    def set_download_decrypt_complete(self, filename: str):
        """Set download decryption progress to 100% when decryption is complete.

        Args:
            filename: Name of the file being decrypted
        """
        if self.__download_decrypt_callback is not None:
            self._invoke_callback(self.__download_decrypt_callback, filename, 100.0)

    def update_upload_encrypt(self, filename: str, progress: float):
        """Report upload encryption progress.

        Args:
            filename: Name of the file being encrypted
            progress: Progress percentage (0-100)
        """
        if self.__upload_encrypt_callback is not None:
            if self._should_update("upload_encrypt"):
                self._invoke_callback(
                    self.__upload_encrypt_callback, filename, progress
                )

    def update_upload_transfer(self, filename: str, progress: float):
        """Report upload transfer progress.

        Args:
            filename: Name of the file being uploaded
            progress: Progress percentage (0-100)
        """
        if self.__upload_transfer_callback is not None:
            if self._should_update("upload_transfer"):
                self._invoke_callback(
                    self.__upload_transfer_callback, filename, progress
                )

    def reset_upload_transfer(self, filename: str):
        """Reset upload transfer progress bar before starting new upload.

        Args:
            filename: Name of the file being uploaded
        """
        if self.__upload_reset_callback is not None:
            self._invoke_callback(self.__upload_reset_callback, filename)

    def set_upload_encrypt_complete(self, filename: str):
        """Set upload encryption progress to 100% before starting upload.

        Args:
            filename: Name of the file being encrypted
        """
        if self.__upload_encrypt_callback is not None:
            self._invoke_callback(self.__upload_encrypt_callback, filename, 100.0)

    def set_upload_transfer_complete(self, filename: str):
        """Set upload transfer progress to 100% when upload is complete.

        Args:
            filename: Name of the file being uploaded
        """
        if self.__upload_transfer_callback is not None:
            self._invoke_callback(self.__upload_transfer_callback, filename, 100.0)

    # Final progress methods for inline mode (always reach 100%)
    def set_download_transfer_final(self, filename: str):
        """Set download transfer progress to final 100% when download completes (inline mode).

        Args:
            filename: Name of the file being downloaded
        """
        if self.__download_transfer_callback is not None:
            self._invoke_callback(self.__download_transfer_callback, filename, 100.0)
        # Feature 2: Mark as complete for green color
        self.mark_download_transfer_complete(filename)

    def set_download_decrypt_final(self, filename: str):
        """Set download decryption progress to final 100% when decryption completes (inline mode).

        Args:
            filename: Name of the file being decrypted
        """
        if self.__download_decrypt_callback is not None:
            self._invoke_callback(self.__download_decrypt_callback, filename, 100.0)
        # Feature 2: Mark as complete for green color
        self.mark_download_decrypt_complete(filename)

    def set_upload_encrypt_final(self, filename: str):
        """Set upload encryption progress to final 100% when encryption completes.

        Args:
            filename: Name of the file being encrypted
        """
        if self.__upload_encrypt_callback is not None:
            self._invoke_callback(self.__upload_encrypt_callback, filename, 100.0)
        # Feature 2: Mark as complete for green color
        self.mark_upload_encrypt_complete(filename)

    def set_upload_transfer_final(self, filename: str):
        """Set upload transfer progress to final 100% when upload completes.

        Args:
            filename: Name of the file being uploaded
        """
        if self.__upload_transfer_callback is not None:
            self._invoke_callback(self.__upload_transfer_callback, filename, 100.0)
        # Feature 2: Mark as complete for green color
        self.mark_upload_transfer_complete(filename)

    # Feature 2: Color state tracking methods for green progress bars on completion

    def mark_download_transfer_complete(self, filename: str):
        """Mark download transfer as complete (turn green).

        Args:
            filename: Name of the file being downloaded
        """
        with self.__lock:
            self.__download_transfer_complete.add(filename)
        if self.__download_transfer_color_callback is not None:
            self._invoke_callback(
                self.__download_transfer_color_callback, filename, True
            )

    def mark_download_decrypt_complete(self, filename: str):
        """Mark download decrypt as complete (turn green).

        Args:
            filename: Name of the file being decrypted
        """
        with self.__lock:
            self.__download_decrypt_complete.add(filename)
        if self.__download_decrypt_color_callback is not None:
            self._invoke_callback(
                self.__download_decrypt_color_callback, filename, True
            )

    def mark_upload_encrypt_complete(self, filename: str):
        """Mark upload encrypt as complete (turn green).

        Args:
            filename: Name of the file being encrypted
        """
        with self.__lock:
            self.__upload_encrypt_complete.add(filename)
        if self.__upload_encrypt_color_callback is not None:
            self._invoke_callback(self.__upload_encrypt_color_callback, filename, True)

    def mark_upload_transfer_complete(self, filename: str):
        """Mark upload transfer as complete (turn green).

        Args:
            filename: Name of the file being uploaded
        """
        with self.__lock:
            self.__upload_transfer_complete.add(filename)
        if self.__upload_transfer_color_callback is not None:
            self._invoke_callback(self.__upload_transfer_color_callback, filename, True)

    def reset_download_transfer_complete(self, filename: str):
        """Reset download transfer color (remove from complete set).

        Args:
            filename: Name of the file to reset
        """
        with self.__lock:
            self.__download_transfer_complete.discard(filename)
        if self.__download_transfer_color_callback is not None:
            self._invoke_callback(
                self.__download_transfer_color_callback, filename, False
            )

    def reset_download_decrypt_complete(self, filename: str):
        """Reset download decrypt color (remove from complete set).

        Args:
            filename: Name of the file to reset
        """
        with self.__lock:
            self.__download_decrypt_complete.discard(filename)
        if self.__download_decrypt_color_callback is not None:
            self._invoke_callback(
                self.__download_decrypt_color_callback, filename, False
            )

    def reset_upload_encrypt_complete(self, filename: str):
        """Reset upload encrypt color (remove from complete set).

        Args:
            filename: Name of the file to reset
        """
        with self.__lock:
            self.__upload_encrypt_complete.discard(filename)
        if self.__upload_encrypt_color_callback is not None:
            self._invoke_callback(self.__upload_encrypt_color_callback, filename, False)

    def reset_upload_transfer_complete(self, filename: str):
        """Reset upload transfer color (remove from complete set).

        Args:
            filename: Name of the file to reset
        """
        with self.__lock:
            self.__upload_transfer_complete.discard(filename)
        if self.__upload_transfer_color_callback is not None:
            self._invoke_callback(
                self.__upload_transfer_color_callback, filename, False
            )

    def is_download_transfer_complete(self, filename: str) -> bool:
        """Check if download transfer is marked as complete.

        Args:
            filename: Name of the file to check

        Returns:
            True if complete, False otherwise
        """
        with self.__lock:
            return filename in self.__download_transfer_complete

    def is_download_decrypt_complete(self, filename: str) -> bool:
        """Check if download decrypt is marked as complete.

        Args:
            filename: Name of the file to check

        Returns:
            True if complete, False otherwise
        """
        with self.__lock:
            return filename in self.__download_decrypt_complete

    def is_upload_encrypt_complete(self, filename: str) -> bool:
        """Check if upload encrypt is marked as complete.

        Args:
            filename: Name of the file to check

        Returns:
            True if complete, False otherwise
        """
        with self.__lock:
            return filename in self.__upload_encrypt_complete

    def is_upload_transfer_complete(self, filename: str) -> bool:
        """Check if upload transfer is marked as complete.

        Args:
            filename: Name of the file to check

        Returns:
            True if complete, False otherwise
        """
        with self.__lock:
            return filename in self.__upload_transfer_complete

    def _should_update(self, update_type: str) -> bool:
        """Check if progress update should be invoked based on throttling.

        Args:
            update_type: Type of update (e.g., 'download_transfer', 'upload_encrypt')

        Returns:
            True if update should proceed, False if throttled
        """
        current_time = time.time()
        last_time = self.__last_update_time.get(update_type, 0)

        if current_time - last_time >= self.__min_update_interval:
            self.__last_update_time[update_type] = current_time
            return True

        return False

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
