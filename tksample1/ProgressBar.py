"""
Progress Bar Wrapper for CLI Mode

This module provides a progress bar wrapper for CLI file transfer operations.
It uses tqdm to display progress bars for encryption/decryption and network transfer phases.
"""

from typing import Optional

from tqdm import tqdm


class ProgressBarWrapper:
    """
    Wrapper for managing progress bar display across multiple phases.

    Provides separate progress bars for encryption/decryption and network transfer phases,
    ensuring clear visual feedback during file upload and download operations in CLI mode.

    Example:
        # For upload
        progress = ProgressBarWrapper(f"Uploading '{filename}'")
        progress.encrypt_phase(desc="Encrypting")
        encrypted_data = encrypt_file(file_path)
        progress.update_encrypt(len(encrypted_data))
        progress.transfer_phase(total=len(encrypted_data), desc="Transferring")
        send_to_server(encrypted_data)
        progress.update_transfer(len(encrypted_data))
        progress.close()

        # For download
        progress = ProgressBarWrapper(f"Downloading '{filename}'")
        progress.transfer_phase(desc="Downloading")
        encrypted_data = fetch_from_server()
        progress.update_transfer(len(encrypted_data))
        progress.encrypt_phase(total=len(encrypted_data), desc="Decrypting")
        decrypted_data = decrypt_file(encrypted_data)
        progress.update_encrypt(len(decrypted_data))
        progress.close()
    """

    def __init__(self, description: str, total: Optional[int] = None):
        """
        Initialize progress bar wrapper.

        Args:
            description: Description of the operation (e.g., "Uploading filename.txt")
            total: Total size in bytes (for byte-based progress)
        """
        self.description = description
        self.phase_bars: dict[str, tqdm] = {}
        self.current_phase: Optional[str] = None

    def encrypt_phase(self, total: Optional[int] = None, desc: str = "Encrypting"):
        """
        Start encryption phase progress bar.

        Args:
            total: Estimated total for encryption (if known)
            desc: Description for this phase

        Returns:
            The tqdm progress bar for this phase
        """
        # Close any existing phase
        self._close_current_phase()

        self.current_phase = "encrypt"
        self.phase_bars["encrypt"] = tqdm(
            desc=f"  {desc}:",
            total=total,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} ({percentage:.0f}%)",
        )
        return self.phase_bars["encrypt"]

    def update_encrypt(self, current: int):
        """
        Update encryption progress.

        Args:
            current: Current bytes processed
        """
        if "encrypt" in self.phase_bars:
            self.phase_bars["encrypt"].update(current)

    def set_encrypt_total(self, total: int):
        """
        Set the total for encryption phase (useful when total is not known initially).

        Args:
            total: Total bytes to encrypt
        """
        if "encrypt" in self.phase_bars:
            self.phase_bars["encrypt"].total = total
            self.phase_bars["encrypt"].refresh()

    def transfer_phase(self, total: Optional[int] = None, desc: str = "Transferring"):
        """
        Transition to transfer phase with new progress bar.

        Args:
            total: Total size in bytes
            desc: Description for this phase
        """
        # Close any existing phase
        self._close_current_phase()

        self.current_phase = "transfer"
        self.phase_bars["transfer"] = tqdm(
            desc=f"  {desc}:",
            total=total,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} ({percentage:.0f}%)",
        )
        return self.phase_bars["transfer"]

    def update_transfer(self, current: int):
        """
        Update transfer progress.

        Args:
            current: Current bytes transferred
        """
        if "transfer" in self.phase_bars:
            self.phase_bars["transfer"].update(current)

    def set_transfer_total(self, total: int):
        """
        Set the total for transfer phase (useful when total is not known initially).

        Args:
            total: Total bytes to transfer
        """
        if "transfer" in self.phase_bars:
            self.phase_bars["transfer"].total = total
            self.phase_bars["transfer"].refresh()

    def update_current(self, amount: int = 1):
        """
        Update the current phase progress by a given amount.

        Args:
            amount: Bytes to add to the current phase progress
        """
        if self.current_phase == "encrypt":
            self.update_encrypt(amount)
        elif self.current_phase == "transfer":
            self.update_transfer(amount)

    def _close_current_phase(self):
        """Close the current phase progress bar if it exists."""
        if self.current_phase and self.current_phase in self.phase_bars:
            self.phase_bars[self.current_phase].close()
            del self.phase_bars[self.current_phase]

    def close(self):
        """
        Close all progress bars and clean up.
        """
        for bar in self.phase_bars.values():
            bar.close()
        self.phase_bars.clear()
        self.current_phase = None


class ProgressBarCallback:
    """
    Callback handler for progress updates.

    Wraps a progress bar and provides a callback function that can be used
    by encryption/decryption or file transfer operations to report progress.
    """

    def __init__(self, progress_wrapper: ProgressBarWrapper, phase: str, total: int):
        """
        Initialize progress callback.

        Args:
            progress_wrapper: The ProgressBarWrapper instance
            phase: Phase type ('encrypt' or 'transfer')
            total: Total bytes for this phase
        """
        self.progress_wrapper = progress_wrapper
        self.phase = phase
        self.total = total
        self.current = 0

    def __call__(self, current: int, total: int):
        """
        Update progress bar on callback.

        Args:
            current: Current bytes processed
            total: Total bytes
        """
        delta = current - self.current
        if delta > 0:
            if self.phase == "encrypt":
                self.progress_wrapper.update_encrypt(delta)
            elif self.phase == "transfer":
                self.progress_wrapper.update_transfer(delta)
            self.current = current

    def reset(self):
        """Reset the callback to initial state."""
        self.current = 0


class DownloadProgressBar:
    """
    Progress bar wrapper specifically for download operations.

    For downloads, the flow is:
    1. Download from server (network transfer)
    2. Decrypt the downloaded data
    """

    def __init__(self, filename: str):
        """
        Initialize download progress bar.

        Args:
            filename: Name of the file being downloaded
        """
        self.wrapper = ProgressBarWrapper(f"Downloading '{filename}'")
        self.encrypted_size: Optional[int] = None
        self.decrypted_size: Optional[int] = None

    def start_download(self, size: Optional[int] = None):
        """
        Start the download phase.

        Args:
            size: Size of encrypted data to download
        """
        self.encrypted_size = size
        self.wrapper.transfer_phase(total=size, desc="Downloading")

    def update_download(self, amount: int):
        """
        Update download progress.

        Args:
            amount: Bytes downloaded
        """
        self.wrapper.update_transfer(amount)

    def start_decrypt(self):
        """Start the decryption phase."""
        self.wrapper.encrypt_phase(total=self.encrypted_size, desc="Decrypting")

    def update_decrypt(self, amount: int):
        """
        Update decryption progress.

        Args:
            amount: Bytes decrypted
        """
        self.wrapper.update_encrypt(amount)

    def set_decrypted_size(self, size: int):
        """
        Set the size of decrypted data.

        Args:
            size: Size of decrypted data
        """
        self.decrypted_size = size
        if "encrypt" in self.wrapper.phase_bars:
            self.wrapper.phase_bars["encrypt"].total = size
            self.wrapper.phase_bars["encrypt"].refresh()

    def close(self):
        """Close all progress bars."""
        self.wrapper.close()


class UploadProgressBar:
    """
    Progress bar wrapper specifically for upload operations.

    For uploads, the flow is:
    1. Encrypt the file
    2. Upload encrypted data to server (network transfer)
    """

    def __init__(self, filename: str):
        """
        Initialize upload progress bar.

        Args:
            filename: Name of the file being uploaded
        """
        self.wrapper = ProgressBarWrapper(f"Uploading '{filename}'")
        self.encrypted_size: Optional[int] = None

    def start_encrypt(self):
        """Start the encryption phase."""
        self.wrapper.encrypt_phase(total=None, desc="Encrypting")

    def update_encrypt(self, amount: int):
        """
        Update encryption progress.

        Args:
            amount: Bytes encrypted
        """
        self.wrapper.update_encrypt(amount)

    def set_encrypted_size(self, size: int):
        """
        Set the size of encrypted data.

        Args:
            size: Size of encrypted data
        """
        self.encrypted_size = size
        if "encrypt" in self.wrapper.phase_bars:
            self.wrapper.phase_bars["encrypt"].total = size
            self.wrapper.phase_bars["encrypt"].refresh()

    def start_upload(self):
        """Start the upload phase."""
        self.wrapper.transfer_phase(total=self.encrypted_size, desc="Transferring")

    def update_upload(self, amount: int):
        """
        Update upload progress.

        Args:
            amount: Bytes uploaded
        """
        self.wrapper.update_transfer(amount)

    def close(self):
        """Close all progress bars."""
        self.wrapper.close()
