"""
Custom exceptions for download pause/resume functionality.
"""


class DownloadPausedException(Exception):
    """Raised when a download is paused."""

    pass


class DownloadRetryException(Exception):
    """Raised when a download should be retried due to network error."""

    def __init__(self, message: str, retry_count: int, last_error: Exception = None):
        super().__init__(message)
        self.retry_count = retry_count
        self.last_error = last_error


class DownloadFailedException(Exception):
    """Raised when a download has failed after all retries."""

    def __init__(self, message: str, last_error: Exception = None):
        super().__init__(message)
        self.last_error = last_error
