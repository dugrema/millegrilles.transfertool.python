import logging
import pathlib
import signal
import sys
from shlex import split as shlex_split
from threading import Event, Lock
from typing import List, Optional

from tksample1.Downloader import CancelledDownloadException
from tksample1.FileTransfer import TransferHandler
from tksample1.Navigation import Navigation, Repertoire, sync_collection
from tksample1.ProgressBar import DownloadProgressBar, UploadProgressBar


class CLIHandler:
    """Handler for Command Line Interface operations."""

    def __init__(
        self,
        stop_event: Event,
        auth,
        navigation: Navigation,
        transfer_handler: TransferHandler,
    ):
        """Initialize CLI handler with dependencies.

        Args:
            stop_event: Event to signal application stop
            auth: Authentification instance for authentication state
            navigation: Navigation instance for directory operations
            transfer_handler: TransferHandler instance for file transfers
        """
        self.__logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.__stop_event = stop_event
        self.__auth = auth
        self.__navigation = navigation
        self.__transfer_handler = transfer_handler

        # Lock for thread-safe operations
        self.__lock = Lock()

        # Track navigation state
        # We'll access Navigation's breadcrumb and repertoire directly
        self.__current_path_display: str = "(Favoris)"

        # Local directory tracking (for lcd, lls, lpwd)
        self.__local_dir: pathlib.Path = (
            self.__auth.download_path
        )  # Initialize with download directory

    def run(self):
        """Main CLI loop."""
        # Wait for connection to be established
        self._wait_for_connection()

        # Print welcome message
        self._print_welcome()

        # Main command loop
        while self.__stop_event.is_set() is False:
            try:
                command_input = self._get_command_input()
                if command_input is None:
                    break
                if command_input == "":
                    continue

                self._process_command(command_input)
            except KeyboardInterrupt:
                self.__logger.info("CLI interrupted by user (CTRL-C)")
                # Cancel all active uploads and downloads
                cancelled_downloads = len(
                    self.__transfer_handler.downloader.get_active_downloads()
                )
                cancelled_uploads = len(
                    self.__transfer_handler.uploader.get_active_uploads()
                )

                if cancelled_downloads > 0 or cancelled_uploads > 0:
                    print("\nCTRL-C detected. Cancelling active transfers...")
                    if cancelled_downloads > 0:
                        self.__transfer_handler.downloader.cancel_all_downloads()
                        print(f"Cancelled {cancelled_downloads} active download(s)")
                    if cancelled_uploads > 0:
                        self.__transfer_handler.uploader.cancel_all_uploads()
                        print(f"Cancelled {cancelled_uploads} active upload(s)")
                    # Wait a moment for cancellation to propagate
                    import time

                    time.sleep(0.5)
                    print("Transfers cancelled. CLI session continues...")
                    # Continue CLI loop instead of breaking
                    continue
                else:
                    # No active transfers, exit CLI
                    print("\nNo active transfers. Exiting CLI...")
                    break
            except Exception as e:
                self.__logger.exception("Error processing command")
                print(f"Error: {e}")

        self.__logger.info("CLI stopped")

    def _wait_for_connection(self):
        """Wait for authentication/connection to be established."""
        self.__logger.info("Waiting for connection...")
        print("Connecting to server...")

        # Wait for connect_event to be set
        if self.__auth.connect_event.is_set():
            self.__logger.info("Connection already established")
            print("Connection established")
        else:
            # Check if credentials exist and trigger authentication
            if self.__auth.nom_usager and self.__auth.url_fiche_serveur:
                print("Credentials found. Attempting auto-connect...")
                try:
                    # Trigger authentication programmatically
                    url_serveur = self.__auth.url_fiche_serveur.geturl()
                    self.__auth.authentifier(self.__auth.nom_usager, url_serveur)

                    # Wait for connection with timeout
                    connected = self.__auth.connect_event.wait(timeout=30)
                    if connected:
                        self.__logger.info("Connection established")
                        print("Connection established")
                    else:
                        print("Connection timeout after auto-connect attempt.")
                        raise ConnectionError("Failed to establish connection")
                except Exception as e:
                    self.__logger.exception("Auto-connect failed")
                    print(f"Auto-connect failed: {e}")
                    raise ConnectionError("Failed to establish connection")
            else:
                print("No saved credentials found.")
                print("Auto-triggering connect command for authentication...\n")
                # Auto-trigger the connect command to prompt user for credentials
                self.cmd_connect()
                return  # cmd_connect handles the connection flow

            # Small delay to ensure navigation is ready
            import time

            time.sleep(0.5)

    def _print_welcome(self):
        """Print welcome message and help."""
        print()
        print("=" * 60)
        print("MilleGrilles Transfer Tool - CLI Mode")
        print("=" * 60)
        print()
        print("Connection commands:")
        print("  connect    - Connect to server (re-authenticate if needed)")
        print("  disconnect - Disconnect from server")
        print()
        print("Connection info:")
        print("  status     - Show current connection status")
        print()
        print("Remote commands:")
        print("  ls [path]  - List remote directory contents")
        print("  cd <path>  - Change remote directory (use '..' for parent)")
        print("  pwd        - Print remote working directory")
        print()
        print("Local commands:")
        print("  lls [pattern]  - List local directory contents")
        print("  lcd [path]     - Change local directory (no path = home)")
        print("  lpwd           - Print local working directory")
        print()
        print("Transfer commands:")
        print("  get <file> - Download file from remote to local directory")
        print("  put <file> - Upload file from local directory to remote")
        print()
        print("Other commands:")
        print("  mkdir <name> - Create directory on remote")
        print("  exit       - Exit CLI")
        print()
        print("Type 'help' for more information")
        print()

    def _get_prompt(self) -> str:
        """Generate the prompt string for display.

        Returns:
            Formatted prompt string in the format: user@hostname:path>
        """
        # Get remote path from navigation
        remote_path = self._get_current_path()

        # Get username and hostname from auth
        username = self.__auth.nom_usager or "user"
        url_fiche_serveur = self.__auth.url_fiche_serveur
        if url_fiche_serveur is not None:
            # url_fiche_serveur is already a ParseResult object
            hostname = url_fiche_serveur.hostname or "localhost"
        else:
            hostname = "localhost"

        return f"{username}@{hostname}:{remote_path}> "

    def _print_updated_prompt(self):
        """Print the current prompt to show updated path.

        This is called after cd commands to immediately show the updated prompt
        without waiting for the next command input.
        """
        print()
        print(self._get_prompt(), end="")

    def _get_command_input(self) -> Optional[str]:
        """Get and validate command input from user."""
        try:
            command = input(self._get_prompt()).strip()

            if not command:
                return ""  # Empty command, continue loop

            return command
        except EOFError:
            print()  # Newline after Ctrl+D
            return None
        except KeyboardInterrupt:
            print()  # Newline after Ctrl+C
            return None

    def _process_command(self, command_input: str):
        """Parse and process command input."""
        # Use shlex to properly handle quoted strings
        try:
            parts = shlex_split(command_input)
        except ValueError:
            # If shlex fails (unbalanced quotes), fall back to simple split
            parts = command_input.split()

        if not parts:
            return

        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []

        # Route to appropriate command handler
        if command == "ls" or command == "list":
            self.cmd_ls(args)
        elif command == "cd":
            self.cmd_cd(args)
        elif command == "pwd":
            self.cmd_pwd()
        elif command == "get":
            self.cmd_get(args)
        elif command == "put":
            self.cmd_put(args)
        elif command == "mkdir":
            self.cmd_mkdir(args)
        elif command == "lcd":
            self.cmd_lcd(args)
        elif command == "lpwd":
            self.cmd_lpwd()
        elif command == "lls":
            self.cmd_lls(args)
        elif command == "exit" or command == "quit":
            self.cmd_exit()
        elif command == "disconnect":
            self.cmd_disconnect()
        elif command == "connect":
            # Extract TOTP code if provided as argument
            totp_code = args[0] if len(args) > 0 else None
            self.cmd_connect(totp_code=totp_code)
        elif command == "status":
            self.cmd_status()
        elif command == "cancel":
            self.cmd_cancel(args)
        elif command == "help":
            self._print_help()
        else:
            print(f"Unknown command: {command}")
            print("Type 'help' for available commands")

    def cmd_disconnect(self):
        """Disconnect from server."""
        self.__logger.info("Disconnecting from server...")
        print("Disconnecting from server...")
        self.__auth.effacer_usager()  # Clean-up user cert/session, prevent auto-reconnection
        self.__auth.deconnecter()
        print("Disconnected from server")
        print("Tip: Use 'connect' to re-authenticate if needed")
        print()

    def _prompt_for_credentials(self):
        """Prompt user for username and server URL."""
        print("\n=== MilleGrilles Authentication ===\n")

        # Prompt for username
        username = input("Enter your username: ").strip()
        if not username:
            print("Error: Username cannot be empty.")
            return None, None

        # Prompt for server URL
        server_url = input(
            "Enter server URL (e.g., https://millegrille.example.com): "
        ).strip()
        if not server_url:
            print("Error: Server URL cannot be empty.")
            return None, None

        # Validate URL format
        if not server_url.startswith(("http://", "https://")):
            server_url = f"https://{server_url}"

        return username, server_url

    def _prompt_for_totp(self) -> Optional[str]:
        """Prompt user for TOTP code if server requires it.

        Returns:
            TOTP code if provided, None otherwise
        """
        try:
            totp = input("\nCode TOTP (laisser vide si non requis): ").strip()
            return totp if totp else None
        except KeyboardInterrupt:
            print("\nAborted.")
            return None

    def _authenticate_user(
        self, username: str, server_url: str, totp_code: Optional[str] = None
    ):
        """Initiate authentication with the server.

        Args:
            username: User's username
            server_url: Server URL
            totp_code: Optional TOTP code for two-factor authentication

        Returns:
            bool: True if authentication initiated successfully, False otherwise
        """
        try:
            self.__auth.authentifier(username, server_url, totp_code=totp_code)
            return True
        except ImportError as e:
            # TOTP module not found - should not happen, but handle gracefully
            self.__logger.exception("TOTP validation module not found")
            print(
                "Error: TOTP validation module error - please reinstall the application"
            )
            return False
        except Exception as e:
            # Check if this is a TOTP validation error
            error_msg = str(e)
            if "TOTP" in error_msg or "Code TOTP" in error_msg:
                self.__logger.exception("TOTP validation failed")
                print(f"Error: {error_msg}")
            else:
                self.__logger.exception("Authentication failed")
                print(f"Error: Authentication failed - {e}")
            return False

    def _display_confirmation_code(self):
        """Display the confirmation code and instructions to the user."""
        confirmation_code = self.__auth.confirmation_code
        if confirmation_code is None:
            # Using existing certificate, no code needed
            return False

        print("\n" + "=" * 50)
        print("AUTHENTICATION CODE REQUIRED")
        print("=" * 50)
        print(f"\nYour confirmation code is: **{confirmation_code}**\n")
        print(
            "Please enter this code on your MilleGrilles device/app to approve this connection."
        )
        print("The server has 5 minutes (300 seconds) to approve your request.\n")
        print("Waiting for approval...")

        return True

    def _wait_for_server_approval(self, timeout: int = 300):
        """Wait for server to approve the authentication request.

        Args:
            timeout: Maximum time to wait in seconds (default 300)

        Returns:
            bool: True if approved, False if timeout or error
        """
        try:
            # Show progress indicator
            print("[", end="", flush=True)

            # Wait for the certificate event with progress
            progress_chars = [" "] * 30
            for i in range(timeout):
                progress_chars[i % 30] = "#"
                print("".join(progress_chars), end="\r", flush=True)

                if self.__auth.connect_event.wait(timeout=1):
                    print("] Approved!")
                    return True

                if i > 0 and i % 30 == 0:
                    print(f"\rWaiting for approval... {i} seconds elapsed", flush=True)

            print("\r[ ] Timeout!")
            return False

        except Exception as e:
            self.__logger.exception("Error waiting for server approval")
            print(f"\rError waiting for approval: {e}")
            return False

    def cmd_connect(self, totp_code: Optional[str] = None):
        """Connect to server with authentication flow and optional TOTP.

        Args:
            totp_code: Optional TOTP code from command argument
        """
        self.__logger.info(
            "Starting connection process with TOTP: %s", totp_code or "not provided"
        )
        print("\n=== Connect Command ===")

        # Check if already connected
        if self.__auth.connect_event.is_set():
            print("Already connected. Use 'disconnect' first to re-authenticate.")
            return

        # Step 1: Check if we have existing credentials
        if self.__auth.nom_usager and self.__auth.url_fiche_serveur:
            use_existing = (
                input("\nExisting credentials found. Use them? [y/N]: ").strip().lower()
            )
            if use_existing in ("y", "yes"):
                username = self.__auth.nom_usager
                server_url = self.__auth.url_fiche_serveur.geturl()
            else:
                credentials = self._prompt_for_credentials()
                if credentials[0] is None:
                    return
                username, server_url = credentials
        else:
            # No existing credentials, prompt for new ones
            credentials = self._prompt_for_credentials()
            if credentials[0] is None:
                return
            username, server_url = credentials

        # Step 2: Initiate authentication
        print(f"\nAuthenticating {username} with {server_url}...")
        if not self._authenticate_user(username, server_url, totp_code=totp_code):
            return

        # Step 3: Display confirmation code if needed
        needs_approval = self._display_confirmation_code()

        # Step 4: Wait for server approval (only if new authentication)
        if needs_approval:
            approved = self._wait_for_server_approval()
            if not approved:
                print(
                    "\nAuthentication timeout. Server did not approve the connection."
                )
                print("Please check your credentials and try again.")
                return

        # Step 5: Wait for connection to be established
        print("\nEstablishing connection...")
        connected = self.__auth.connect_event.wait(timeout=30)

        if connected:
            print("\n✓ Connection established successfully!")
            print(f"User: {self.__auth.nom_usager}")
            print(f"Server: {self.__auth.url_fiche_serveur.hostname}")
        else:
            print("\n✗ Connection timeout. Check credentials or server availability.")
            self.__logger.error("Connection timeout after authentication")

    def cmd_status(self):
        """Show connection status."""
        connected = self.__auth.connect_event.is_set()
        if connected:
            print("Status: Connected")
            if self.__auth.nom_usager:
                print(f"User: {self.__auth.nom_usager}")
        else:
            print("Status: Disconnected")
            if self.__auth.nom_usager:
                print(f"User: {self.__auth.nom_usager} (use 'connect' to authenticate)")
            else:
                print("No credentials found. Use GUI mode to authenticate first.")

    def _print_help(self):
        """Print help information."""
        print()
        print("Available commands:")
        print("Connection:")
        print("  connect [TOTP_CODE] - Connect to server")
        print("                      - TOTP_CODE: Optional 2FA code (6-10 digits)")
        print("                      - Example: connect 123456")
        print("  disconnect - Disconnect from server")
        print("  status     - Show current connection status")
        print()
        print("Remote:")
        print("  ls [path]    - List remote directory contents")
        print("  cd <path>    - Change remote directory")
        print("  pwd          - Print remote working directory")
        print()
        print("Local:")
        print("  lls [pat]    - List local directory (glob pattern)")
        print("  lcd [path]   - Change local directory")
        print("  lpwd         - Print local working directory")
        print()
        print("Transfer:")
        print("  get <file>   - Download file to local directory")
        print("  put <path>   - Upload file from local directory")
        print("  cancel [file] - Cancel active transfer (empty cancels all)")
        print("    cancel --uploads    - Cancel all uploads")
        print("    cancel --downloads  - Cancel all downloads")
        print("  mkdir <name> - Create remote directory")
        print()
        print("Other:")
        print("  exit         - Exit CLI")
        print()

    def cmd_ls(self, args: List[str]):
        """List directory contents.

        For Phase 1: Only list current directory.
        No path argument support yet.
        """
        if args:
            print("Path argument not supported yet. Listing current directory only.")

        try:
            self._list_current_directory()
        except Exception as e:
            self.__logger.exception("Error listing directory")
            print(f"Error: {e}")

    def _list_current_directory(self):
        """List contents of current directory.

        Uses the current directory state from navigation breadcrumb.
        """
        # Get connection from navigation
        connexion = self.__navigation.connexion

        if connexion is None or connexion.url_fiche_serveur is None:
            print("Error: Not connected to server")
            return

        try:
            # Get current directory from navigation state
            repertoire = self._get_current_repertoire_from_navigation()

            # Display contents
            self._display_directory(repertoire)

        except Exception as e:
            self.__logger.exception("Error loading directory")
            print(f"Error loading directory: {e}")

    def _display_directory(self, repertoire: Repertoire):
        """Display directory contents in a formatted way."""
        if repertoire.fichiers is None or len(repertoire.fichiers) == 0:
            print("(empty)")
            return

        print()
        # Print header
        print(f"{'Type':<6} {'Name':<40} {'Size':>15}")
        print("-" * 62)

        # Separate directories and files
        directories = []
        files = []

        for item in repertoire.fichiers:
            type_node = item.get("type_node", "")
            if type_node in ["Collection", "Repertoire"]:
                directories.append(item)
            else:
                files.append(item)

        # Sort directories case-insensitively by name
        directories.sort(key=lambda x: x.get("metadata", {}).get("nom", "").lower())

        # Sort files case-insensitively by name
        files.sort(key=lambda x: x.get("metadata", {}).get("nom", "").lower())

        # Display directories first
        for item in directories:
            type_node = item.get("type_node", "")
            item_type = "DIR " if type_node in ["Collection", "Repertoire"] else ""

            # Get name
            name = item.get("metadata", {}).get("nom", "Unknown")

            # Get size (directories show "-")
            size_str = "-"

            # Print formatted line
            print(f"{item_type:<6} {name:<40} {size_str:>15}")

        # Display files
        for item in files:
            type_node = item.get("type_node", "")
            item_type = ""

            # Get name
            name = item.get("metadata", {}).get("nom", "Unknown")

            # Get size (only for files)
            if type_node not in ["Collection", "Repertoire"]:
                # Size is stored in metadata, not directly in item
                version_courante = item["version_courante"]
                size = item.get("metadata", {}).get(
                    "taille", version_courante["taille"]
                )
                size_str = self._format_size(size)

            # Print formatted line
            print(f"{item_type:<6} {name:<40} {size_str:>15}")

        print()
        print(f"Total: {len(repertoire.fichiers)} items")

    def cmd_cd(self, args: List[str]):
        """Change directory.

        Supports:
        - '..' for parent directory
        - directory name to navigate down one level
        """
        if not args:
            print("Error: cd requires a path argument")
            return

        path = args[0]

        try:
            # Get current directory contents
            connexion = self.__navigation.connexion
            if connexion is None or connexion.url_fiche_serveur is None:
                print("Error: Not connected to server")
                return

            # Get current repertoire from navigation breadcrumb
            current_repertoire = self._get_current_repertoire_from_navigation()

            if path == "..":
                # Navigate up to parent directory
                self.__navigation.naviguer_up()
                print("Changed directory to parent")
            elif path == "Favoris" or path == "":
                # Navigate to root
                self.__navigation.changer_cuuid(None)
                print("Changed directory to root (Favoris)")
            else:
                # Navigate into a subdirectory
                # Find the directory in current repertoire
                target_item = None
                for item in current_repertoire.fichiers:
                    if item.get("metadata", {}).get("nom") == path:
                        type_node = item.get("type_node", "")
                        if type_node in ["Collection", "Repertoire"]:
                            target_item = item
                            break

                if target_item:
                    # Use changer_cuuid to navigate down
                    cuuid = target_item.get("tuuid")
                    self.__navigation.changer_cuuid(cuuid)
                    print(f"Changed directory to '{path}'")
                else:
                    if any(
                        f.get("metadata", {}).get("nom") == path
                        for f in current_repertoire.fichiers
                    ):
                        print(f"Error: '{path}' is not a directory")
                    else:
                        print(f"Error: Directory '{path}' not found")

        except Exception as e:
            self.__logger.exception("Error during cd operation")
            print(f"Error: {e}")

    def cmd_pwd(self):
        """Print working directory."""
        self._print_pwd()

    def _print_pwd(self):
        """Print current working directory path."""
        current_path = self._get_current_path()
        print(current_path)

    def _get_current_path(self) -> str:
        """Get current path string for display."""
        self._update_path_display()
        return self.__current_path_display

    def _update_path_display(self):
        """Update current path display based on navigation breadcrumb."""
        if len(self.__navigation.breadcrumb) == 0:
            self.__current_path_display = "(Favoris)"
        else:
            # Build path from breadcrumb
            path_parts = ["Favoris"]
            for item in self.__navigation.breadcrumb:
                name = item.get("metadata", {}).get("nom", "Unknown")
                path_parts.append(name)
            self.__current_path_display = "/".join(path_parts)

    def _get_current_repertoire_from_navigation(self) -> Repertoire:
        """Get the current directory from Navigation.

        This needs to wait for the background thread to process navigation
        and then return the current repertoire.
        """
        # For CLI, we need to poll or wait for navigation to complete
        # Since navigation uses background threads, we'll reload the current state
        connexion = self.__navigation.connexion

        # Determine cuuid based on breadcrumb
        if len(self.__navigation.breadcrumb) == 0:
            # Root directory
            return sync_collection(connexion)
        else:
            # Use the last breadcrumb item's tuuid
            last_item = self.__navigation.breadcrumb[-1]
            cuuid = last_item.get("tuuid")
            return sync_collection(connexion, cuuid)

    def cmd_exit(self):
        """Exit CLI mode."""
        print("Exiting CLI...")
        self.__stop_event.set()

    def cmd_get(self, args: List[str]):
        """Download file from current directory.

        Args:
            args: List containing the filename to download
        """
        if not args:
            print("Error: get requires a filename argument")
            print("Usage: get <filename>")
            return

        filename = args[0]
        download_item = None
        download_progress = None

        try:
            # Get current directory contents
            connexion = self.__navigation.connexion
            if connexion is None or connexion.url_fiche_serveur is None:
                print("Error: Not connected to server")
                return

            # Get current repertoire from navigation breadcrumb
            current_repertoire = self._get_current_repertoire_from_navigation()

            # Find the file in current directory
            target_item = None
            for item in current_repertoire.fichiers:
                if item.get("metadata", {}).get("nom") == filename:
                    target_item = item
                    break

            if not target_item:
                print(f"Error: File '{filename}' not found in current directory")
                return

            type_node = target_item.get("type_node", "")

            # For directories, download without progress bar (simpler)
            if type_node in ["Collection", "Repertoire"]:
                print(f"Downloading directory '{filename}'...")
                download_item = self.__transfer_handler.ajouter_download_repertoire(
                    target_item, self.__local_dir
                )
                try:
                    download_item.wait()
                except CancelledDownloadException:
                    print(f"\nDownload cancelled: '{filename}'")
                    return
                except Exception as e:
                    raise

                # Check if cancelled
                if download_item.is_cancelled():
                    print(f"\nDownload cancelled: '{filename}'")
                    return

                print(f"Download complete: '{filename}'")
                return

            # For files, use progress bar
            elif type_node == "Fichier":
                print(f"Downloading file '{filename}'...")

                # Create progress bar for download
                download_progress = DownloadProgressBar(filename)

                # Get encrypted size from target_item
                encrypted_size = target_item.get("version_courante", {}).get(
                    "taille", None
                )

                # Start download phase (transfer from server)
                download_progress.start_download(encrypted_size)

                # Set progress wrapper on transfer handler
                self.__transfer_handler.set_progress_wrappers(
                    downloader_progress_wrapper=download_progress.wrapper
                )

                # Download the file
                download_item = self.__transfer_handler.ajouter_download_fichier(
                    target_item, self.__local_dir
                )

                # Wait for download to complete
                try:
                    download_item.wait()
                except CancelledDownloadException:
                    print(f"\nDownload cancelled: '{filename}'")
                    download_progress.close()
                    return
                except Exception as e:
                    raise

                # Check if cancelled
                if download_item.is_cancelled():
                    print(f"\nDownload cancelled: '{filename}'")
                    download_progress.close()
                    return

                # Start decrypt phase after download completes
                download_progress.start_decrypt()

                # Close progress bars
                download_progress.close()

                print(f"Download complete: '{filename}'")
            else:
                print(f"Error: Unsupported type '{type_node}'")
                return

        except KeyboardInterrupt:
            # Handle Ctrl+C
            print(f"\nDownload interrupted by user")
            if download_item is not None:
                self.__transfer_handler.downloader.cancel_download(download_item)
            if download_progress is not None:
                download_progress.close()
            # Partial files will be cleaned up by the downloader
            return
        except FileExistsError:
            print(f"Error: File '{filename}' already exists in download directory")
            if download_progress is not None:
                download_progress.close()
        except CancelledDownloadException:
            # Cancellation propagated - should not reach here, but handle gracefully
            print(f"\nDownload cancelled: '{filename}'")
            if download_progress is not None:
                download_progress.close()
        except Exception as e:
            self.__logger.exception("Error during get operation")
            print(f"Error: {e}")

    def cmd_put(self, args: List[str]):
        """Upload file or directory to current directory.

        Args:
            args: List containing the local file/directory path to upload
        """
        if not args:
            print("Error: put requires a local file/directory path argument")
            print("Usage: put <local_path>")
            return

        local_path = args[0]

        try:
            # Get current directory information
            connexion = self.__navigation.connexion
            if connexion is None or connexion.url_fiche_serveur is None:
                print("Error: Not connected to server")
                return

            # Resolve relative paths against local directory
            if not pathlib.Path(local_path).is_absolute():
                local_path = str(self.__local_dir / local_path)

            path_upload = pathlib.Path(local_path)
            if not path_upload.exists():
                print(f"Error: Local path '{local_path}' does not exist")
                return

            # Get current directory cuuid from navigation breadcrumb
            cuuid_parent: str | None = None
            if len(self.__navigation.breadcrumb) > 0:
                cuuid_parent = self.__navigation.breadcrumb[-1].get("tuuid")

            # For directories, upload without progress bar (simpler)
            # For directories, upload without progress bar (simpler)
            if path_upload.is_dir():
                print(f"Uploading directory '{local_path}'...")
                upload_item = self.__transfer_handler.ajouter_upload(
                    cuuid_parent or "", str(path_upload)
                )
                upload_item.wait()
                print(f"Upload complete: '{local_path}'")
                return

            # For files, use progress bar
            if path_upload.is_file():
                print(f"Uploading file '{local_path}'...")

                # Get file size for progress bar
                file_size = path_upload.stat().st_size

                # Create progress bar for upload
                upload_progress = UploadProgressBar(path_upload.name)

                # Start encryption phase with file size
                upload_progress.start_encrypt(total=file_size)

                # Set progress wrapper on transfer handler
                self.__transfer_handler.set_progress_wrappers(
                    uploader_progress_wrapper=upload_progress.wrapper
                )

                # Upload the file
                upload_item = self.__transfer_handler.ajouter_upload(
                    cuuid_parent or "", str(path_upload)
                )

                # Wait for upload to complete
                upload_item.wait()

                # Close progress bars
                upload_progress.close()

                print(f"Upload complete: '{local_path}'")
            else:
                print(f"Error: '{local_path}' is neither a file nor a directory")
                return

        except Exception as e:
            self.__logger.exception("Error during put operation")
            print(f"Error: {e}")

    def cmd_lcd(self, args: List[str]):
        """Change local working directory.

        Args:
            args: Optional path to change to. If empty, changes to home directory.
        """
        try:
            if not args:
                # Change to home directory
                self.__local_dir = pathlib.Path.home()
                print(f"Changed local directory to {self.__local_dir}")
                return

            path = args[0]

            # Support tilde expansion
            if path.startswith("~"):
                path = pathlib.Path(path).expanduser()

            # Resolve the path (handle relative and absolute paths)
            if pathlib.Path(path).is_absolute():
                new_dir = pathlib.Path(path)
            else:
                # Relative to current local directory
                new_dir = self.__local_dir / path

            # Check if it's a symlink
            is_symlink = new_dir.is_symlink()

            # Validate: must be a directory or a symlink to a directory
            if not is_symlink:
                # Regular path: check if it exists and is a directory
                if not new_dir.exists():
                    print(f"Error: Local directory '{path}' does not exist")
                    return
                if not new_dir.is_dir():
                    print(f"Error: '{path}' is not a directory")
                    return
            else:
                # Symlink: check if it points to a directory
                # is_dir() follows symlinks by default
                if not new_dir.is_dir():
                    print(
                        f"Error: '{path}' is not a directory or points to non-existent target"
                    )
                    return

            self.__local_dir = new_dir.resolve()
            print(f"Changed local directory to {self.__local_dir}")

        except Exception as e:
            print(f"Error changing local directory: {e}")

    def cmd_lpwd(self):
        """Print local working directory."""
        print(str(self.__local_dir))

    def cmd_lls(self, args: List[str]):
        """List local directory contents.

        Args:
            args: Optional glob pattern for filtering files.
        """
        try:
            pattern = args[0] if args else "*"

            # Get matching files/directories
            items = list(self.__local_dir.glob(pattern))

            if not items:
                print("(empty)")
                return

            print()
            print(f"{'Type':<6} {'Name':<40} {'Size':>15}")
            print("-" * 62)

            for item in sorted(items):
                item_type = "DIR " if item.is_dir() else ""
                name = item.name

                if item.is_file():
                    try:
                        size_str = self._format_size(item.stat().st_size)
                    except OSError:
                        size_str = "-"
                else:
                    size_str = "-"

                print(f"{item_type:<6} {name:<40} {size_str:>15}")

            print()
            print(f"Total: {len(items)} items")

        except Exception as e:
            print(f"Error listing local directory: {e}")

    def cmd_cancel(self, args: List[str]):
        """Cancel active downloads and uploads.

        Args:
            args: Optional arguments. Can be:
                - [] - Cancel all active transfers
                - ['--uploads'] - Cancel uploads only
                - ['--downloads'] - Cancel downloads only
                - [filename] - Cancel specific transfer by filename
        """
        try:
            # Get active transfers
            active_downloads = self.__transfer_handler.downloader.get_active_downloads()
            active_uploads = self.__transfer_handler.uploader.get_active_uploads()

            # Determine what to cancel based on args
            cancel_downloads = True
            cancel_uploads = True
            target_filename = None

            if args:
                if args[0] == "--uploads":
                    cancel_downloads = False
                elif args[0] == "--downloads":
                    cancel_uploads = False
                else:
                    # Specific filename
                    target_filename = args[0]

            has_active = bool(active_downloads or active_uploads)

            if not has_active:
                print("No active transfers to cancel")
                return

            # List active transfers
            if active_downloads:
                print(f"Found {len(active_downloads)} active download(s):")
                for i, download in enumerate(active_downloads, 1):
                    download_type = (
                        "Directory" if hasattr(download, "cuuid") else "File"
                    )
                    print(f"  D{i}. {download.nom} ({download_type})")

            if active_uploads:
                print(f"Found {len(active_uploads)} active upload(s):")
                for i, upload in enumerate(active_uploads, 1):
                    from tksample1.Uploader import UploadRepertoire

                    upload_type = (
                        "Directory" if isinstance(upload, UploadRepertoire) else "File"
                    )
                    print(f"  U{i}. {upload.path.name} ({upload_type})")

            # If specific filename provided, cancel that transfer
            if target_filename:
                cancelled = False

                # Try to find in downloads
                for download in active_downloads:
                    if download.nom == target_filename:
                        self.__transfer_handler.downloader.cancel_download(download)
                        print(f"Cancelled download: {target_filename}")
                        cancelled = True
                        break

                # Try to find in uploads if not found in downloads
                if not cancelled:
                    for upload in active_uploads:
                        if upload.path.name == target_filename:
                            self.__transfer_handler.uploader.cancel_upload(upload)
                            print(f"Cancelled upload: {target_filename}")
                            cancelled = True
                            break

                if not cancelled:
                    print(f"No active transfer found for: {target_filename}")
            else:
                # Cancel based on flags
                cancelled_anything = False

                if cancel_downloads and active_downloads:
                    self.__transfer_handler.downloader.cancel_all_downloads()
                    print(f"Cancelled {len(active_downloads)} active download(s)")
                    cancelled_anything = True

                if cancel_uploads and active_uploads:
                    self.__transfer_handler.uploader.cancel_all_uploads()
                    print(f"Cancelled {len(active_uploads)} active upload(s)")
                    cancelled_anything = True

                if not cancelled_anything:
                    print("No matching transfers to cancel")

        except Exception as e:
            self.__logger.exception("Error during cancel operation")
            print(f"Error: {e}")

    def cmd_mkdir(self, args: List[str]):
        """Create new directory/collection on server in current directory.

        Args:
            args: List containing the name of the directory to create
        """
        if not args:
            print("Error: mkdir requires a directory name argument")
            print("Usage: mkdir <directory_name>")
            return

        dir_name = args[0]

        try:
            # Get current directory information
            connexion = self.__navigation.connexion
            if connexion is None or connexion.url_fiche_serveur is None:
                print("Error: Not connected to server")
                return

            # Get current directory cuuid from navigation breadcrumb
            cuuid_parent: str | None = None
            if len(self.__navigation.breadcrumb) > 0:
                cuuid_parent = self.__navigation.breadcrumb[-1].get("tuuid")

            # Create the collection using Uploader.creer_collection
            cuuid = self.__transfer_handler.uploader.creer_collection(
                dir_name, cuuid_parent
            )

            print(f"Directory '{dir_name}' created successfully (tuuid: {cuuid})")

            # Refresh current directory state to include new directory
            self._get_current_repertoire_from_navigation()

        except Exception as e:
            self.__logger.exception("Error during mkdir operation")
            print(f"Error: {e}")

    def _format_size(self, size: int) -> str:
        """Format size in human-readable format."""
        size_float = float(size)
        for unit in ["B", "KB", "MB", "GB"]:
            if size_float < 1024:
                return f"{size_float:.1f}{unit}"
            size_float /= 1024
        return f"{size_float:.1f}TB"
