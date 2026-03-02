import logging
from shlex import split as shlex_split
from threading import Event, Lock
from typing import List, Optional

from tksample1.FileTransfer import TransferHandler
from tksample1.Navigation import Navigation, Repertoire, sync_collection


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

                self._process_command(command_input)
            except KeyboardInterrupt:
                self.__logger.info("CLI interrupted by user")
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
                print("Hint: Use GUI mode to authenticate first, then try CLI mode.")
                raise ConnectionError("No credentials available for auto-connect")

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
        print("Available commands:")
        print("  ls [path]  - List directory contents")
        print("  cd <path>  - Change directory (use '..' for parent)")
        print("  pwd        - Print working directory")
        print("  get <file> - Download file from current directory")
        print("  exit       - Exit CLI")
        print()
        print("Type 'help' for more information")
        print()

    def _get_command_input(self) -> Optional[str]:
        """Get and validate command input from user."""
        try:
            # Show prompt with current path
            current_path = self._get_current_path()
            command = input(f"mgtransfer{current_path}> ").strip()

            if not command:
                return None  # Empty command, continue loop

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
        elif command == "exit" or command == "quit":
            self.cmd_exit()
        elif command == "help":
            self._print_help()
        else:
            print(f"Unknown command: {command}")
            print("Type 'help' for available commands")

    def _print_help(self):
        """Print help information."""
        print()
        print("Available commands:")
        print("  ls [path]  - List directory contents")
        print('  cd <path>  - Change directory (use quotes for spaces: cd "dir name")')
        print("  pwd        - Print current working directory")
        print("  get <file> - Download file from current directory")
        print("  exit       - Exit CLI")
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

        for item in repertoire.fichiers:
            # Determine type (directory or file)
            type_node = item.get("type_node", "")
            item_type = "DIR " if type_node in ["Collection", "Repertoire"] else ""

            # Get name
            name = item.get("metadata", {}).get("nom", "Unknown")

            # Get size (only for files)
            type_node = item.get("type_node", "")
            if type_node not in ["Collection", "Repertoire"]:
                size = item.get("size", 0)
                size_str = self._format_size(size)
            else:
                size_str = "-"

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
            self.__current_path_display = " / ".join(path_parts)

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

            # Distinguish between file and directory download
            if type_node in ["Collection", "Repertoire"]:
                print(f"Downloading directory '{filename}'...")
                download_item = self.__transfer_handler.ajouter_download_repertoire(
                    target_item, connexion.download_path
                )
            elif type_node == "Fichier":
                print(f"Downloading file '{filename}'...")
                download_item = self.__transfer_handler.ajouter_download_fichier(
                    target_item, connexion.download_path
                )
            else:
                print(f"Error: Unsupported type '{type_node}'")
                return

            # Wait for download to complete
            download_item.wait()
            print(f"Download complete: '{filename}'")

        except FileExistsError:
            print(f"Error: File '{filename}' already exists in download directory")
        except Exception as e:
            self.__logger.exception("Error during get operation")
            print(f"Error: {e}")

    def _format_size(self, size: int) -> str:
        """Format size in human-readable format."""
        size_float = float(size)
        for unit in ["B", "KB", "MB", "GB"]:
            if size_float < 1024:
                return f"{size_float:.1f}{unit}"
            size_float /= 1024
        return f"{size_float:.1f}TB"
