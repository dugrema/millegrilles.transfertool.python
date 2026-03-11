# MilleGrilles File Transfer utility

This is a python file transfer utility for MilleGrilles.

## Development

Run using the .venv in the project (use `. .venv/bin/activate`, not `source`. To run: `python3 -m tksample1`.

## Auto-Fallback Behavior

The application automatically detects GUI availability and falls back to CLI mode when:
- No display is available (`$DISPLAY` or `$WAYLAND_DISPLAY` not set)
- tkinter is not installed
- Running in a headless environment (SSH, Docker, CI/CD)

### Force Mode Selection

**Command-line flags:**
- `--cli` - Force CLI mode
- `--gui` - Force GUI mode (will error if unavailable)

**Environment variable:**
- `MGTRANSFER_MODE=cli` - Force CLI mode
- `MGTRANSFER_MODE=gui` - Force GUI mode

**Examples:**
```bash
# Run in CLI mode on a server
MGTRANSFER_MODE=cli python3 -m tksample1

# Run via SSH (auto-fallback)
ssh user@server "python3 -m tksample1"

# Force GUI even in headless (will fail)
python3 -m tksample1 --gui
```

## CLI Mode

Run in CLI mode (text-based interface) by using the `--cli` argument:

```bash
python3 -m tksample1 --cli
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `connect` | Connect with existing certificate or proceed with authentication |
| `disconnect` | Disconnect from the MilleGrilles server |
| `ls [path]` | List directory contents (current or specified path) |
| `cd <path>` | Change directory (use `..` to go up one level) |
| `pwd` | Print current working directory |
| `get <remote> [--1pass]` | Download file from server (use --1pass for 1-pass mode) |
| `put <local> [remote]` | Upload file to server (optional remote filename) |
| `mkdir <path>` | Create a new directory on the server |
| `set download [--1pass | --2pass]` | Set download mode (--1pass: faster, not resumable; --2pass: default, resumable) |
| `status` | Show current connection and configuration status |
| `exit` or `quit` | Exit the CLI |

### CLI Usage Notes

- Only allows navigating down one level at a time
- Only allows downloading files from the current directory
- Only allows uploading files to the current directory
- `get` distinguishes between downloading a single file or a directory
- `put` distinguishes between uploading a single file or a directory
- `get --1pass` uses 1-pass download/decrypt (faster, not resumable)
- `set download --1pass` enables 1-pass mode for subsequent downloads
- `set download --2pass` disables 1-pass mode (default, resumable)

## Folder Structure

```
millegrilles.transfertool.python/
├── .idea/                          # IDE configuration folder
├── .gitignore                      # Git ignore rules
├── AGENTS.md                       # Project documentation (this file)
├── README.md                       # Project README with development notes
├── requirements.txt                # Python dependencies
├── bin/                            # Build and installation scripts
│   ├── build.sh                  # Build script for creating release packages
│   ├── install_mgtransfer.bat    # Windows installation script
│   └── mgtransfertool.bat        # Windows launcher script
└── tksample1/                      # Main application package
    ├── __init__.py               # Package initialization (empty)
    ├── __main__.py               # Application entry point with auto-fallback
    ├── AuthUsager.py             # User authentication module
    ├── CLI.py                    # CLI handler for text-based interface
    ├── Configuration.py          # Configuration management
    ├── ConnectionFrame.py        # Connection UI frame (tabbed interface)
    ├── Downloader.py             # File download functionality
    ├── FileTransfer.py           # Main file transfer UI handler
    ├── GuiCapability.py          # GUI detection and auto-fallback utility
    ├── Navigation.py             # File system navigation
    ├── Uploader.py               # File upload functionality
    ├── apiMapping.signed.json    # API mapping configuration with signed JSON
    └── mimetypes.json            # MIME type definitions
```

### Module Descriptions

| Module | Description |
|--------|-------------|
| **AuthUsager.py** | User authentication module handling MilleGrilles certificate management, secure communication, and session management. |
| **CLI.py** | Command-line interface handler providing text-based file transfer operations with sftp-like commands. |
| **Configuration.py** | Configuration management for application settings and directories. |
| **ConnectionFrame.py** | GUI frame for connection management as a notebook tab, providing username/server URL inputs and connection status display. |
| **Downloader.py** | File download functionality with progress tracking, encrypted file handling, and collection synchronization. |
| **FileTransfer.py** | Main GUI component implementing the file transfer interface, coordinating uploads and downloads. |
| **GuiCapability.py** | GUI detection utility for auto-fallback to CLI mode in headless environments. |
| **Navigation.py** | File system navigation for browsing collections, displaying directories, and managing file selections. |
| **Uploader.py** | File upload module handling encrypted file transfers, progress tracking, and collection operations. |
| **apiMapping.signed.json** | API mapping configuration defining commands, requests, and subscriptions for MilleGrilles ecosystem interaction. |
| **mimetypes.json** | MIME type definitions for file handling and content type detection. |

### Dependencies

- **requests** - HTTP client for API calls
- **python-socketio[client]** - Socket.IO client for real-time communication
- **websocket-client** - WebSocket client for additional connectivity
- **wakepy** - Keep system awake during file transfers
- **millegrilles_messages** - MilleGrilles messaging library for encrypted communication