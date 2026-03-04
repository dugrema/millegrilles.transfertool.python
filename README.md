# MilleGrilles Transfer Tool

A Python file transfer utility for MilleGrilles with GUI and CLI support.

## DEV

For local development, ensure tkinter is installed.

```bash
sudo apt install python3-tk
```

## CLI Mode

Run in CLI mode (text-based interface) by using the `--cli` argument:

```bash
python3 -m tksample1 --cli
```

### Command-line Parameters

| Parameter | Description |
|-----------|-------------|
| `--verbose` | Use DEBUG logging |
| `--cli` | Run in CLI mode (disable GUI) |
| `--gui` | Force GUI mode (will fail if display not available) |
| `--downdir <path>` | Download directory (overrides config) |
| `--tmpdir <path>` | Temporary directory for processing |

### Auto-Fallback Behavior

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

### CLI Commands

| Command | Description |
|---------|-------------|
| `connect` | Connect with existing certificate or proceed with authentication |
| `disconnect` | Disconnect from the MilleGrilles server |
| `ls [path]` | List directory contents (current or specified path) |
| `cd <path>` | Change directory (use `..` to go up one level) |
| `pwd` | Print current working directory |
| `get <remote> [local]` | Download file from server (optional local filename) |
| `put <local> [remote]` | Upload file to server (optional remote filename) |
| `mkdir <path>` | Create a new directory on the server |
| `exit` or `quit` | Exit the CLI |

#### Local Commands

| Command | Description |
|---------|-------------|
| `lls [pattern]` | List local directory contents |
| `lcd <path>` | Change local directory (no path = home) |
| `lpwd` | Print local working directory |

### CLI Usage Notes

- Only allows navigating down one level at a time
- Only allows downloading files from the current directory
- Only allows uploading files to the current directory
- `get` distinguishes between downloading a single file or a directory
- `put` distinguishes between uploading a single file or a directory

### Examples

```bash
# Run in CLI mode on a server
MGTRANSFER_MODE=cli python3 -m tksample1

# Run via SSH (auto-fallback)
ssh user@server "python3 -m tksample1"

# Force GUI even in headless (will fail)
python3 -m tksample1 --gui

# Connect with verbose logging
python3 -m tksample1 --cli --verbose

# Use custom download directory
python3 -m tksample1 --cli --downdir /home/user/downloads
```

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

## Dependencies

- **requests** - HTTP client for API calls
- **python-socketio[client]** - Socket.IO client for real-time communication
- **websocket-client** - WebSocket client for additional connectivity
- **wakepy** - Keep system awake during file transfers
- **millegrilles_messages** - MilleGrilles messaging library for encrypted communication