# MilleGrilles File Transfer utility

This is a python file transfer utility for MilleGrilles.

## Development

Run using the .venv in the project (use `. .venv/bin/activate`, not `source`. To run: `python3 -m tksample1`.

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
| `get <remote> [local]` | Download file from server (optional local filename) |
| `put <local> [remote]` | Upload file to server (optional remote filename) |
| `mkdir <path>` | Create a new directory on the server |
| `exit` or `quit` | Exit the CLI |

### CLI Usage Notes

- Only allows navigating down one level at a time
- Only allows downloading files from the current directory
- Only allows uploading files to the current directory
- `get` distinguishes between downloading a single file or a directory
- `put` distinguishes between uploading a single file or a directory

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
    ├── __main__.py               # Application entry point
    ├── AuthUsager.py             # User authentication module
    ├── CLI.py                    # CLI handler for text-based interface
    ├── Downloader.py             # File download functionality
    ├── FileTransfer.py           # Main file transfer UI handler
    ├── Navigation.py             # File/directory navigation
    ├── Uploader.py               # File upload functionality
    ├── apiMapping.signed.json    # API mapping configuration with signed JSON
    └── mimetypes.json            # MIME type definitions
```

### Module Descriptions

| Module | Description |
|--------|-------------|
| **AuthUsager.py** | User authentication module handling MilleGrilles certificate management, secure communication, and session management. |
| **CLI.py** | Command-line interface handler providing text-based file transfer operations with sftp-like commands. |
| **Downloader.py** | File download functionality with progress tracking, encrypted file handling, and collection synchronization. |
| **FileTransfer.py** | Main GUI component implementing the file transfer interface, coordinating uploads and downloads. |
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