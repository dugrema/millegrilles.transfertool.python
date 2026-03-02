# MilleGrilles Transfer Tool - Update Plan

## Overview

This document outlines the design for adding new features to the MilleGrilles Transfer Tool, including CLI support, command-line arguments, configuration management, and GUI improvements.

---

## Feature List

### 1. Command Line Interface (CLI)
- **Description**: A sftp-like text-based interface for file transfers
- **Purpose**: Enable automated/scripted file operations, remote server access via terminal
- **Status**: New feature

### 2. Command-Line Arguments
- **`--cli`**: Disable GUI and start CLI mode only
- **Status**: New feature

---

## Design Proposals

### Feature 1: Command Line Interface (CLI)

#### Architecture
```
App (Entry Point)
├── CLI Mode
│   ├── CommandLineParser (argparse)
│   ├── CLIHandler (core logic)
│   └── CLI Interface (readline or similar)
└── GUI Mode (existing)
    ├── Window (tkinter)
    └── Notebooks
```

#### Implementation Details

**1.1 Create CLI Handler Class**
```python
# tksample1/CLI.py

class CLIHandler:
    def __init__(self, stop_event, auth, navigation, transfer_handler):
        self.auth = auth
        self.navigation = navigation
        self.transfer_handler = transfer_handler
        self.stop_event = stop_event
        
    def run(self):
        # Main CLI loop
        # Prompt: "mgtransfer> "
        # Commands: ls, cd, pwd, get, put, mkdir, exit
        
    def cmd_ls(self, args):
        # List directory contents
        
    def cmd_cd(self, args):
        # Change directory
        
    def cmd_get(self, args):
        # Download file
        
    def cmd_put(self, args):
        # Upload file
        
    def cmd_exit(self, args):
        # Set stop event and break loop
```

**1.2 CLI Command Structure**
- `connect`: Connect with existing certificate or proceed with authentication behavior (existing `Connecter` button).
- `disconnect`: Same as current behavior for `Deconnecter` button.
- `ls [path]` - List directory contents
- `cd <path>` - Change directory
- `pwd` - Print working directory
- `get <remote> [local]` - Download file
- `put <local> [remote]` - Upload file
- `mkdir <path>` - Create directory
- `exit` or `quit` - Exit CLI

**1.3 Integration Points**
- Use existing `navigation` and `transfer_handler` classes
- Reuse authentication from `Authentification` class
- Shared configuration with GUI mode
- Use `Navigation.changer_cuuid()` to load the directory information on `cd` and refresh with `ls`. This information needs to be kept in memory like in the GUI for `get` operations.
- `cd ..` uses the existing `Navigation.naviguer_up()` behavior.
- For now, only allow navigating down one level at a time and only allow downloading files from the current directory and uploading files to the current directory.
- `get` must distinguish between downloading a signle file or a directory; behavior already exists in `Downloader`.
- `put` must distinguish between uploading a single file or a directory; behavior already exists in `Uploader.py`.
---

### Feature 2: Command-Line Arguments

#### Argument Parser Structure

```python
# __main__.py modified

import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='MilleGrilles Transfer Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--cli',
        action='store_true',
        help='Run in CLI mode (disable GUI)'
    )
    
    ...
    
    return parser.parse_args()
```

#### Integration in App Class

```python
class App:
    def __init__(self, args=None):
        ...
        
        # Choose mode
        if self.args.cli:
            self.run_cli_mode()
        else:
            self.run_gui_mode()
```

---

## Implementation Order

### Phase 1: CLI Mode Foundation
1. Create `CLI.py` module with `CLIHandler` class
2. Implement basic CLI commands (ls, cd, pwd)
3. Add CLI mode entry point
4. Test CLI functionality

### Phase 2: Command-Line Arguments
1. Add CLI mode toggle (`--cli`)

---

## Potential Challenges

### 1. CLI Mode Complexity
- **Challenge**: Maintaining consistency between CLI and GUI modes
- **Solution**: Share core logic classes, only different in presentation layer

### 2. Configuration Synchronization
- **Challenge**: CLI args vs config file vs GUI settings
- **Solution**: Clear priority order: CLI args > Config file > Defaults

### 3. Resizable Layouts
- **Challenge**: Complex nested layouts with notebooks, paned windows
- **Solution**: Use grid weights and sticky configurations throughout

### 4. Authentication State
- **Challenge**: Ensuring auth state persists between CLI and GUI
- **Solution**: Shared `Authentification` instance across modes

---

## Notes

- All new code should follow existing project patterns
- Use existing logging infrastructure
- Maintain thread safety with stop_event pattern
- Keep GUI responsive with proper threading
- Document new methods/classes appropriately
