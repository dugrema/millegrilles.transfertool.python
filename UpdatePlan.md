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
- **`--downdir`**: Specify download directory
- **`--tmpdir`**: Specify temporary directory for processing
- **`--cli`**: Disable GUI and start CLI mode only
- **Status**: New feature

### 3. Configuration Tab in GUI
- **Description**: Add a new notebook tab for application configuration
- **Settings**: Download directory, temporary directory
- **Persistence**: Save to existing config.json
- **Status**: New feature

### 4. Fix GUI Navigation (Up Button)
- **Issue**: Up button navigation is inconsistent depending on current path
- **Goal**: Reliable directory navigation (parent directory)
- **Status**: Bug fix

### 5. GUI Window Resizing
- **Issue**: Windows don't resize properly when window dimensions change
- **Goal**: Dynamic layout adjustment on window resize
- **Status**: Bug fix

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
- `ls [path]` - List directory contents
- `cd <path>` - Change directory
- `pwd` - Print working directory
- `get <remote> [local]` - Download file
- `put <local> [remote]` - Upload file
- `mkdir <path>` - Create directory
- `rm <path>` - Remove file/directory
- `exit` or `quit` - Exit CLI

**1.3 Integration Points**
- Use existing `navigation` and `transfer_handler` classes
- Reuse authentication from `Authentification` class
- Shared configuration with GUI mode

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
    
    parser.add_argument(
        '--downdir',
        type=str,
        default=None,
        help='Download directory (overrides config)'
    )
    
    parser.add_argument(
        '--tmpdir',
        type=str,
        default=None,
        help='Temporary directory for processing'
    )
    
    return parser.parse_args()
```

#### Integration in App Class

```python
class App:
    def __init__(self, args=None):
        self.args = args or parse_arguments()
        self.__logger = logging.getLogger(__name__)
        self.__stop_event = Event()
        
        # Set download directory
        if self.args.downdir:
            download_path = pathlib.Path(self.args.downdir)
        else:
            download_path = self.config.get('download_dir', 
                                          pathlib.Path.home() / 'Downloads')
            
        # Set temp directory
        if self.args.tmpdir:
            temp_path = pathlib.Path(self.args.tmpdir)
        else:
            temp_path = pathlib.Path.home() / '.millegrilles' / 'tmp'
        
        self.auth = Authentification(self.__stop_event, 
                                    download_path=download_path,
                                    temp_path=temp_path)
        
        # Initialize components
        self.transfer_handler = TransferHandler(...)
        self.navigation = Navigation(...)
        
        # Choose mode
        if self.args.cli:
            self.run_cli_mode()
        else:
            self.run_gui_mode()
```

---

### Feature 3: Configuration Tab in GUI

#### UI Structure
Add a new notebook tab:
```
Notebook
├── Authentication (existing)
├── Navigation (existing)
├── Transfers (existing)
└── Configuration (new)
```

#### Configuration Tab Implementation

```python
# Add to Window class in __main__.py

self.__frame_config = ConfigurationFrame(
    self.auth, 
    master=self.__frame_notebook
)
self.__frame_notebook.add(self.__frame_config, text="Configuration")

# ConfigurationFrame class
class ConfigurationFrame(tk.Frame):
    def __init__(self, auth, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Download directory
        tk.Label(self, text="Download Directory:").grid(row=0, column=0)
        self.download_var = tk.StringVar(value=auth.download_path)
        tk.Entry(self, textvariable=self.download_var, width=50).grid(row=0, column=1)
        
        # Temp directory
        tk.Label(self, text="Temp Directory:").grid(row=1, column=0)
        self.temp_var = tk.StringVar(value=auth.temp_path)
        tk.Entry(self, textvariable=self.temp_var, width=50).grid(row=1, column=1)
        
        # Save button
        tk.Button(self, text="Save", 
                 command=self.save_config).grid(row=2, column=0, columnspan=2)
        
        # Load button
        tk.Button(self, text="Load", 
                 command=self.load_config).grid(row=3, column=0, columnspan=2)
```

#### Save/Load Configuration

```python
def save_config(self):
    config = {
        'download_dir': str(self.download_var.get()),
        'temp_dir': str(self.temp_var.get())
    }
    
    with open(self.auth.__path_config, 'w') as f:
        json.dump(config, f, indent=2)

def load_config(self):
    if self.auth.__path_config.exists():
        with open(self.auth.__path_config, 'r') as f:
            config = json.load(f)
            self.download_var.set(config.get('download_dir', str(pathlib.Path.home() / 'Downloads')))
            self.temp_var.set(config.get('temp_dir', str(pathlib.Path.home() / '.millegrilles' / 'tmp')))
```

---

### Feature 4: Fix GUI Navigation (Up Button)

#### Current Issue Analysis
The Up button (`btn_up_handler`) calls `navigation.naviguer_up()`. Looking at the current implementation, the issue seems to be in how the breadcrumb or directory state is updated after navigation.

#### Fix Strategy

**4.1 Review `naviguer_up` Method**
```python
# In Navigation.py

def naviguer_up(self):
    """Navigate to parent directory"""
    # Get current directory
    if self.__repertoire is None:
        return
        
    # Get parent directory
    parent = self.__repertoire.get_parent()
    
    if parent is None:
        # At root level
        return
    
    # Navigate to parent
    self.__charger_cuuid(parent['tuuid'])
    
    # Update breadcrumb
    if self.nav_frame:
        breadcrumb = parent.get('nom', 'Favoris')
        self.nav_frame.set_breadcrumb(breadcrumb)
```

**4.2 Fix Breadcrumb Update**
```python
# In NavigationFrame.py

def btn_up_handler(self):
    self.__navigation.naviguer_up()
    # Ensure breadcrumb updates after navigation
    self.refresh()  # Trigger refresh to update display
```

**4.3 Ensure Proper State Management**
```python
# Ensure all navigation changes update the UI
def changer_cuuid(self, cuuid):
    self.__charger_cuuid(cuuid)
    
    # Update UI
    if self.nav_frame:
        self.nav_frame.afficher_repertoire(self.__repertoire)
        # Update breadcrumb
        breadcrumb = pathlib.Path('Favoris') / self.__repertoire.nom
        self.nav_frame.set_breadcrumb(breadcrumb)
```

---

### Feature 5: GUI Window Resizing

#### Current Issue
The layout doesn't adapt when window size changes. This is likely due to fixed grid/pack configurations.

#### Fix Strategy

**5.1 Use Responsive Layout Managers**

```python
# In Window class
self.geometry("800x600")

# Add resize handler
self.bind('<Configure>', self.on_window_resize)

def on_window_resize(self, event):
    # Adjust layout based on new size
    if event.width < 800 or event.height < 600:
        # Reduce padding, adjust column weights
        self.__frame_notebook.grid_propagate(False)
        self.__frame_notebook.grid(
            row=1, column=0, 
            sticky='nsew',
            padx=5,
            pady=5
        )
```

**5.2 Use Grid Weight System**
```python
# In Window.__init__
self.grid_rowconfigure(1, weight=1)
self.grid_columnconfigure(0, weight=1)

# In each frame
self.__frame_notebook.grid(sticky='nsew')

# In NavigationFrame
self.__dir_frame.grid(sticky='nsew')
```

**5.3 Treeview Resize Handling**
```python
# In NavigationFrame.__init__
self.dirlist.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# In FileTransfer
self.__treeview_upload.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
```

**5.4 Notebook Resize Handler**
```python
class Window(tk.Tk):
    def __init__(self, ...):
        # ... existing code ...
        
        # Bind resize event
        self.bind('<Configure>', self.handle_resize)
    
    def handle_resize(self, event):
        # Adjust notebook padding based on size
        if event.width < 900:
            self.__frame_notebook.grid(padx=2, pady=2)
        else:
            self.__frame_notebook.grid(padx=5, pady=5)
```

---

## Implementation Order

### Phase 1: CLI Mode Foundation
1. Create `CLI.py` module with `CLIHandler` class
2. Implement basic CLI commands (ls, cd, pwd)
3. Add CLI mode entry point
4. Test CLI functionality

### Phase 2: Command-Line Arguments
1. Add argument parser to `__main__.py`
2. Implement `--downdir` and `--tmpdir`
3. Wire arguments to application initialization
4. Add CLI mode toggle (`--cli`)

### Phase 3: Configuration Tab
1. Create `ConfigurationFrame` class
2. Add save/load configuration functionality
3. Integrate into notebook
4. Test persistence

### Phase 4: GUI Navigation Fixes
1. Debug `naviguer_up()` implementation
2. Fix breadcrumb updates
3. Test navigation in various scenarios

### Phase 5: GUI Resizing
1. Implement responsive grid configurations
2. Add resize event handlers
3. Test with various window sizes
4. Verify all frames adjust properly

---

## Testing Plan

### CLI Mode
- [ ] List directory contents
- [ ] Navigate between directories
- [ ] Download files
- [ ] Upload files
- [ ] Handle permissions errors
- [ ] Exit cleanly

### Command-Line Arguments
- [ ] Test `--downdir` with valid path
- [ ] Test `--downdir` with invalid path
- [ ] Test `--tmpdir` configuration
- [ ] Test `--cli` flag disables GUI
- [ ] Test arguments override config file

### Configuration Tab
- [ ] Load saved configuration
- [ ] Save new configuration
- [ ] Test directory persistence across sessions
- [ ] Test invalid directory paths

### Navigation Fixes
- [ ] Navigate up from various directory depths
- [ ] Verify breadcrumb updates correctly
- [ ] Test at root level (no parent)
- [ ] Test error handling

### GUI Resizing
- [ ] Resize window vertically
- [ ] Resize window horizontally
- [ ] Minimize/maximize window
- [ ] Test all notebook tabs resize properly
- [ ] Verify treeview scrolling works correctly

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

## Next Steps

1. **Start with CLI mode** - Build incrementally, test each command
2. **Add command-line arguments** - Make app more flexible for automation
3. **Add configuration tab** - Improve user experience
4. **Fix navigation** - Improve usability
5. **Fix resizing** - Professional polish

---

## Notes

- All new code should follow existing project patterns
- Use existing logging infrastructure
- Maintain thread safety with stop_event pattern
- Keep GUI responsive with proper threading
- Document new methods/classes appropriately