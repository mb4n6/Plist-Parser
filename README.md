# Universal Plist Parser -- Forensic GUI

A standalone Plist viewer with a graphical interface built using **tkinter**.\
Designed for forensic analysis, reverse engineering, and debugging of Apple Property List files --- supporting all formats without depth limitations.

------------------------------------------------------------------------

## Authors

Marc Brandt\
Hochschule für Polizei Baden-Württemberg

------------------------------------------------------------------------

## Features

**Load any Plist format**: XML, Binary, and NSKeyedArchive\
**Unlimited nesting depth** for complete forensic analysis\
**Embedded Plist detection** in binary data and Base64-encoded strings\
**Multiple views**: Tree, JSON, and raw text output\
**Deep inspection**: Size info, type info, and hex preview for binary data\
**One-click opening** of embedded Plists in new windows\
**Statistics & analysis** tools for structure overview\
**Export functions**: JSON and text export\
**Context menu**: Copy values, copy paths, open embedded Plists\
**Keyboard shortcuts**: Expand/collapse all nodes (Ctrl+E / Ctrl+R)\
Cross-platform: macOS, Linux, Windows

------------------------------------------------------------------------

## Installation

``` bash
# No additional dependencies required - uses built-in tkinter
python3 plist_parser_gui_forensic.py
```

------------------------------------------------------------------------

## Usage

``` bash
python3 plist_parser_gui_forensic.py
```

1.  Click **Open File...** to load a `.plist` file\
2.  Inspect:
    -   Keys and values at any depth
    -   Data types and sizes
    -   Embedded Plists (marked with 📋 symbol)
    -   Full hex representation of binary data
3.  **Double-click** on items with 📋 to open embedded Plists\
4.  Use **Forensik → Scan for embedded Plists** to scan for all embedded Plists\
5.  Export to JSON or text for further analysis

------------------------------------------------------------------------

## Forensic Features

**Embedded Plist Detection**: Automatically identifies Plists hidden in binary fields or Base64-encoded strings\
**Unlimited Depth**: No truncation of nested structures (up to depth 1000)\
**Complete Display**: Every element is shown, including deeply nested strings\
**Statistics View**: Total element counts, maximum nesting depth, data sizes\
**Path Tracking**: Right-click any element to copy its full path for documentation

------------------------------------------------------------------------

## License

MIT License.
