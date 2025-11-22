#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import plistlib
import json
import base64
from pathlib import Path
from typing import Any, Dict, List, Union
import tempfile
import re


class UniversalPlistParser:
    
    def __init__(self, plist_path: str = None):
        self.plist_path = Path(plist_path) if plist_path else None
        self.data = None
        self.objects = []
        self.root_object = None
        self.plist_format = None
        self.is_nskeyedarchive = False
        
    def load(self, plist_path: str = None) -> bool:
        if plist_path:
            self.plist_path = Path(plist_path)
            
        try:
            with open(self.plist_path, 'rb') as f:
                self.data = plistlib.load(f)
            
            self._detect_format()
            
            if self.is_nskeyedarchive:
                self.objects = self.data.get('$objects', [])
                top = self.data.get('$top', {})
                if isinstance(top, dict) and 'root' in top:
                    root_ref = top['root']
                    if hasattr(root_ref, 'data'):
                        self.root_object = self._resolve_uid(root_ref.data)
                    else:
                        self.root_object = self._resolve_uid(root_ref)
                else:
                    self.root_object = self.data
            else:
                self.root_object = self.data
            
            return True
        except Exception as e:
            raise Exception(f"Error loading file: {e}")
    
    def _detect_format(self):
        if isinstance(self.data, dict) and '$archiver' in self.data:
            self.plist_format = 'nskeyedarchive'
            self.is_nskeyedarchive = True
        else:
            try:
                with open(self.plist_path, 'rb') as f:
                    header = f.read(16)
                    if header.startswith(b'bplist'):
                        self.plist_format = 'binary'
                    elif header.startswith(b'<?xml') or header.startswith(b'<plist'):
                        self.plist_format = 'xml'
                    else:
                        self.plist_format = 'unknown'
            except:
                self.plist_format = 'unknown'
    
    def _resolve_uid(self, uid: int) -> Any:
        if uid < len(self.objects):
            return self.objects[uid]
        return None
    
    def _parse_object(self, obj: Any, depth: int = 0, max_depth: int = 1000) -> Any:
        if depth > max_depth:
            return "... (max depth reached - possible circular reference)"
        
        if self.is_nskeyedarchive and hasattr(obj, 'data'):
            resolved = self._resolve_uid(obj.data)
            return self._parse_object(resolved, depth + 1, max_depth)
        
        if isinstance(obj, dict):
            if self.is_nskeyedarchive and '$class' in obj:
                result = {}
                for key, value in obj.items():
                    if key != '$class':
                        result[key] = self._parse_object(value, depth + 1, max_depth)
                return result
            else:
                return {k: self._parse_object(v, depth + 1, max_depth) 
                       for k, v in obj.items()}
        
        if isinstance(obj, list):
            return [self._parse_object(item, depth + 1, max_depth) for item in obj]
        
        return obj
    
    def get_structured_data(self) -> Dict:
        if self.root_object is None:
            return {'error': 'No root object found'}
        return self._parse_object(self.root_object)
    
    def get_info(self) -> Dict:
        if not self.data:
            return {}
        
        format_names = {
            'xml': 'XML Plist',
            'binary': 'Binary Plist',
            'nskeyedarchive': 'NSKeyedArchive',
            'unknown': 'Unknown'
        }
        
        info = {
            'filename': self.plist_path.name if self.plist_path else 'Unknown',
            'format': format_names.get(self.plist_format, 'Unknown')
        }
        
        if self.is_nskeyedarchive:
            info['archiver'] = self.data.get('$archiver', 'Unknown')
            info['version'] = self.data.get('$version', 'Unknown')
            info['object_count'] = len(self.objects)
        else:
            if isinstance(self.data, dict):
                info['root_type'] = 'Dictionary'
                info['object_count'] = len(self.data)
            elif isinstance(self.data, list):
                info['root_type'] = 'Array'
                info['object_count'] = len(self.data)
            else:
                info['root_type'] = type(self.data).__name__
                info['object_count'] = 1
        
        return info


class EmbeddedPlistDetector:
    
    @staticmethod
    def is_plist_data(data: bytes) -> bool:
        if not data or len(data) < 8:
            return False
        
        if data.startswith(b'bplist'):
            return True
        
        if data.startswith(b'<?xml') or data.startswith(b'<plist'):
            return True
        
        try:
            parsed = plistlib.loads(data)
            if isinstance(parsed, dict) and '$archiver' in parsed:
                return True
        except:
            pass
        
        return False
    
    @staticmethod
    def try_base64_decode(text: str) -> bytes:
        try:
            text = re.sub(r'\s+', '', text)
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', text) and len(text) % 4 == 0:
                return base64.b64decode(text)
        except:
            pass
        return None
    
    @staticmethod
    def detect_in_value(value: Any) -> tuple:
        if isinstance(value, bytes):
            if EmbeddedPlistDetector.is_plist_data(value):
                return (True, value, 'binary')
        
        elif isinstance(value, str):
            if len(value) > 100:
                decoded = EmbeddedPlistDetector.try_base64_decode(value)
                if decoded and EmbeddedPlistDetector.is_plist_data(decoded):
                    return (True, decoded, 'base64')
        
        return (False, None, None)


class PlistParserGUI:
    
    def __init__(self, root):
        self.root = root
        self.root.title("Universal Plist Parser - Forensic Edition")
        self.root.geometry("1400x900")
        
        self.parser = UniversalPlistParser()
        self.current_file = None
        self.embedded_plist_cache = {}
        self.bytes_cache = {}
        self.cached_data = None
        self.views_loaded = {'tree': False, 'json': False, 'raw': False}
        
        self.setup_ui()
        self.setup_menu()
        
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open...", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Export as JSON...", command=self.export_json)
        file_menu.add_command(label="Export as Text...", command=self.export_text)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")
        
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Tree View", command=lambda: self.switch_view('tree'))
        view_menu.add_command(label="JSON View", command=lambda: self.switch_view('json'))
        view_menu.add_command(label="Raw View", command=lambda: self.switch_view('raw'))
        view_menu.add_separator()
        view_menu.add_command(label="Expand All", command=self.expand_all)
        view_menu.add_command(label="Collapse All", command=self.collapse_all)
        
        forensic_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Forensics", menu=forensic_menu)
        forensic_menu.add_command(label="Scan for Embedded Plists", command=self.scan_for_embedded_plists)
        forensic_menu.add_command(label="Show Statistics", command=self.show_statistics)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<Control-e>', lambda e: self.expand_all())
        self.root.bind('<Control-r>', lambda e: self.collapse_all())
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        header_frame = ttk.LabelFrame(main_frame, text="File Information", padding="10")
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        info_grid = ttk.Frame(header_frame)
        info_grid.pack(fill=tk.X)
        
        ttk.Label(info_grid, text="File:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.file_label = ttk.Label(info_grid, text="-", foreground='blue')
        self.file_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(info_grid, text="Format:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=2, sticky=tk.W, padx=20)
        self.format_label = ttk.Label(info_grid, text="-")
        self.format_label.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(info_grid, text="Objects:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=4, sticky=tk.W, padx=20)
        self.count_label = ttk.Label(info_grid, text="-")
        self.count_label.grid(row=0, column=5, sticky=tk.W, padx=5)
        
        ttk.Label(info_grid, text="Embedded Plists:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=6, sticky=tk.W, padx=20)
        self.embedded_label = ttk.Label(info_grid, text="-", foreground='red')
        self.embedded_label.grid(row=0, column=7, sticky=tk.W, padx=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(button_frame, text="Open File", command=self.open_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Scan for Embedded Plists", command=self.scan_for_embedded_plists).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Expand All", command=self.expand_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Collapse All", command=self.collapse_all).pack(side=tk.LEFT, padx=5)
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_changed)
        
        tree_frame = ttk.Frame(self.notebook)
        self.notebook.add(tree_frame, text="🌳 Tree View")
        
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        
        self.tree_view = ttk.Treeview(
            tree_frame,
            columns=('value', 'type', 'size', 'embedded'),
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set
        )
        
        tree_scroll_y.config(command=self.tree_view.yview)
        tree_scroll_x.config(command=self.tree_view.xview)
        
        self.tree_view.heading('#0', text='Key / Path')
        self.tree_view.heading('value', text='Value')
        self.tree_view.heading('type', text='Type')
        self.tree_view.heading('size', text='Size')
        self.tree_view.heading('embedded', text='Embedded')
        
        self.tree_view.column('#0', width=300, minwidth=200)
        self.tree_view.column('value', width=600, minwidth=300)
        self.tree_view.column('type', width=100, minwidth=80)
        self.tree_view.column('size', width=100, minwidth=60)
        self.tree_view.column('embedded', width=100, minwidth=80)
        
        self.tree_view.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        tree_scroll_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        self.tree_context_menu = tk.Menu(self.tree_view, tearoff=0)
        self.tree_context_menu.add_command(label="Copy Value", command=self.copy_value)
        self.tree_context_menu.add_command(label="Copy Path", command=self.copy_path)
        self.tree_context_menu.add_separator()
        self.tree_context_menu.add_command(label="Show Hex Viewer", command=self.show_hex_viewer)
        self.tree_context_menu.add_command(label="Open Embedded Plist", command=self.open_embedded_plist)
        
        self.tree_view.bind('<Button-3>', self.show_context_menu)
        self.tree_view.bind('<Double-Button-1>', self.on_double_click)
        
        json_frame = ttk.Frame(self.notebook)
        self.notebook.add(json_frame, text="📄 JSON View")
        
        self.json_text = scrolledtext.ScrolledText(json_frame, wrap=tk.NONE, font=('Courier', 10))
        self.json_text.pack(fill=tk.BOTH, expand=True)
        
        raw_frame = ttk.Frame(self.notebook)
        self.notebook.add(raw_frame, text="📝 Text View")
        
        self.raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.NONE, font=('Courier', 10))
        self.raw_text.pack(fill=tk.BOTH, expand=True)
        
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.status_bar = ttk.Label(status_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        self.view_var = tk.StringVar(value='tree')
        
    def open_file(self):
        filename = filedialog.askopenfilename(
            title="Open Plist File",
            filetypes=[
                ("Plist Files", "*.plist"),
                ("All Files", "*.*")
            ]
        )
        
        if filename:
            try:
                self.status_bar.config(text=f"Loading {Path(filename).name}...")
                self.root.update()
                
                self.current_file = filename
                self.parser.load(filename)
                
                info = self.parser.get_info()
                self.file_label.config(text=info.get('filename', '-'))
                self.format_label.config(text=info.get('format', '-'))
                self.count_label.config(text=str(info.get('object_count', '-')))
                
                self.embedded_plist_cache.clear()
                self.bytes_cache.clear()
                self.embedded_label.config(text="Not scanned yet")
                
                self.display_data()
                
                self.status_bar.config(text=f"Loaded: {Path(filename).name}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error opening file:\n{str(e)}")
                self.status_bar.config(text="Error loading")
    
    def display_data(self):
        try:
            self.cached_data = self.parser.get_structured_data()
            self.views_loaded = {'tree': False, 'json': False, 'raw': False}
            
            self.update_treeview(self.cached_data)
            self.views_loaded['tree'] = True
            
        except Exception as e:
            messagebox.showerror("Error", f"Error displaying data:\n{str(e)}")
    
    def on_tab_changed(self, event):
        if not self.cached_data:
            return
        
        selected_tab = self.notebook.index(self.notebook.select())
        
        if selected_tab == 1 and not self.views_loaded['json']:
            self.status_bar.config(text="Loading JSON view...")
            self.root.update_idletasks()
            self.update_json(self.cached_data)
            self.views_loaded['json'] = True
            self.status_bar.config(text="Ready")
        elif selected_tab == 2 and not self.views_loaded['raw']:
            self.status_bar.config(text="Loading text view...")
            self.root.update_idletasks()
            self.update_raw_text(self.cached_data)
            self.views_loaded['raw'] = True
            self.status_bar.config(text="Ready")
    
    def update_treeview(self, data):
        self.tree_view.configure(selectmode='none')
        
        for item in self.tree_view.get_children():
            self.tree_view.delete(item)
        
        self.embedded_plist_cache.clear()
        self.bytes_cache.clear()
        
        self._add_tree_items('', data, '', 0)
        
        self.tree_view.configure(selectmode='browse')
        
    def _add_tree_items(self, parent, obj, key=None, depth=0):
        has_embedded, plist_data, detection_type = EmbeddedPlistDetector.detect_in_value(obj)
        embedded_indicator = f"📋 {detection_type}" if has_embedded else ""
        
        if isinstance(obj, dict):
            if key is not None:
                size_info = f"{len(obj)} keys"
                node = self.tree_view.insert(
                    parent, 'end',
                    text=key,
                    values=('', 'dict', size_info, embedded_indicator),
                    open=True if depth < 3 else False
                )
            else:
                node = parent
            
            for k, v in obj.items():
                self._add_tree_items(node if node else parent, v, k, depth + 1)
        
        elif isinstance(obj, list):
            if key is not None:
                size_info = f"{len(obj)} items"
                node = self.tree_view.insert(
                    parent, 'end',
                    text=key,
                    values=('', 'list', size_info, embedded_indicator),
                    open=True if depth < 3 else False
                )
            else:
                node = parent
            
            for i, item in enumerate(obj):
                self._add_tree_items(node if node else parent, item, f'[{i}]', depth + 1)
        
        else:
            value_str = self._format_value(obj)
            type_str = type(obj).__name__
            
            size_str = ""
            if isinstance(obj, bytes):
                size_str = f"{len(obj)} bytes"
            elif isinstance(obj, str):
                size_str = f"{len(obj)} chars"
            
            if key is not None:
                item_id = self.tree_view.insert(
                    parent, 'end',
                    text=key,
                    values=(value_str, type_str, size_str, embedded_indicator)
                )
                
                if has_embedded:
                    self.embedded_plist_cache[item_id] = plist_data
                
                self.bytes_cache[item_id] = obj
    
    def _format_value(self, value):
        if isinstance(value, bytes):
            max_preview = 32
            if len(value) > max_preview:
                preview = value[:max_preview].hex() + "..."
            else:
                preview = value.hex() if len(value) > 0 else ""
            return f"<bytes: {len(value)} bytes> {preview}"
        elif isinstance(value, str):
            max_length = 200
            if len(value) > max_length:
                return value[:max_length] + "..."
            return value
        elif isinstance(value, bool):
            return str(value)
        elif isinstance(value, (int, float)):
            return str(value)
        elif value is None:
            return "null"
        else:
            return str(value)
    
    def update_json(self, data):
        self.json_text.delete(1.0, tk.END)
        
        def convert_bytes(obj):
            if isinstance(obj, bytes):
                try:
                    return obj.decode('utf-8')
                except:
                    max_hex = 64
                    if len(obj) > max_hex:
                        return f"<bytes: {len(obj)} bytes, hex: {obj[:max_hex].hex()}...>"
                    return f"<bytes: {obj.hex()}>"
            elif isinstance(obj, dict):
                return {k: convert_bytes(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_bytes(item) for item in obj]
            return obj
        
        data = convert_bytes(data)
        json_str = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        self.json_text.insert(1.0, json_str)
    
    def update_raw_text(self, data):
        self.raw_text.delete(1.0, tk.END)
        
        output = []
        self._format_tree_text(data, output)
        self.raw_text.insert(1.0, '\n'.join(output))
    
    def _format_tree_text(self, obj, output, indent=0, key=None, max_depth=1000):
        if indent > max_depth:
            output.append("  " * indent + "... (max depth)")
            return
        
        indent_str = "  " * indent
        
        if key is not None:
            key_str = f"{key}: "
        else:
            key_str = ""
        
        if isinstance(obj, dict):
            if key is not None:
                output.append(f"{indent_str}├─ {key_str}{{dict: {len(obj)} keys}}")
                indent += 1
                indent_str = "  " * indent
            
            for k, v in obj.items():
                self._format_tree_text(v, output, indent, k, max_depth)
        
        elif isinstance(obj, list):
            if key is not None:
                output.append(f"{indent_str}├─ {key_str}[list: {len(obj)} items]")
                indent += 1
                indent_str = "  " * indent
            
            for i, item in enumerate(obj):
                self._format_tree_text(item, output, indent, f"[{i}]", max_depth)
        
        else:
            value_display = self._format_value(obj)
            output.append(f"{indent_str}├─ {key_str}{value_display}")
    
    def scan_for_embedded_plists(self):
        if not self.parser.data:
            messagebox.showwarning("Warning", "No data loaded.")
            return
        
        self.status_bar.config(text="Scanning for embedded plists...")
        self.root.update()
        
        count = 0
        data = self.parser.get_structured_data()
        
        def scan_recursive(obj):
            nonlocal count
            has_embedded, _, _ = EmbeddedPlistDetector.detect_in_value(obj)
            if has_embedded:
                count += 1
            
            if isinstance(obj, dict):
                for v in obj.values():
                    scan_recursive(v)
            elif isinstance(obj, list):
                for item in obj:
                    scan_recursive(item)
        
        scan_recursive(data)
        
        self.embedded_label.config(text=str(count) if count > 0 else "None found")
        
        if count > 0:
            self.embedded_label.config(foreground='red')
            messagebox.showinfo("Result", f"✅ {count} embedded plist(s) found!\n\nDouble-click on an entry with 📋 symbol to open.")
        else:
            self.embedded_label.config(foreground='green')
            messagebox.showinfo("Result", "No embedded plists found.")
        
        self.status_bar.config(text=f"Scan complete: {count} embedded plist(s)")
    
    def show_context_menu(self, event):
        try:
            item = self.tree_view.identify_row(event.y)
            if item:
                self.tree_view.selection_set(item)
                self.tree_context_menu.post(event.x_root, event.y_root)
        except:
            pass
    
    def on_double_click(self, event):
        selection = self.tree_view.selection()
        if selection:
            item = selection[0]
            if item in self.embedded_plist_cache:
                self.open_embedded_plist()
            elif item in self.bytes_cache:
                self.show_hex_viewer()
    
    def open_embedded_plist(self):
        selection = self.tree_view.selection()
        if not selection:
            return
        
        item = selection[0]
        if item not in self.embedded_plist_cache:
            messagebox.showwarning("Warning", "No embedded plist found in this item.")
            return
        
        try:
            plist_data = self.embedded_plist_cache[item]
            
            with tempfile.NamedTemporaryFile(suffix='.plist', delete=False) as tmp:
                tmp.write(plist_data)
                tmp_path = tmp.name
            
            new_window = tk.Toplevel(self.root)
            new_app = PlistParserGUI(new_window)
            new_app.parser.load(tmp_path)
            new_app.display_data()
            
            item_text = self.tree_view.item(item, 'text')
            new_window.title(f"Embedded Plist: {item_text}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error opening embedded plist:\n{str(e)}")
    
    def show_hex_viewer(self):
        selection = self.tree_view.selection()
        if not selection:
            return
        
        item = selection[0]
        if item not in self.bytes_cache:
            messagebox.showwarning("Warning", "No data found in this item.")
            return
        
        try:
            data = self.bytes_cache[item]
            item_text = self.tree_view.item(item, 'text')
            
            if isinstance(data, bytes):
                bytes_data = data
                data_type = "bytes"
            elif isinstance(data, str):
                bytes_data = data.encode('utf-8')
                data_type = "string (UTF-8)"
            elif isinstance(data, bool):
                bytes_data = str(data).encode('utf-8')
                data_type = "boolean"
            elif isinstance(data, int):
                bytes_data = data.to_bytes((data.bit_length() + 7) // 8 or 1, byteorder='big', signed=True)
                data_type = "integer"
            elif isinstance(data, float):
                import struct
                bytes_data = struct.pack('d', data)
                data_type = "float (double)"
            elif data is None:
                bytes_data = b'null'
                data_type = "null"
            else:
                bytes_data = str(data).encode('utf-8')
                data_type = type(data).__name__
            
            hex_window = tk.Toplevel(self.root)
            hex_window.title(f"Hex Viewer: {item_text}")
            hex_window.geometry("900x600")
            
            frame = ttk.Frame(hex_window, padding="10")
            frame.pack(fill=tk.BOTH, expand=True)
            
            info_frame = ttk.Frame(frame)
            info_frame.pack(fill=tk.X, pady=(0, 10))
            
            ttk.Label(info_frame, text=f"Key: {item_text}", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"Type: {data_type}", font=('TkDefaultFont', 9)).pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"Size: {len(bytes_data)} bytes", font=('TkDefaultFont', 9)).pack(anchor=tk.W)
            if data_type != "bytes":
                ttk.Label(info_frame, text=f"Original Value: {str(data)[:100]}", font=('TkDefaultFont', 9)).pack(anchor=tk.W)
            
            hex_text = scrolledtext.ScrolledText(frame, wrap=tk.NONE, font=('Courier', 10))
            hex_text.pack(fill=tk.BOTH, expand=True)
            
            hex_output = []
            bytes_per_line = 16
            for offset in range(0, len(bytes_data), bytes_per_line):
                chunk = bytes_data[offset:offset+bytes_per_line]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                hex_output.append(f"{offset:08x}  {hex_part}  {ascii_part}")
            
            hex_text.insert(1.0, "\n".join(hex_output))
            hex_text.config(state=tk.DISABLED)
            
            button_frame = ttk.Frame(frame)
            button_frame.pack(fill=tk.X, pady=(10, 0))
            
            def copy_hex():
                hex_window.clipboard_clear()
                hex_window.clipboard_append(bytes_data.hex())
                messagebox.showinfo("Copied", "Hex data copied to clipboard")
            
            def copy_raw():
                hex_window.clipboard_clear()
                hex_window.clipboard_append(bytes_data)
                messagebox.showinfo("Copied", "Raw bytes copied to clipboard")
            
            ttk.Button(button_frame, text="Copy Hex", command=copy_hex).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Copy Raw", command=copy_raw).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Close", command=hex_window.destroy).pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error opening hex viewer:\n{str(e)}")
    
    def copy_value(self):
        selection = self.tree_view.selection()
        if selection:
            item = selection[0]
            value = self.tree_view.item(item, 'values')[0]
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.status_bar.config(text="Value copied to clipboard")
    
    def copy_path(self):
        selection = self.tree_view.selection()
        if selection:
            item = selection[0]
            path_parts = []
            
            while item:
                text = self.tree_view.item(item, 'text')
                if text:
                    path_parts.insert(0, text)
                item = self.tree_view.parent(item)
            
            path = " → ".join(path_parts)
            self.root.clipboard_clear()
            self.root.clipboard_append(path)
            self.status_bar.config(text="Path copied to clipboard")
    
    def expand_all(self):
        def expand_item(item):
            self.tree_view.item(item, open=True)
            for child in self.tree_view.get_children(item):
                expand_item(child)
        
        for item in self.tree_view.get_children():
            expand_item(item)
        
        self.status_bar.config(text="All nodes expanded")
    
    def collapse_all(self):
        def collapse_item(item):
            self.tree_view.item(item, open=False)
            for child in self.tree_view.get_children(item):
                collapse_item(child)
        
        for item in self.tree_view.get_children():
            collapse_item(item)
        
        self.status_bar.config(text="All nodes collapsed")
    
    def show_statistics(self):
        if not self.parser.data:
            messagebox.showwarning("Warning", "No data loaded.")
            return
        
        data = self.parser.get_structured_data()
        
        stats = {
            'dicts': 0,
            'lists': 0,
            'strings': 0,
            'numbers': 0,
            'bytes': 0,
            'bools': 0,
            'nulls': 0,
            'max_depth': 0,
            'total_string_length': 0,
            'total_bytes_length': 0
        }
        
        def analyze_recursive(obj, depth=0):
            stats['max_depth'] = max(stats['max_depth'], depth)
            
            if isinstance(obj, dict):
                stats['dicts'] += 1
                for v in obj.values():
                    analyze_recursive(v, depth + 1)
            elif isinstance(obj, list):
                stats['lists'] += 1
                for item in obj:
                    analyze_recursive(item, depth + 1)
            elif isinstance(obj, str):
                stats['strings'] += 1
                stats['total_string_length'] += len(obj)
            elif isinstance(obj, bytes):
                stats['bytes'] += 1
                stats['total_bytes_length'] += len(obj)
            elif isinstance(obj, bool):
                stats['bools'] += 1
            elif isinstance(obj, (int, float)):
                stats['numbers'] += 1
            elif obj is None:
                stats['nulls'] += 1
        
        analyze_recursive(data)
        
        msg = "📊 Plist Statistics:\n\n"
        msg += f"Dictionaries: {stats['dicts']}\n"
        msg += f"Lists: {stats['lists']}\n"
        msg += f"Strings: {stats['strings']} (Total length: {stats['total_string_length']} chars)\n"
        msg += f"Numbers: {stats['numbers']}\n"
        msg += f"Binary data: {stats['bytes']} (Total size: {stats['total_bytes_length']} bytes)\n"
        msg += f"Booleans: {stats['bools']}\n"
        msg += f"Null values: {stats['nulls']}\n"
        msg += f"\nMaximum nesting depth: {stats['max_depth']}\n"
        
        messagebox.showinfo("Statistics", msg)
    
    def switch_view(self, view_type):
        self.view_var.set(view_type)
        if view_type == 'tree':
            self.notebook.select(0)
        elif view_type == 'json':
            self.notebook.select(1)
        elif view_type == 'raw':
            self.notebook.select(2)
    
    def export_json(self):
        if not self.parser.data:
            messagebox.showwarning("Warning", "No data to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if filename:
            try:
                data = self.parser.get_structured_data()
                
                def convert_bytes(obj):
                    if isinstance(obj, bytes):
                        try:
                            return obj.decode('utf-8')
                        except:
                            return f"<bytes: {obj.hex()}>"
                    elif isinstance(obj, dict):
                        return {k: convert_bytes(v) for k, v in obj.items()}
                    elif isinstance(obj, list):
                        return [convert_bytes(item) for item in obj]
                    return obj
                
                data = convert_bytes(data)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False, default=str)
                
                self.status_bar.config(text=f"JSON exported: {Path(filename).name}")
                messagebox.showinfo("Success", "JSON successfully exported!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error exporting:\n{str(e)}")
    
    def export_text(self):
        if not self.parser.data:
            messagebox.showwarning("Warning", "No data to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export Text",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if filename:
            try:
                data = self.parser.get_structured_data()
                output = []
                self._format_tree_text(data, output)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(output))
                
                self.status_bar.config(text=f"Text exported: {Path(filename).name}")
                messagebox.showinfo("Success", "Text successfully exported!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error exporting:\n{str(e)}")
    
    def show_about(self):
        messagebox.showinfo(
            "About Universal Plist Parser - Forensic Edition",
            "Universal Plist Parser v2.1 - Forensic Edition\n\n"
            "A tool for parsing and viewing Plist files\n"
            "specifically designed for forensic analysis.\n\n"
            "Features:\n"
            "• Supports all Plist formats (XML, Binary, NSKeyedArchive)\n"
            "• Unlimited nesting depth\n"
            "• Embedded plist detection\n"
            "• Complete display of all elements\n"
            "• Statistics and analysis tools\n\n"
            "Created with Python and tkinter"
        )


def main():
    root = tk.Tk()
    app = PlistParserGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()