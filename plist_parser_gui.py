#!/usr/bin/env python3
"""
Universal Plist Parser - Forensic GUI Version
Grafische Benutzeroberfläche zum Parsen und Anzeigen von Plist-Dateien
Speziell für forensische Analysen mit vollständiger Tiefe und eingebetteten Plists
Unterstützt: XML, Binary und NSKeyedArchive Formate
"""

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
    """Parser für alle Plist-Formate (XML, Binary, NSKeyedArchive)"""
    
    def __init__(self, plist_path: str = None):
        self.plist_path = Path(plist_path) if plist_path else None
        self.data = None
        self.objects = []
        self.root_object = None
        self.plist_format = None  # 'xml', 'binary', or 'nskeyedarchive'
        self.is_nskeyedarchive = False
        
    def load(self, plist_path: str = None) -> bool:
        """Lädt die Plist-Datei (XML, Binary oder NSKeyedArchive)"""
        if plist_path:
            self.plist_path = Path(plist_path)
            
        try:
            with open(self.plist_path, 'rb') as f:
                self.data = plistlib.load(f)
            
            # Erkenne Plist-Format
            self._detect_format()
            
            # Für NSKeyedArchive: Extrahiere spezielle Struktur
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
                # Für normale Plists ist die Daten-Struktur direkt verwendbar
                self.root_object = self.data
            
            return True
        except Exception as e:
            raise Exception(f"Fehler beim Laden der Datei: {e}")
    
    def _detect_format(self):
        """Erkennt das Plist-Format"""
        # NSKeyedArchive erkennen
        if isinstance(self.data, dict) and '$archiver' in self.data:
            self.plist_format = 'nskeyedarchive'
            self.is_nskeyedarchive = True
        else:
            # Prüfe Datei-Header für XML vs Binary
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
        """Löst eine UID-Referenz auf"""
        if uid < len(self.objects):
            return self.objects[uid]
        return None
    
    def _parse_object(self, obj: Any, depth: int = 0, max_depth: int = 1000) -> Any:
        """Parst ein Objekt rekursiv - UNBEGRENZTE TIEFE für forensische Analyse"""
        if depth > max_depth:
            return "... (max depth reached - possible circular reference)"
        
        # Handle UID-Referenzen (nur für NSKeyedArchive)
        if self.is_nskeyedarchive and hasattr(obj, 'data'):
            resolved = self._resolve_uid(obj.data)
            return self._parse_object(resolved, depth + 1, max_depth)
        
        if isinstance(obj, dict):
            # NSKeyedArchive Objekt mit $class
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
        """Gibt die strukturierten Daten zurück"""
        if self.root_object is None:
            return {'error': 'Kein Root-Objekt gefunden'}
        return self._parse_object(self.root_object)
    
    def get_info(self) -> Dict:
        """Gibt Informationen über die Plist zurück"""
        if not self.data:
            return {}
        
        format_names = {
            'xml': 'XML Plist',
            'binary': 'Binary Plist',
            'nskeyedarchive': 'NSKeyedArchive',
            'unknown': 'Unbekannt'
        }
        
        info = {
            'filename': self.plist_path.name if self.plist_path else 'Unbekannt',
            'format': format_names.get(self.plist_format, 'Unbekannt')
        }
        
        if self.is_nskeyedarchive:
            info['archiver'] = self.data.get('$archiver', 'Unbekannt')
            info['version'] = self.data.get('$version', 'Unbekannt')
            info['object_count'] = len(self.objects)
        else:
            # Für normale Plists
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
    """Erkennt eingebettete Plists in Daten"""
    
    @staticmethod
    def is_plist_data(data: bytes) -> bool:
        """Prüft ob Binärdaten eine Plist enthalten"""
        if not data or len(data) < 8:
            return False
        
        # Binary Plist
        if data.startswith(b'bplist'):
            return True
        
        # XML Plist
        if data.startswith(b'<?xml') or data.startswith(b'<plist'):
            return True
        
        # Versuche es als NSKeyedArchive zu parsen
        try:
            parsed = plistlib.loads(data)
            if isinstance(parsed, dict) and '$archiver' in parsed:
                return True
        except:
            pass
        
        return False
    
    @staticmethod
    def try_base64_decode(text: str) -> bytes:
        """Versucht Base64-Dekodierung"""
        try:
            # Entferne Whitespace
            text = re.sub(r'\s+', '', text)
            # Prüfe ob es wie Base64 aussieht
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', text) and len(text) % 4 == 0:
                return base64.b64decode(text)
        except:
            pass
        return None
    
    @staticmethod
    def detect_in_value(value: Any) -> tuple:
        """
        Erkennt eingebettete Plists in einem Wert
        Gibt zurück: (has_plist, plist_data, detection_type)
        """
        # Direkte Binärdaten
        if isinstance(value, bytes):
            if EmbeddedPlistDetector.is_plist_data(value):
                return (True, value, 'binary')
        
        # String - könnte Base64-kodiert sein
        elif isinstance(value, str):
            if len(value) > 100:  # Nur längere Strings prüfen
                decoded = EmbeddedPlistDetector.try_base64_decode(value)
                if decoded and EmbeddedPlistDetector.is_plist_data(decoded):
                    return (True, decoded, 'base64')
        
        return (False, None, None)


class PlistParserGUI:
    """Grafische Benutzeroberfläche für den Plist-Parser - Forensic Edition"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Universal Plist Parser - Forensic Edition")
        self.root.geometry("1400x900")
        
        self.parser = UniversalPlistParser()
        self.current_file = None
        self.embedded_plist_cache = {}  # Cache für erkannte eingebettete Plists
        
        self.setup_ui()
        self.setup_menu()
        
    def setup_menu(self):
        """Erstellt die Menüleiste"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Datei-Menü
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Datei", menu=file_menu)
        file_menu.add_command(label="Öffnen...", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Als JSON exportieren...", command=self.export_json)
        file_menu.add_command(label="Als Text exportieren...", command=self.export_text)
        file_menu.add_separator()
        file_menu.add_command(label="Beenden", command=self.root.quit, accelerator="Ctrl+Q")
        
        # Ansicht-Menü
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ansicht", menu=view_menu)
        view_menu.add_command(label="Baum-Ansicht", command=lambda: self.switch_view('tree'))
        view_menu.add_command(label="JSON-Ansicht", command=lambda: self.switch_view('json'))
        view_menu.add_command(label="Raw-Ansicht", command=lambda: self.switch_view('raw'))
        view_menu.add_separator()
        view_menu.add_command(label="Alle Knoten erweitern", command=self.expand_all)
        view_menu.add_command(label="Alle Knoten reduzieren", command=self.collapse_all)
        
        # Forensik-Menü
        forensic_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Forensik", menu=forensic_menu)
        forensic_menu.add_command(label="Eingebettete Plists suchen", command=self.scan_for_embedded_plists)
        forensic_menu.add_command(label="Statistiken anzeigen", command=self.show_statistics)
        
        # Hilfe-Menü
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Hilfe", menu=help_menu)
        help_menu.add_command(label="Über", command=self.show_about)
        
        # Tastenkombinationen
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<Control-e>', lambda e: self.expand_all())
        self.root.bind('<Control-r>', lambda e: self.collapse_all())
        
    def setup_ui(self):
        """Erstellt die Benutzeroberfläche"""
        # Hauptcontainer
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Header mit Dateiinformationen
        header_frame = ttk.LabelFrame(main_frame, text="Datei-Information", padding="10")
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Info-Grid
        info_grid = ttk.Frame(header_frame)
        info_grid.pack(fill=tk.X)
        
        # Dateiname
        ttk.Label(info_grid, text="Datei:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.file_label = ttk.Label(info_grid, text="-", foreground='blue')
        self.file_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Format
        ttk.Label(info_grid, text="Format:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=2, sticky=tk.W, padx=20)
        self.format_label = ttk.Label(info_grid, text="-")
        self.format_label.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Objekt-Anzahl
        ttk.Label(info_grid, text="Objekte:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=4, sticky=tk.W, padx=20)
        self.count_label = ttk.Label(info_grid, text="-")
        self.count_label.grid(row=0, column=5, sticky=tk.W, padx=5)
        
        # Embedded Plists
        ttk.Label(info_grid, text="Eingebettete Plists:", font=('TkDefaultFont', 9, 'bold')).grid(row=0, column=6, sticky=tk.W, padx=20)
        self.embedded_label = ttk.Label(info_grid, text="-", foreground='red')
        self.embedded_label.grid(row=0, column=7, sticky=tk.W, padx=5)
        
        # Button-Leiste
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(button_frame, text="Datei öffnen", command=self.open_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Eingebettete Plists suchen", command=self.scan_for_embedded_plists).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Alle erweitern", command=self.expand_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Alle reduzieren", command=self.collapse_all).pack(side=tk.LEFT, padx=5)
        
        # Notebook für verschiedene Ansichten
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Tab 1: Tree View
        tree_frame = ttk.Frame(self.notebook)
        self.notebook.add(tree_frame, text="🌳 Baum-Ansicht")
        
        # Scrollbars für Tree View
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        
        # TreeView mit erweiterter Darstellung
        self.tree_view = ttk.Treeview(
            tree_frame,
            columns=('value', 'type', 'size', 'embedded'),
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set
        )
        
        tree_scroll_y.config(command=self.tree_view.yview)
        tree_scroll_x.config(command=self.tree_view.xview)
        
        # Spalten konfigurieren
        self.tree_view.heading('#0', text='Schlüssel / Pfad')
        self.tree_view.heading('value', text='Wert')
        self.tree_view.heading('type', text='Typ')
        self.tree_view.heading('size', text='Größe')
        self.tree_view.heading('embedded', text='Eingebettet')
        
        self.tree_view.column('#0', width=300, minwidth=200)
        self.tree_view.column('value', width=400, minwidth=200)
        self.tree_view.column('type', width=100, minwidth=80)
        self.tree_view.column('size', width=80, minwidth=60)
        self.tree_view.column('embedded', width=100, minwidth=80)
        
        # Layout
        self.tree_view.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        tree_scroll_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Context-Menü für TreeView
        self.tree_context_menu = tk.Menu(self.tree_view, tearoff=0)
        self.tree_context_menu.add_command(label="Wert kopieren", command=self.copy_value)
        self.tree_context_menu.add_command(label="Pfad kopieren", command=self.copy_path)
        self.tree_context_menu.add_separator()
        self.tree_context_menu.add_command(label="Eingebettete Plist öffnen", command=self.open_embedded_plist)
        
        self.tree_view.bind('<Button-3>', self.show_context_menu)
        self.tree_view.bind('<Double-Button-1>', self.on_double_click)
        
        # Tab 2: JSON View
        json_frame = ttk.Frame(self.notebook)
        self.notebook.add(json_frame, text="📄 JSON-Ansicht")
        
        self.json_text = scrolledtext.ScrolledText(json_frame, wrap=tk.NONE, font=('Courier', 10))
        self.json_text.pack(fill=tk.BOTH, expand=True)
        
        # Tab 3: Raw Text View
        raw_frame = ttk.Frame(self.notebook)
        self.notebook.add(raw_frame, text="📝 Text-Ansicht")
        
        self.raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.NONE, font=('Courier', 10))
        self.raw_text.pack(fill=tk.BOTH, expand=True)
        
        # Status-Bar
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.status_bar = ttk.Label(status_frame, text="Bereit", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        self.view_var = tk.StringVar(value='tree')
        
    def open_file(self):
        """Öffnet eine Plist-Datei"""
        filename = filedialog.askopenfilename(
            title="Plist-Datei öffnen",
            filetypes=[
                ("Plist-Dateien", "*.plist"),
                ("Alle Dateien", "*.*")
            ]
        )
        
        if filename:
            try:
                self.status_bar.config(text=f"Lade {Path(filename).name}...")
                self.root.update()
                
                self.current_file = filename
                self.parser.load(filename)
                
                # Update Info Labels
                info = self.parser.get_info()
                self.file_label.config(text=info.get('filename', '-'))
                self.format_label.config(text=info.get('format', '-'))
                self.count_label.config(text=str(info.get('object_count', '-')))
                
                # Reset embedded plist info
                self.embedded_plist_cache.clear()
                self.embedded_label.config(text="Noch nicht gescannt")
                
                # Zeige Daten an
                self.display_data()
                
                self.status_bar.config(text=f"Geladen: {Path(filename).name}")
                
            except Exception as e:
                messagebox.showerror("Fehler", f"Fehler beim Öffnen der Datei:\n{str(e)}")
                self.status_bar.config(text="Fehler beim Laden")
    
    def display_data(self):
        """Zeigt die Daten in allen Ansichten an"""
        try:
            data = self.parser.get_structured_data()
            
            # Update Tree View
            self.update_treeview(data)
            
            # Update JSON
            self.update_json(data)
            
            # Update Raw Text
            self.update_raw_text(data)
            
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Anzeigen der Daten:\n{str(e)}")
    
    def update_treeview(self, data):
        """Aktualisiert die Treeview mit den Daten - VOLLSTÄNDIGE REKURSION"""
        # Lösche alte Einträge
        for item in self.tree_view.get_children():
            self.tree_view.delete(item)
        
        # Füge neue Einträge hinzu
        self._add_tree_items('', data, '', 0)
        
    def _add_tree_items(self, parent, obj, key=None, depth=0):
        """
        Fügt Items rekursiv zur Treeview hinzu - UNBEGRENZTE TIEFE
        Zeigt ALLE Elemente an, egal wie tief verschachtelt
        """
        # Prüfe auf eingebettete Plist
        has_embedded, plist_data, detection_type = EmbeddedPlistDetector.detect_in_value(obj)
        embedded_indicator = f"📋 {detection_type}" if has_embedded else ""
        
        if isinstance(obj, dict):
            # Dictionary-Knoten
            if key is not None:
                size_info = f"{len(obj)} Schlüssel"
                node = self.tree_view.insert(
                    parent, 'end',
                    text=key,
                    values=('', 'dict', size_info, embedded_indicator),
                    open=True if depth < 3 else False  # Erste 3 Ebenen offen
                )
            else:
                node = parent
            
            # Rekursiv alle Schlüssel hinzufügen
            for k, v in obj.items():
                self._add_tree_items(node if node else parent, v, k, depth + 1)
        
        elif isinstance(obj, list):
            # Listen-Knoten
            if key is not None:
                size_info = f"{len(obj)} Items"
                node = self.tree_view.insert(
                    parent, 'end',
                    text=key,
                    values=('', 'list', size_info, embedded_indicator),
                    open=True if depth < 3 else False
                )
            else:
                node = parent
            
            # Rekursiv alle Items hinzufügen
            for i, item in enumerate(obj):
                self._add_tree_items(node if node else parent, item, f'[{i}]', depth + 1)
        
        else:
            # Primitive Typen - WICHTIG: Diese werden nun IMMER angezeigt
            value_str = self._format_value(obj)
            type_str = type(obj).__name__
            
            # Berechne Größe
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
                
                # Cache für eingebettete Plists
                if has_embedded:
                    self.embedded_plist_cache[item_id] = plist_data
    
    def _format_value(self, value):
        """Formatiert einen Wert für die Anzeige - zeigt mehr Details"""
        if isinstance(value, bytes):
            # Zeige erste Bytes als Hex
            preview = value[:16].hex() if len(value) > 0 else ""
            if len(value) > 16:
                preview += "..."
            return f"<bytes: {len(value)} bytes> {preview}"
        elif isinstance(value, str):
            # Zeige vollständigen String bis 200 Zeichen
            if len(value) > 200:
                return f'{value[:200]}...'
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
        """Aktualisiert die JSON-Ansicht"""
        self.json_text.delete(1.0, tk.END)
        
        def convert_bytes(obj):
            if isinstance(obj, bytes):
                try:
                    # Versuche UTF-8 Dekodierung
                    return obj.decode('utf-8')
                except:
                    # Zeige als Hex
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
        """Aktualisiert die Text-Ansicht"""
        self.raw_text.delete(1.0, tk.END)
        
        output = []
        self._format_tree_text(data, output)
        self.raw_text.insert(1.0, '\n'.join(output))
    
    def _format_tree_text(self, obj, output, indent=0, key=None, max_depth=1000):
        """Formatiert Daten als Text-Baum - UNBEGRENZTE TIEFE"""
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
        """Scannt nach eingebetteten Plists"""
        if not self.parser.data:
            messagebox.showwarning("Warnung", "Keine Daten geladen.")
            return
        
        self.status_bar.config(text="Scanne nach eingebetteten Plists...")
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
        
        self.embedded_label.config(text=str(count) if count > 0 else "Keine gefunden")
        
        if count > 0:
            self.embedded_label.config(foreground='red')
            messagebox.showinfo("Ergebnis", f"✅ {count} eingebettete Plist(s) gefunden!\n\nDoppelklick auf einen Eintrag mit 📋 Symbol zum Öffnen.")
        else:
            self.embedded_label.config(foreground='green')
            messagebox.showinfo("Ergebnis", "Keine eingebetteten Plists gefunden.")
        
        self.status_bar.config(text=f"Scan abgeschlossen: {count} eingebettete Plist(s)")
    
    def show_context_menu(self, event):
        """Zeigt Context-Menü an"""
        item = self.tree_view.identify_row(event.y)
        if item:
            self.tree_view.selection_set(item)
            
            # Prüfe ob eingebettete Plist
            has_embedded = item in self.embedded_plist_cache
            
            if has_embedded:
                self.tree_context_menu.entryconfig(2, state=tk.NORMAL)  # "Eingebettete Plist öffnen"
            else:
                self.tree_context_menu.entryconfig(2, state=tk.DISABLED)
            
            self.tree_context_menu.post(event.x_root, event.y_root)
    
    def on_double_click(self, event):
        """Behandelt Doppelklick auf TreeView-Items"""
        item = self.tree_view.identify_row(event.y)
        if item and item in self.embedded_plist_cache:
            self.open_embedded_plist()
    
    def open_embedded_plist(self):
        """Öffnet eine eingebettete Plist in einem neuen Fenster"""
        selection = self.tree_view.selection()
        if not selection:
            return
        
        item = selection[0]
        if item not in self.embedded_plist_cache:
            messagebox.showwarning("Warnung", "Kein eingebettete Plist an dieser Position.")
            return
        
        try:
            plist_data = self.embedded_plist_cache[item]
            
            # Erstelle temporäre Datei
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.plist', delete=False) as tmp_file:
                tmp_file.write(plist_data)
                tmp_path = tmp_file.name
            
            # Öffne in neuem Fenster
            new_window = tk.Toplevel(self.root)
            new_window.title("Eingebettete Plist - " + self.tree_view.item(item, 'text'))
            new_window.geometry("1200x800")
            
            # Erstelle neue GUI-Instanz für eingebettete Plist
            embedded_gui = PlistParserGUI.__new__(PlistParserGUI)
            embedded_gui.root = new_window
            embedded_gui.parser = UniversalPlistParser()
            embedded_gui.current_file = None
            embedded_gui.embedded_plist_cache = {}
            
            embedded_gui.setup_ui()
            embedded_gui.setup_menu()
            
            # Lade eingebettete Plist
            embedded_gui.parser.load(tmp_path)
            embedded_gui.display_data()
            
            info = embedded_gui.parser.get_info()
            embedded_gui.file_label.config(text="[Eingebettete Plist]")
            embedded_gui.format_label.config(text=info.get('format', '-'))
            embedded_gui.count_label.config(text=str(info.get('object_count', '-')))
            embedded_gui.embedded_label.config(text="-")
            
            embedded_gui.status_bar.config(text="Eingebettete Plist geladen")
            
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Öffnen der eingebetteten Plist:\n{str(e)}")
    
    def copy_value(self):
        """Kopiert den Wert eines Items"""
        selection = self.tree_view.selection()
        if selection:
            item = selection[0]
            value = self.tree_view.item(item, 'values')[0]
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.status_bar.config(text="Wert in Zwischenablage kopiert")
    
    def copy_path(self):
        """Kopiert den Pfad eines Items"""
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
            self.status_bar.config(text="Pfad in Zwischenablage kopiert")
    
    def expand_all(self):
        """Erweitert alle Knoten"""
        def expand_item(item):
            self.tree_view.item(item, open=True)
            for child in self.tree_view.get_children(item):
                expand_item(child)
        
        for item in self.tree_view.get_children():
            expand_item(item)
        
        self.status_bar.config(text="Alle Knoten erweitert")
    
    def collapse_all(self):
        """Reduziert alle Knoten"""
        def collapse_item(item):
            self.tree_view.item(item, open=False)
            for child in self.tree_view.get_children(item):
                collapse_item(child)
        
        for item in self.tree_view.get_children():
            collapse_item(item)
        
        self.status_bar.config(text="Alle Knoten reduziert")
    
    def show_statistics(self):
        """Zeigt Statistiken über die Plist an"""
        if not self.parser.data:
            messagebox.showwarning("Warnung", "Keine Daten geladen.")
            return
        
        data = self.parser.get_structured_data()
        
        # Zähle verschiedene Typen
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
        
        # Formatiere Statistiken
        msg = "📊 Plist-Statistiken:\n\n"
        msg += f"Dictionaries: {stats['dicts']}\n"
        msg += f"Listen: {stats['lists']}\n"
        msg += f"Strings: {stats['strings']} (Gesamtlänge: {stats['total_string_length']} Zeichen)\n"
        msg += f"Zahlen: {stats['numbers']}\n"
        msg += f"Binärdaten: {stats['bytes']} (Gesamtgröße: {stats['total_bytes_length']} Bytes)\n"
        msg += f"Booleans: {stats['bools']}\n"
        msg += f"Null-Werte: {stats['nulls']}\n"
        msg += f"\nMaximale Verschachtelungstiefe: {stats['max_depth']}\n"
        
        messagebox.showinfo("Statistiken", msg)
    
    def switch_view(self, view_type):
        """Wechselt zwischen den Ansichten"""
        self.view_var.set(view_type)
        if view_type == 'tree':
            self.notebook.select(0)
        elif view_type == 'json':
            self.notebook.select(1)
        elif view_type == 'raw':
            self.notebook.select(2)
    
    def export_json(self):
        """Exportiert die Daten als JSON"""
        if not self.parser.data:
            messagebox.showwarning("Warnung", "Keine Daten zum Exportieren vorhanden.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="JSON exportieren",
            defaultextension=".json",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")]
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
                
                self.status_bar.config(text=f"JSON exportiert: {Path(filename).name}")
                messagebox.showinfo("Erfolg", "JSON erfolgreich exportiert!")
                
            except Exception as e:
                messagebox.showerror("Fehler", f"Fehler beim Exportieren:\n{str(e)}")
    
    def export_text(self):
        """Exportiert die Daten als Text"""
        if not self.parser.data:
            messagebox.showwarning("Warnung", "Keine Daten zum Exportieren vorhanden.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Text exportieren",
            defaultextension=".txt",
            filetypes=[("Text-Dateien", "*.txt"), ("Alle Dateien", "*.*")]
        )
        
        if filename:
            try:
                data = self.parser.get_structured_data()
                output = []
                self._format_tree_text(data, output)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(output))
                
                self.status_bar.config(text=f"Text exportiert: {Path(filename).name}")
                messagebox.showinfo("Erfolg", "Text erfolgreich exportiert!")
                
            except Exception as e:
                messagebox.showerror("Fehler", f"Fehler beim Exportieren:\n{str(e)}")
    
    def show_about(self):
        """Zeigt den Über-Dialog"""
        messagebox.showinfo(
            "Über Universal Plist Parser - Forensic Edition",
            "Universal Plist Parser v2.1 - Forensic Edition\n\n"
            "Ein Tool zum Parsen und Anzeigen von Plist-Dateien\n"
            "speziell für forensische Analysen.\n\n"
            "Features:\n"
            "• Unterstützt alle Plist-Formate (XML, Binary, NSKeyedArchive)\n"
            "• Unbegrenzte Verschachtelungstiefe\n"
            "• Erkennung eingebetteter Plists\n"
            "• Vollständige Anzeige aller Elemente\n"
            "• Statistiken und Analyse-Tools\n\n"
            "Erstellt mit Python und tkinter"
        )


def main():
    """Hauptfunktion"""
    root = tk.Tk()
    app = PlistParserGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()