#!/usr/bin/env python3
"""
NSKeyedArchive Plist Parser
Parst Plist-Dateien im NSKeyedArchive-Format und gibt Key/Value-Paare strukturiert aus.
"""

import plistlib
import sys
from pathlib import Path
from typing import Any, Dict, List, Union
import json


class NSKeyedArchiveParser:
    """Parser für NSKeyedArchive Plist-Dateien"""
    
    def __init__(self, plist_path: str):
        self.plist_path = Path(plist_path)
        self.data = None
        self.objects = []
        self.root_object = None
        
    def load(self) -> bool:
        """Lädt die Plist-Datei"""
        try:
            with open(self.plist_path, 'rb') as f:
                self.data = plistlib.load(f)
            
            # Extrahiere NSKeyedArchive-Struktur
            if isinstance(self.data, dict):
                self.objects = self.data.get('$objects', [])
                top = self.data.get('$top', {})
                if isinstance(top, dict) and 'root' in top:
                    root_ref = top['root']
                    if hasattr(root_ref, 'data'):
                        # UID-Objekt
                        self.root_object = self._resolve_uid(root_ref.data)
                    else:
                        self.root_object = self._resolve_uid(root_ref)
            
            return True
        except Exception as e:
            print(f"Fehler beim Laden der Datei: {e}")
            return False
    
    def _resolve_uid(self, uid: int) -> Any:
        """Löst eine UID-Referenz auf"""
        if uid < len(self.objects):
            return self.objects[uid]
        return None
    
    def _parse_object(self, obj: Any, depth: int = 0, max_depth: int = 10) -> Any:
        """Parst ein Objekt rekursiv"""
        if depth > max_depth:
            return "... (max depth reached)"
        
        # Handle UID-Referenzen
        if hasattr(obj, 'data'):
            # plistlib UID-Objekt
            resolved = self._resolve_uid(obj.data)
            return self._parse_object(resolved, depth + 1, max_depth)
        
        # Handle Dictionaries
        if isinstance(obj, dict):
            # NSKeyedArchive Objekt mit $class
            if '$class' in obj:
                result = {}
                for key, value in obj.items():
                    if key != '$class':
                        result[key] = self._parse_object(value, depth + 1, max_depth)
                return result
            else:
                # Normales Dictionary
                return {k: self._parse_object(v, depth + 1, max_depth) 
                       for k, v in obj.items()}
        
        # Handle Listen
        if isinstance(obj, list):
            return [self._parse_object(item, depth + 1, max_depth) for item in obj]
        
        # Primitive Typen
        return obj
    
    def get_structured_data(self) -> Dict:
        """Gibt die strukturierten Daten zurück"""
        if self.root_object is None:
            return {'error': 'Kein Root-Objekt gefunden'}
        
        return self._parse_object(self.root_object)
    
    def print_tree(self, obj: Any = None, indent: int = 0, prefix: str = "", key: str = None):
        """Gibt die Daten als Baum-Struktur aus"""
        if obj is None:
            obj = self.get_structured_data()
        
        indent_str = "  " * indent
        
        if key is not None:
            key_str = f"{prefix}{key}: "
        else:
            key_str = prefix
        
        if isinstance(obj, dict):
            if key is not None:
                print(f"{indent_str}{key_str}")
                indent += 1
                indent_str = "  " * indent
            
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    self.print_tree(v, indent, "├─ ", k)
                else:
                    print(f"{indent_str}├─ {k}: {self._format_value(v)}")
        
        elif isinstance(obj, list):
            if key is not None:
                print(f"{indent_str}{key_str}[{len(obj)} items]")
                indent += 1
                indent_str = "  " * indent
            
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self.print_tree(item, indent, f"├─ [{i}] ", None)
                else:
                    print(f"{indent_str}├─ [{i}]: {self._format_value(item)}")
        
        else:
            print(f"{indent_str}{key_str}{self._format_value(obj)}")
    
    def _format_value(self, value: Any) -> str:
        """Formatiert einen Wert für die Ausgabe"""
        if isinstance(value, bytes):
            return f"<bytes: {len(value)} bytes>"
        elif isinstance(value, str):
            if len(value) > 100:
                return f'"{value[:100]}..."'
            return f'"{value}"'
        return str(value)
    
    def print_json(self, indent: int = 2):
        """Gibt die Daten als JSON aus"""
        data = self.get_structured_data()
        
        # Konvertiere bytes zu lesbaren Strings
        def convert_bytes(obj):
            if isinstance(obj, bytes):
                try:
                    return obj.decode('utf-8')
                except:
                    return f"<bytes: {len(obj)} bytes>"
            elif isinstance(obj, dict):
                return {k: convert_bytes(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_bytes(item) for item in obj]
            return obj
        
        data = convert_bytes(data)
        print(json.dumps(data, indent=indent, ensure_ascii=False, default=str))
    
    def print_summary(self):
        """Gibt eine Zusammenfassung aus"""
        print(f"\n{'='*60}")
        print(f"Plist-Datei: {self.plist_path.name}")
        print(f"{'='*60}")
        
        if self.data:
            print(f"Archiver: {self.data.get('$archiver', 'Unbekannt')}")
            print(f"Version: {self.data.get('$version', 'Unbekannt')}")
            print(f"Anzahl Objekte: {len(self.objects)}")
            print(f"{'='*60}\n")


def main():
    """Hauptfunktion"""
    if len(sys.argv) < 2:
        print("Usage: python plist_parser.py <plist-file> [--json|--tree]")
        print("\nOptionen:")
        print("  --json    Ausgabe als JSON-Format")
        print("  --tree    Ausgabe als Baum-Struktur (Standard)")
        sys.exit(1)
    
    plist_file = sys.argv[1]
    output_format = 'tree'
    
    if len(sys.argv) > 2:
        if sys.argv[2] == '--json':
            output_format = 'json'
        elif sys.argv[2] == '--tree':
            output_format = 'tree'
    
    # Erstelle Parser
    parser = NSKeyedArchiveParser(plist_file)
    
    # Lade Datei
    if not parser.load():
        sys.exit(1)
    
    # Gib Zusammenfassung aus
    parser.print_summary()
    
    # Gib Daten aus
    if output_format == 'json':
        print("JSON-Ausgabe:")
        print("-" * 60)
        parser.print_json()
    else:
        print("Strukturierte Ausgabe:")
        print("-" * 60)
        parser.print_tree()
    
    print("\n" + "="*60)


if __name__ == "__main__":
    main()
