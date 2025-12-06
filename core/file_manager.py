"""File Manager for Payloads and Wordlists"""
from pathlib import Path
from typing import Dict, Any

class FileManager:
    def __init__(self, base_dir: str = "/tmp/spectreweb"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def create_file(self, filename: str, content: str, binary: bool = False) -> Dict:
        try:
            filepath = self.base_dir / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            mode = 'wb' if binary else 'w'
            with open(filepath, mode) as f:
                f.write(content.encode() if binary and isinstance(content, str) else content)
            return {"success": True, "path": str(filepath), "size": filepath.stat().st_size}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def read_file(self, filename: str) -> Dict:
        try:
            filepath = self.base_dir / filename
            with open(filepath, 'r') as f:
                content = f.read()
            return {"success": True, "content": content, "size": len(content)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_files(self, directory: str = ".") -> Dict:
        try:
            target = self.base_dir / directory
            files = []
            for item in target.iterdir():
                files.append({
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0
                })
            return {"success": True, "files": files, "directory": str(target)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_file(self, filename: str) -> Dict:
        try:
            filepath = self.base_dir / filename
            filepath.unlink()
            return {"success": True, "deleted": str(filepath)}
        except Exception as e:
            return {"success": False, "error": str(e)}

# Global instance
file_manager = FileManager()
