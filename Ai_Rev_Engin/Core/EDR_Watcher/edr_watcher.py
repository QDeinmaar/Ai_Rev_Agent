import time
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
import sys

sys.path.insert(0,str(Path(__file__).parent.parent.parent))

from Ai_Rev_Engin.Core.pe_parser import PeParser
from Ai_Rev_Engin.Core.llm import LLMAnalyser
from Ai_Rev_Engin.Data_Base import db_manager

class EDRWATCHER:
    def __init__(self):
        self.watched_folders = []
        self.quarantine_path = Path("storage/quarantine")
        self.quarantine_path.mkdir(parents= True, exist_ok= True)
        self.log_path = Path('storage/edr_logs')
        self.log_path.mkdir(parents= True, exist_ok= True)

    def watch_folder(self, folder_path, recursive = True):
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class MalwarHandler(FileSystemEventHandler):
            def __init__(self, callback):
                self.callback = callback

            def on_created(self, event):
                if not event.is_directory:
                    file_path = Path(event.src_path)
                    if file_path.suffix.lower() in ['.exe', '.dll', '.scr', '.sys']:
                        self.callback(file_path)
        
        print(f"\nStarting File System Watcher")
        print(f"Monitoring: {folder_path}")
        print("Analyzing new .exe/.dll/.scr/.sys files in real-time")
        print("Press Ctrl+C to stop\n")
