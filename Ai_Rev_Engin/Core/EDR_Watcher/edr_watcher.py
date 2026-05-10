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

        handler = MalwarHandler(self.analyze_new_file)
        Observer = Observer()
        Observer.schedule(handler, str(folder_path), recursive= recursive)

        try:
            while True:
                time.sleep(1)
        
        except KeyboardInterrupt:
            Observer.stop()
            print("File Watcher stopped")

        Observer.join()

    def analyze_new_file(self, file_path):
        print(f"\n" + "=" * 60)
        print(f"NEW FILE DETECTED!")
        print(f"File: {file_path.name}")
        print(f"Path: {file_path}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        try:
            with open(file_path, 'rb') as f:
                if f.read(2) != b'MZ':
                    print("This is not a PE File !")
                    return
                
            parser = PeParser(str(file_path))
            if not parser.load():
                print("Failed to analyze !")
                return
            
            dangerous = parser.get_dangerous_apis()
            score_data = parser.calculate_score()
            verdict = parser.get_verdict(score_data['score'])

            print(f"\n" + "=" * 60)
            print(f"NEW FILE DETECTED!")
            print(f"File: {file_path.name}")
            print(f"Path: {file_path}")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 60)

            if dangerous:
                print(f"\n Dangerous APIs found ({len(dangerous)}) : ")

                for api in dangerous[:5]:
                    print(f" - {api['api']} ({api['dll']})")

            self.log_event(file_path, score_data['score'], verdict, dangerous)

            # Alert

            if score_data['score'] >= 70:
                self.send_alert(file_path,score_data['score'], verdict, dangerous)
                self.quarantine_file(file_path)
                self.terminate_process(file_path)

            db = db_manager()

            results = {
                'file_name': file_path.name,
                'sha256': parser.compute_sha256(),
                'file_size': file_path.stat().st_size,
                'entropy': parser.get_entropy(),
                'is_packed': parser.is_packed,
                'score': score_data['score'],
                'verdict': verdict,
                'dangerous_apis': dangerous,
                'imports': parser.get_imports()[:50]
            }

            db.save_analysis(results)
            db.close()

            print("\n Analysis saved in Data_Base !")

        except Exception as e:
            print(f"Error analyzing the File : {e}")

    