import time
import shutil
import subprocess
import os
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

    def sen_alert(self, file_path, score, verdict, dangerous_apis):
        print(f"\n" + "!" * 60)
        print(f"MALICIOUS FILE DETECTED!")
        print(f"!" * 60)
        print(f"File: {file_path.name}")
        print(f"Score: {score}/100")
        print(f"Verdict: {verdict}")
        print(f"APIs: {', '.join([a['api'] for a in dangerous_apis[:3]])}")
        print(f"!" * 60)

        try:
            from plyer import notification
            notification.notify(
                tile = "MALWARE DETECTED !",
                message = f"{file_path.name} \n Score: {score}/100 \n Verdict: {verdict}",
                timeout = 10,
                app_name = "AI_EDR"
            )

        except:
            pass

    def quarantine_file(self, file_path):
        try:
            if not file_path.exists():
                return
            
            quarantine_dest = self.quarantine_path / file_path.name
            shutil.move(str(file_path), str(quarantine_dest))
            print(f"\n File quarantined : {quarantine_dest}")

        except Exception as e:
            print(f"Quarantine Failed : {e} !")

    def terminate_process(self, file_path):
        try:
            process_name = file_path.stem + ".exe"
            result = subprocess.run(
                f'taskkill /f /im "{process_name}"',
                shell = True,
                capture_output= True,
                text= True
            )
            if result.returncode == 0:
                print(f"Terminated process : {process_name}")
            else:
                print(f"Process not running : {process_name}")
        
        except Exception as e:
            print(f"Could not terminate : {e} !")

    def log_event(self, file_path, score, verdict, dangerous_apis):
        log_file = self.log_path / f"edr_log_{datetime.now().strftime('%Y-%m-%d')}.csv"

        with open(log_file, 'a') as f:
            f.write(f"{datetime.now().isoformat()}, {file_path.name}, {file_path}, {score}, {verdict}, {len(dangerous_apis)}\n")

    def scan_startup(self):
        print("\n" + "=" * 60)
        print("Scanning Startup Locations for Persistence")
        print("=" * 60)

        startup_folders = [
            Path(os.eviron.get('APPDATA', '')) / "Microsoft/Windows/Start Menu/Programs/Startup",
            Path(os.environ.get('PROGRAMDATA', '')) / "Microsoft/Windows/Start Menu/Programs/StartUp",
        ]

        registry_keys = [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        
        suspicious = []

        for key in registry_keys:
            try:
                result = subprocess.run(
                    f'reg_query "{key}',
                    shell= True,
                    capture_output= True,
                    text= True
                )

                if result.stdout:
                    print(f"\n Registry : {key}")
                    for line in result.stdout.split('\n'):
                        if "REG_" in line:
                            print(f"{line.strip()}")
            
            except:
                pass

            if suspicious:
                print(f"\n Found {len(suspicious)} startup items")

                for item in suspicious:
                    self.analyze_new_file(item)
            
            else:
                print(f"\n No suspicious startup items found")

    
                