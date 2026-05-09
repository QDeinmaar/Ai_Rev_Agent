import sys
from pathlib import Path
import time
import csv
import json
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from Ai_Rev_Engin.Core.pe_parser import PeParser
from Ai_Rev_Engin.Core.mitre_mapper import MitreMapper
from Ai_Rev_Engin.Data_Base.db_manager import DatabaseManager
from Ai_Rev_Engin.Core.llm import LLMAnalyser

from Ai_Rev_Engin.Core.ghidra_client import GhidraClient

# ----------------------------
# Analyze File
# ----------------------------
def analyze_file(file_path):
    file_path = Path(file_path)

    if not file_path.exists():
        print(f" File does not exist: {file_path}")
        return None

    print("\n" + "=" * 60)
    print(f"Analyzing: {file_path.name}")
    print("=" * 60)

    parser = PeParser(str(file_path))

    if not parser.load():
        print(" Invalid PE file")
        return None

    
    # Extract Data
    
    imports = parser.get_imports()
    dangerous = parser.get_dangerous_apis()
    sections = parser.get_sections()
    entropy = parser.get_entropy()
    is_packed = parser.is_packed()
    score_data = parser.calculate_score()
    verdict = parser.get_verdict(score_data["score"])
    sha256 = parser.compute_sha256()
    file_size = file_path.stat().st_size

    
    # MITRE Mapping
    
    mapper = MitreMapper()
    dangerous_api_names = [api["api"] for api in dangerous]
    mitre_results = mapper.map_apis(dangerous_api_names)

    
    # Display File Info
    
    print("\n File Information:")
    print(f"Name: {file_path.name}")
    print(f"Size: {file_size:,} bytes")
    print(f"SHA256: {sha256[:32]}...")
    print(f"Entropy: {entropy}")
    print(f"Packed: {'Yes' if is_packed else 'No'}")

    
    # Imports
    
    print("\n Imports:")
    print(f"Total Imports: {len(imports)}")
    print(f"Dangerous APIs: {len(dangerous)}")

    if dangerous:
        print("\n Suspicious APIs Found:")
        for api in dangerous[:10]:
            print(f"- {api['api']} ({api['dll']})")

    
    # Sections
    
    print("\n Sections:")
    for section in sections[:8]:
        packed_mark = (
            "Suspicious Entropy"
            if section["entropy"] > 7.0 and section["name"] != ".rsrc"
            else ""
        )
        print(
            f"{section['name']:12} | "
            f"Size: {section['virtual_size']:>8} | "
            f"Entropy: {section['entropy']} {packed_mark}"
        )

    
    # Verdict
    
    print("\n Verdict:")
    print(f"Score: {score_data['score']}/100")
    print(f"Result: {verdict}")

    if score_data["reasons"]:
        print("\n Reasons:")
        for reason in score_data["reasons"]:
            print(f"- {reason}")

    
    # MITRE Output
    
    if mitre_results:
        print("\n MITRE ATT&CK Techniques:")
        for technique in mitre_results:
            print(f"- {technique['technique']} : {technique['name']}")

    
    # Prepare Results Dictionary 
    
    results = {
        "filename": file_path.name,
        "sha256": sha256,
        "file_size": file_size,
        "entropy": entropy,
        "is_packed": is_packed,
        "score": score_data["score"],
        "verdict": verdict,
        "imports": imports[:50],
        "dangerous_apis": dangerous,
        "sections": sections,
        "mitre_techniques": mitre_results,
        "suspicious_sections": [
            s for s in sections
            if s["name"] in ["UPX", "UPX0", "UPX1", ".aspack", ".MPRESS", "themida"]
        ]
    }

    
    # GHIDRA DECOMPILATION
    
    print("\n Ghidra Decompilation:")
    pseudocode_text = None
    try:
        ghidra = GhidraClient()
        pseudocode_text = ghidra.get_pseudocode_text(str(file_path), max_functions=3)
        
        if pseudocode_text and "No decompiled" not in pseudocode_text:
            print(f"   Extracted {pseudocode_text.count('Function:')} functions")
            results['pseudocode'] = pseudocode_text
        else:
            print(f"   No decompiled code available")
            results['pseudocode'] = "Decompilation not available"
    except Exception as e:
        print(f"   Ghidra error: {e}")
        results['pseudocode'] = f"Decompilation failed: {e}"

    
    # AI Analysis
    
    ai = LLMAnalyser()

    if ai.available:
        print("\n AI Analysis\n")
        ai_report = ai.analyze_malware(results, pseudocode_text)
        print(ai_report)

    
    # Save to Database
    
    db = DatabaseManager()
    sample_id = db.save_analysis(results)
    db.close()

    print(f"\n Saved to database (ID: {sample_id})")
    print("=" * 60 + "\n")

    return results

    # Batch Analysis

def batch_analysis(folder_path):
    folder = Path(folder_path)

    if not folder.exists():
        print(f"Folder does not exist : {folder_path}")
        return
    
    pe_extensions = ['*.exe', '*.dll', '*.sys', '*.scr', '*.ocx', '*.cpl']
    files = []

    for ext in pe_extensions:
        files.extend(folder.rglob(ext))

    if not files:
        print(f"PE Files dont exist in : {folder_path}")
        return
    
    print("\n" + "=" * 70)
    print(f"BATCH ANALYSIS")
    print(f"Folder: {folder_path}")
    print(f"Files found: {len(files)}")
    print("=" * 70)

    # STATS
    results = []
    start_time = time.time()
    malicious_count = 0
    suspicious_count = 0
    benign_count = 0
    failed_count = 0

    for idx, file_path in enumerate(files, 1):
        print(f"\n[{idx}/{len(files)}] Analyzing: {file_path.name}")
        print("-" * 50)

        try:
            with open(file_path, 'rb') as f:
                if f.read(2) != b'MZ':
                    print(f"Skipping: Not a PE file")
                    benign_count += 1
                    continue
                result = analyze_file(str(file_path))

            if result:
                results.append(result)
                if result.get('verdict') == 'MALICIOUS':
                    malicious_count += 1
                elif result.get('verdict') == 'SUSPICIOUS':
                    suspicious_count += 1
                elif result.get('verdict') == 'CAUTION':
                    suspicious_count += 1
                else:
                    benign_count += 1
            else:
                failed_count += 1
        except Exception as e:
            print(f'Error !: {e}')
            failed_count += 1

    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print("BATCH ANALYSIS SUMMARY")
    print("=" * 70)
    print(f"Total files scanned: {len(files)}")
    print(f"Malicious: {malicious_count}")
    print(f"Suspicious: {suspicious_count}")
    print(f"Benign: {benign_count}")
    print(f"Failed: {failed_count}")
    print(f"Time elapsed: {elapsed:.1f} seconds")
    print("=" * 70)    

    if suspicious_count > 0:
        print('\n Suspicious Files are :')
        for r in results:
            if r.get('verdict') in ['SUSPICIOUS', 'CAUTION']:
                score = r.get('score', 0)
                print(f"{r['filename']} (Score: {score})")

    export_batch_csv(results, folder_path)

    return results

def export_batch_csv(results, folder_path):
    if not results:
        return
    
    timestamps = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_path = Path(folder_path) / f"batch_report_{timestamps}.csv"

    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['filename', 'sha256', 'verdict', 'score', 'entropy', 
                      'is_packed', 'total_imports', 'dangerous_apis', 'mitre_techniques']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for r in results:
            # Format MITRE techniques for CSV
            mitre_str = ", ".join([t.get('technique', '') for t in r.get('mitre_techniques', [])])
            
            writer.writerow({
                'filename': r.get('filename', ''),
                'sha256': r.get('sha256', '')[:16],
                'verdict': r.get('verdict', ''),
                'score': r.get('score', 0),
                'entropy': r.get('entropy', 0),
                'is_packed': r.get('is_packed', False),
                'total_imports': len(r.get('imports', [])),
                'dangerous_apis': len(r.get('dangerous_apis', [])),
                'mitre_techniques': mitre_str
            })
    
    print(f"\n CSV report saved: {csv_path}")

def export_batch_json(results, folder_path):
    if not results:
        return
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = Path(folder_path) / f"batch_summary_{timestamp}.json"
    
    summary = {
        "timestamp": timestamp,
        "total_files": len(results),
        "malicious": len([r for r in results if r.get('verdict') == 'MALICIOUS']),
        "suspicious": len([r for r in results if r.get('verdict') in ['SUSPICIOUS', 'CAUTION']]),
        "benign": len([r for r in results if r.get('verdict') == 'BENIGN']),
        "results": results
    }
    
    with open(json_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"JSON report saved: {json_path}")

# List Recent

def list_recent():
    db = DatabaseManager()
    recent = db.list_recent(10)
    db.close()

    if not recent:
        print("\n No analyses found.\n")
        return

    print("\n Recent Analyses")
    print("-" * 70)
    print(f"{'VERDICT':12} {'SCORE':6} {'FILENAME':35} {'DATE'}")
    print("-" * 70)

    for row in recent:
        filename, sha256, score, verdict, analyzed_at = row
        date_part = analyzed_at[:16] if analyzed_at else "Unknown"

        print(
            f"{verdict:12} "
            f"{score:<6} "
            f"{filename[:35]:35} "
            f"{date_part}"
        )

    print("-" * 70)

# Search by SHA256

def search_by_hash(sha256):
    db = DatabaseManager()
    result = db.get_sample_by_sha256(sha256)
    db.close()

    if result:
        print("\n Sample Found:")
        print(f"ID: {result[0]}")
        print(f"Filename: {result[2]}")
        print(f"SHA256: {result[1]}")
        print(f"Score: {result[6]}")
        print(f"Verdict: {result[7]}")
        print(f"Date: {result[8]}")
    else:
        print(f"\n No sample found for hash: {sha256[:16]}...")

# Main CLI

def main():

    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════════════════════════╗
║        AI Reverse Engineering Platform                       ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
    python main.py <file_path>           Analyze a single file
    python main.py --batch <folder>      Analyze all files in folder
    python main.py --list                Show recent analyses
    python main.py --search <sha256>     Find by hash

EXAMPLES:
    python main.py malware.exe
    python main.py --batch C:\\samples\\
    python main.py --list
    python main.py --search abc123...
""")
        return

    command = sys.argv[1]

    if command == "--batch" and len(sys.argv) > 2:
        batch_analysis(sys.argv[2])
    
    elif command == "--list":
        list_recent()

    elif command == "--search" and len(sys.argv) > 2:
        search_by_hash(sys.argv[2])

    elif command.startswith("--"):
        print(f"Unknown command: {command}")

    else:
        analyze_file(command)

if __name__ == "__main__":
    main()