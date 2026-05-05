import sys
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent)) # this is the project path

from Ai_Rev_Engin.Core.pe_parser import PeParser
from Ai_Rev_Engin.Data_Base.db_manager import DatabaseManager

def analyze_file(file_path):
    if not Path(file_path).exists():
        print(f"The file does not exists: {file_path} ! ")
        return None
    
    print(f"\n{'=' *60}")
    print(f"Analyzing: {Path(file_path).name}")
    print(f"{'=' *60}\n")

    parser = PeParser(file_path)

    if not parser.load():
        print("not a valid PE File")
        return None
    
    dos = parser.get_dos_header()
    file_header = parser.get_file_header()
    sections = parser.get_sections()
    imports = parser.get_imports()
    dangerous = parser.get_dangerous_apis()
    is_packed = parser.is_packed()
    score_data = parser.calculate_score()
    verdict = parser.get_verdict(score_data['score'])
    sha256 = parser.compute_sha256()
    entropy = parser.get_entropy()
    file_size = Path(file_path).stat().st_size

    print(f"File Information:")
    print(f"Name: {Path(file_path).name}")
    print(f"Size: {file_size:,} bytes")
    print(f"SHA256: {sha256[:32]}...")
    print(f"Entropy: {entropy}")
    print(f"Packed: {'Yes' if is_packed else 'No'}")

    print(f"\n Imports:")
    print(f"Total: {len(imports)}")
    print(f"Dangerous: {len(dangerous)}")

    if dangerous:
        print(f"\n Dangerous APIs found:")
        for imp in dangerous[:10]:
            print(f" {imp['api']} (from{imp['dll']})")
        
    print(f"\n Sections:")
    for s in sections[:8]:
        packed_mark = "" if s ['entropy'] > 7.0 and s['name'] != '.rsrc' else ""
        print(f"{s['name']:12} | Size: {s['virtual_size']:>8} | Entropy: {s['entropy']} {packed_mark}")

        print(f"\n Verdict:")
        print(f"Score: {score_data['score']}/100")
        print(f"Result: {verdict}")

        if score_data['reasons']:
            print(f"\n Reasons:")
        for reason in score_data['reasons']:
            print(f".{reason}")

    # Save to DataBase

    results = {
        'filename': Path(file_path).name,
        'sha256': sha256,
        'file_size': file_size,
        'entropy': entropy,
        'is_packed': is_packed,
        'score': score_data['score'],
        'verdict': verdict,
        'imports': imports[:50],  # Limit for database
        'dangerous_apis': dangerous,
        'sections': sections,
        'suspicious_sections': [s for s in sections if s['name'] in ['UPX', 'UPX0', 'UPX1', '.aspack', '.MPRESS', 'themida']]
    }

    db = DatabaseManager()
    sample_id = db.save_analysis(results)
    db.close()
    
    print(f"\n Saved to database (ID: {sample_id})")
    print(f"{'=' *60}\n")
    
    return results

def list_recent():
    db = DatabaseManager()
    recent = db.list_recent(10)
    db.close()
    
    if not recent:
        print("\n No analyses found in database\n")
        return
    
    print(f"\n RECENT ANALYSES")
    print(f"{'-'*70}")
    print(f"{'VERDICT':12} {'SCORE':6} {'FILENAME':35} {'DATE'}")
    print(f"{'-'*70}")
    
    for row in recent:
        filename, sha256, score, verdict, analyzed_at = row
        date_part = analyzed_at[:16] if analyzed_at else "Unknown"
        print(f"{verdict:12} {score:6} {filename[:35]:35} {date_part}")
    
    print(f"{'-'*70}\n")

def search_by_hash(sha256):
    db = DatabaseManager()
    result = db.get_sample_by_sha256(sha256)
    db.close()
    
    if result:
        print(f"\n Found:")
        print(f"ID: {result[0]}")
        print(f"Filename: {result[1]}")
        print(f"SHA256: {result[2]}")
        print(f"Score: {result[6]}")
        print(f"Verdict: {result[7]}")
        print(f"Date: {result[8]}\n")
    else:
        print(f"\n No sample found with SHA256: {sha256[:16]}...\n")




# TEST

def main():
    
    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════════════════════════╗
║     AI Reverse Engineering Platform                          ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
    python main.py <file_path>          Analyze a file
    python main.py --list               Show recent analyses
    python main.py --search <sha256>    Find by hash

EXAMPLES:
    python main.py C:\\Windows\\System32\\notepad.exe
    python main.py --list
    python main.py --search e3b0c44298fc1c14
""")
        return
    
    command = sys.argv[1]
    
    if command == "--list":
        list_recent()
    elif command == "--search" and len(sys.argv) > 2:
        search_by_hash(sys.argv[2])
    elif command.startswith("--"):
        print(f" Unknown command: {command}")
        print("Use: --list or --search <hash>")
    else:
        # Assume it's a file path
        analyze_file(command)

if __name__ == "__main__":
    main()