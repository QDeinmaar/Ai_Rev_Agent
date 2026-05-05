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
    verdict, icon = parser.get_verdict(score_data['score'])
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
        print(f"Result: {icon} {verdict}")

        if score_data['reasons']:
            print(f"\n   Reasons:")
        for reason in score_data['reasons']:
            print(f"      • {reason}")