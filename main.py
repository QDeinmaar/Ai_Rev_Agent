import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from Ai_Rev_Engin.Core.pe_parser import PeParser
from Ai_Rev_Engin.Core.mitre_mapper import MitreMapper
from Ai_Rev_Engin.Data_Base.db_manager import DatabaseManager
from Ai_Rev_Engin.Core.llm import LLMAnalyser



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

    # ----------------------------
    # Extract Data
    # ----------------------------
    imports = parser.get_imports()
    dangerous = parser.get_dangerous_apis()
    sections = parser.get_sections()
    entropy = parser.get_entropy()
    is_packed = parser.is_packed()
    score_data = parser.calculate_score()
    verdict = parser.get_verdict(score_data["score"])
    sha256 = parser.compute_sha256()
    file_size = file_path.stat().st_size

    # ----------------------------
    # MITRE Mapping
    # ----------------------------
    mapper = MitreMapper()

    dangerous_api_names = [api["api"] for api in dangerous]

    mitre_results = mapper.map_apis(dangerous_api_names)

    # ----------------------------
    # Display File Info
    # ----------------------------
    print("\n File Information:")
    print(f"Name: {file_path.name}")
    print(f"Size: {file_size:,} bytes")
    print(f"SHA256: {sha256[:32]}...")
    print(f"Entropy: {entropy}")
    print(f"Packed: {'Yes' if is_packed else 'No'}")

    # ----------------------------
    # Imports
    # ----------------------------
    print("\n Imports:")
    print(f"Total Imports: {len(imports)}")
    print(f"Dangerous APIs: {len(dangerous)}")

    if dangerous:
        print("\n Suspicious APIs Found:")
        for api in dangerous[:10]:
            print(f"- {api['api']} ({api['dll']})")

    # ----------------------------
    # Sections
    # ----------------------------
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

    # ----------------------------
    # Verdict
    # ----------------------------
    print("\n Verdict:")
    print(f"Score: {score_data['score']}/100")
    print(f"Result: {verdict}")

    if score_data["reasons"]:
        print("\n Reasons:")
        for reason in score_data["reasons"]:
            print(f"- {reason}")

    # ----------------------------
    # MITRE Output
    # ----------------------------
    if mitre_results:
        print("\n MITRE ATT&CK Techniques:")
        for technique in mitre_results:
            print(
                f"- {technique['technique']} : {technique['name']}"
            )

    # ----------------------------
    # Prepare Results
    # ----------------------------
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
            if s["name"] in [
                "UPX",
                "UPX0",
                "UPX1",
                ".aspack",
                ".MPRESS",
                "themida"
            ]
        ]
    }

    # ----------------------------
    # AI Analysis
    # ----------------------------
    ai = LLMAnalyser()

    if ai.available:
        print("\n AI Analysis\n")
        ai_report = ai.analyze_malware(results)
        print(ai_report)

    # ----------------------------
    # Save to Database
    # ----------------------------
    db = DatabaseManager()
    sample_id = db.save_analysis(results)
    db.close()

    print(f"\n Saved to database (ID: {sample_id})")
    print("=" * 60 + "\n")

    return results

# ----------------------------
# List Recent
# ----------------------------
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


# ----------------------------
# Search by SHA256
# ----------------------------
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


# ----------------------------
# Main CLI
# ----------------------------
def main():
    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════════════════════════╗
║        AI Reverse Engineering Platform                       ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
    python main.py <file_path>
    python main.py --list
    python main.py --search <sha256>

EXAMPLES:
    python main.py malware.exe
    python main.py --list
    python main.py --search abc123...
""")
        return

    command = sys.argv[1]

    if command == "--list":
        list_recent()

    elif command == "--search" and len(sys.argv) > 2:
        search_by_hash(sys.argv[2])

    elif command.startswith("--"):
        print(f"Unknown command: {command}")

    else:
        analyze_file(command)


if __name__ == "__main__":
    main()