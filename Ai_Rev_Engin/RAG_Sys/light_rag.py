import json
from typing import List, Dict
from pathlib import Path


class LightRAG:
    def __init__(self):
        self.patterns = []
        self._load_patterns()
        print(f"LightRAG initialized with {len(self.patterns)} patterns")
    
    def _load_patterns(self):
        self.patterns = [
            {
                "id": "PAT-001",
                "name": "Process Injection",
                "apis": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess"],
                "description": "Injects code into another process to hide execution.",
                "mitre_id": "T1055",
                "mitre_name": "Process Injection",
                "risk": "Critical"
            },
            {
                "id": "PAT-002",
                "name": "Registry Persistence",
                "apis": ["RegSetValue", "RegCreateKey", "RegOpenKey", "RegSetValueEx"],
                "description": "Modifies registry to maintain persistence across reboots.",
                "mitre_id": "T1112",
                "mitre_name": "Modify Registry",
                "risk": "High"
            },
            {
                "id": "PAT-003",
                "name": "C2 Communication",
                "apis": ["InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest", "URLDownloadToFile"],
                "description": "Communicates with command and control servers.",
                "mitre_id": "T1071",
                "mitre_name": "Application Layer Protocol",
                "risk": "High"
            },
            {
                "id": "PAT-004",
                "name": "Ransomware",
                "apis": ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext"],
                "description": "Encrypts files for ransom.",
                "mitre_id": "T1486",
                "mitre_name": "Data Encrypted for Impact",
                "risk": "Critical"
            },
            {
                "id": "PAT-005",
                "name": "Anti-Debug",
                "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetTickCount"],
                "description": "Detects debugging or sandbox environments.",
                "mitre_id": "T1622",
                "mitre_name": "Debugger Evasion",
                "risk": "Medium"
            },
            {
                "id": "PAT-006",
                "name": "Downloader",
                "apis": ["URLDownloadToFile", "WinExec", "ShellExecute", "CreateProcess"],
                "description": "Downloads and executes additional payloads.",
                "mitre_id": "T1105",
                "mitre_name": "Ingress Tool Transfer",
                "risk": "High"
            },
            {
                "id": "PAT-007",
                "name": "Keylogger",
                "apis": ["SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow"],
                "description": "Captures user keystrokes.",
                "mitre_id": "T1056",
                "mitre_name": "Input Capture",
                "risk": "High"
            },
            {
                "id": "PAT-008",
                "name": "Credential Dumping",
                "apis": ["CreateFileMapping", "MapViewOfFile", "ReadProcessMemory"],
                "description": "Extracts credentials from memory.",
                "mitre_id": "T1003",
                "mitre_name": "OS Credential Dumping",
                "risk": "Critical"
            }
        ]
    
    def get_context(self, api_names: List[str]) -> str:
        if not api_names:
            return ""
        
        matches = []
        for pattern in self.patterns:
            matched_apis = [api for api in api_names if api in pattern["apis"]]
            if matched_apis:
                matches.append({
                    "pattern": pattern,
                    "matched_apis": matched_apis,
                    "match_score": len(matched_apis) / len(pattern["apis"])
                })
        
        if not matches:
            return ""
        
        matches.sort(key=lambda x: x["match_score"], reverse=True)
        
        context = "\n[KNOWLEDGE BASE - Matched Malware Patterns]\n\n"
        
        for match in matches[:3]:  # Top 3 matches
            p = match["pattern"]
            context += f"PATTERN: {p['name']}\n"
            context += f"MITRE: {p['mitre_id']} - {p['mitre_name']}\n"
            context += f"Risk: {p['risk']}\n"
            context += f"Description: {p['description']}\n"
            context += f"Matched APIs: {', '.join(match['matched_apis'])}\n"
            context += f"Match Confidence: {match['match_score'] * 100:.0f}%\n\n"
        
        return context


# Test
if __name__ == "__main__":
    rag = LightRAG()
    
    test_apis = ["CreateRemoteThread", "WriteProcessMemory", "RegSetValue"]
    context = rag.get_context(test_apis)
    print(context)