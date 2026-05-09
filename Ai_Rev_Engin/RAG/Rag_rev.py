import json
import hashlib
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Vector DB 

try:
    import chromadb
    from chromadb.utils import embedding_functions

    CHROMADB_AVAILABLE = True

except ImportError:
    CHROMADB_AVAILABLE = False
    print("Chromadb not installed please run : pip install chromadb !")

#Graph for RAG

try:
    import networkx as nex
    GRAPH_AVAILABLE = True

except ImportError:
    GRAPH_AVAILABLE = False
    print("Networkx is not installed please run : pip install networkx !")

class Confidence(Enum):
    HIGH = 0.8
    MEDIUM = 0.6
    LOW = 0.4
    SPECULATIVE = 0.2

class RetrieveEvidence:
    source: str
    content: str
    similarity: float
    confidence: Confidence
    mitre_id: str = ""
    mitre_name: str = ""

class RAG:
    def __init__(self):
        self.collection = None
        self.graph = None
        self.embedding_func = None
        self.patterns = []
        self.initialized = False

        self._init_chromadb()
        self._init_graph()
        self._load_patterns()

        self.initialized = bool(self.patterns)
        if self.initialized:
            print("RAG systeme is initialized !")

    def _init_chromadb(self):
        if not CHROMADB_AVAILABLE:
            return
        
        try:
            self.embedding_func = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name= "all-MiniLM-L6-v2"
                device= "cpu"
            )

            self.client = chromadb.PersistentClient(path="./chroma_db")
            self.collection = self.client.get_or_create_collection(
                name= "Malware_patterns",
                embedding_function= self.embedding_func
            )

        except Exception as e:
            print(f"Chromadb not available : {e}")

    def _init_graph(self):
        if not GRAPH_AVAILABLE:
            return
        
        self.graph = nex.Graph()

        # MITRE technique names
        techniques = {
            "T1055": "Process Injection",
            "T1059": "Command and Scripting",
            "T1562": "Impair Defenses",
            "T1071": "Application Layer Protocol",
            "T1043": "Common Port",
            "T1112": "Modify Registry",
            "T1547": "Boot or Logon Autostart",
            "T1486": "Data Encrypted for Impact",
            "T1490": "Inhibit System Recovery",
            "T1105": "Ingress Tool Transfer",
            "T1204": "User Execution",
            "T1056": "Input Capture",
            "T1622": "Debugger Evasion",
            "T1003": "OS Credential Dumping",
            "T1113": "Screen Capture"
        }

        for tid, name in techniques.items():
            self.graph.add_node(tid, name = name)

        relationships = [
            ("T1055", "T1059"),  # Injection → Execution
            ("T1055", "T1562"),  # Injection → Defense Evasion
            ("T1071", "T1043"),  # C2 → Common Port
            ("T1112", "T1547"),  # Registry → Persistence
            ("T1486", "T1490"),  # Encryption → Inhibit Recovery
        ]

        for src, dst in relationships:
            self.graph.add_edge(src, dst)

    
    def _load_patterns(self):
        self.patterns = [

            {
                "id": "PAT-001",
                "name": "Process Injection",
                "apis": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess", "ReadProcessMemory"],
                "description": "Injects malicious code into another process to hide execution and evade detection.",
                "mitre_id": "T1055",
                "mitre_name": "Process Injection",
                "risk": "Critical"
            },

            {
                "id": "PAT-002",
                "name": "Registry Persistence",
                "apis": ["RegSetValue", "RegCreateKey", "RegOpenKey", "RegSetValueExA", "RegSetValueExW"],
                "description": "Modifies Windows registry to maintain persistence across system reboots.",
                "mitre_id": "T1112",
                "mitre_name": "Modify Registry",
                "risk": "High"
            },

            {
                "id": "PAT-003",
                "name": "C2 Communication",
                "apis": ["InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest", "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW"],
                "description": "Communicates with command and control servers for instructions or data exfiltration.",
                "mitre_id": "T1071",
                "mitre_name": "Application Layer Protocol",
                "risk": "High"
            },

            {
                "id": "PAT-004",
                "name": "Ransomware Encryption",
                "apis": ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "WriteFile"],
                "description": "Encrypts files to demand ransom payment.",
                "mitre_id": "T1486",
                "mitre_name": "Data Encrypted for Impact",
                "risk": "Critical"
            },

            {
                "id": "PAT-005",
                "name": "Anti-Debug Evasion",
                "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetTickCount", "NtQueryInformationProcess", "OutputDebugString"],
                "description": "Detects debugging or sandbox environments to avoid analysis.",
                "mitre_id": "T1622",
                "mitre_name": "Debugger Evasion",
                "risk": "Medium"
            },

            {
                "id": "PAT-006",
                "name": "Downloader",
                "apis": ["URLDownloadToFile", "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"],
                "description": "Downloads and executes additional malicious payloads.",
                "mitre_id": "T1105",
                "mitre_name": "Ingress Tool Transfer",
                "risk": "High"
            },

            {
                "id": "PAT-007",
                "name": "Keylogging",
                "apis": ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetForegroundWindow"],
                "description": "Captures user keystrokes to steal credentials or sensitive information.",
                "mitre_id": "T1056",
                "mitre_name": "Input Capture",
                "risk": "High"
            },

            {
                "id": "PAT-008",
                "name": "Screen Capture",
                "apis": ["CreateDC", "BitBlt", "GetDC", "CreateCompatibleBitmap"],
                "description": "Captures screenshots of user activity.",
                "mitre_id": "T1113",
                "mitre_name": "Screen Capture",
                "risk": "Medium"
            },

            {
                "id": "PAT-009",
                "name": "Credential Dumping",
                "apis": ["CreateFileMapping", "MapViewOfFile", "OpenProcess", "ReadProcessMemory"],
                "description": "Extracts credentials from LSASS or other processes.",
                "mitre_id": "T1003",
                "mitre_name": "OS Credential Dumping",
                "risk": "Critical"
            },
            
            {
                "id": "PAT-010",
                "name": "User Execution",
                "apis": ["WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW", "system"],
                "description": "Executes commands or binaries on the compromised system.",
                "mitre_id": "T1204",
                "mitre_name": "User Execution",
                "risk": "High"
            }
        
        ]