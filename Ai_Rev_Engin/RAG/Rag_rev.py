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
                model_name= "all-MiniLM-L6-v2",
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

        if self.collection:
            for pattern in self.patterns:
                text = f"{pattern['name']} {pattern['description']} {' '.join(pattern['apis'])}"

                self.collection.upsert(
                    ids= [pattern["id"]],
                    documents= [text],
                    metadatas= [{

                        "name": pattern["name"],
                        "mitre_id": pattern["mitre_id"],
                        "mitre_name": pattern["mitre_name"],
                        "risk": pattern["risk"],
                        "apis": ",".join(pattern["apis"])

                    }]
                )
    
    def retrieve(self, api_names: List[str], dangerous_apis: List[str] = None ) -> str:
        if not self.initialized:
            return
        
        search_apis = dangerous_apis if dangerous_apis else api_names
        search_apis = [a for a in search_apis if a]

        if not search_apis:
            return
        
        keyword_matches = self._keyword_search(search_apis)

        vector_matches = []

        if self.collection:
            vector_matches = self._vector_search(search_apis)

        all_matches = keyword_matches + vector_matches
        mitre_ids = [m.mitre_id for m in all_matches if m.mitre_id]
        graph_matches = []
        if mitre_ids and self.graph:
            graph_matches = self._graph_search(mitre_ids)

        all_evidence = all_matches + graph_matches
        seen = set()
        unique_evidence = []

        for e in all_evidence:
            key = f"{e.source}_{e.mitre_id}"
            if key not in seen:
                seen.add(key)
                unique_evidence.append(e)

        if not unique_evidence:
            return
            
        context = "\n [Retrieved Knowledge - similar malware patterns]\n"
        context += "The following khnow malware patterns match this file's APIs: \n\n"

    def keywords_search(self, api_names: List[str]) -> list[RetrieveEvidence]:
        matches = []

        for pattern in self.patterns:
            matched_apis = [api for api in api_names if api in pattern['apis']]
            if matched_apis:
                evidence = RetrieveEvidence()
                evidence.source = pattern['name']
                evidence.content = pattern['description']
                evidence.similarity = len(matched_apis) / len(pattern['apis'])
                evidence.confidence = Confidence.HIGH if evidence.similarity > 0.5 else Confidence.MEDIUM
                evidence.mitre_id = pattern['mitre_id']
                evidence.mitre_name = pattern['mitre_name']
                matches.append(evidence)

        return matches
    
    def _vector_search(self, api_names: List[str]) -> List[RetrieveEvidence]:
        matches = []
        query = " ".join(api_names)

        try:
            results = self.collection.query(
                query_texts = [query],
                n_results = 5 
            )

            if results and results['documents']:
                for i, doc in enumerate(results['documents'][0]):
                    metadata = results['metadatas'][0][i]
                    distance = results["distances"][0][i] if 'distances' in results else 0.5

                    evidence = RetrieveEvidence()
                    evidence.source = metadata.get('name', 'Unkhown')
                    evidence.content = doc[:200]
                    evidence.similarity = 1 - distance if distance <= 1 else 0.5
                    evidence.confidence = Confidence.HIGH if evidence.similarity > 0.7 else Confidence.MEDIUM
                    evidence.mitre_id = metadata.get('mitre_id', ' ')
                    evidence.mitre_name = metadata.get('mitre_name', ' ')
                    matches.append(evidence)

        except Exception as e:
            print(f"Vector search failed : {e}")

        return matches
    
    def _graph_search(self, mitre_ids: List[str]) -> List[RetrieveEvidence]:
        matches = []
        seen = set()

        for tid in mitre_ids:
            if tid in seen:
                continue
            seen.add(tid)

            if self.graph and tid in self.graph:
                for neighbor in self.graph.neighbors(tid):
                    if neighbor not in seen:
                        evidence = RetrieveEvidence()
                        evidence.source = 'MITRE graph'
                        evidence.content = f"Related technique: {neighbor} - {self.graph.nodes[neighbor].get('name', 'Unkhnown')}"
                        evidence.similarity = 0.6
                        evidence.confidence = Confidence.MEDIUM
                        evidence.mitre_id = neighbor
                        evidence.mitre_name = self.graph.nodes[neighbor].get('name', ' ')
                        matches.append(evidence)
                        seen.add(neighbor)

        return matches
    
    def get_context(self, api_names: List[str], dangerous_apis: List[str] = None) -> str:
        if not self.initialized:
            return ""
        
        evidence_list = self.retrieve(api_names, dangerous_apis)

        if not evidence_list:
            return ""
        
        context = "\n[KNOWLEDGE BASE - Known Malware Patterns]\n"
        context += "The following patterns match this file:\n\n"

        for ev in evidence_list:
             
            mitre_str = f"({ev.mitre_id}: {ev.mitre_name})" if ev.mitre_id else ""
            context += f"{ev.source}{mitre_str}\n"
            context += f"{ev.content}\n"
            context += f"Confidence: {ev.confidence.value * 100:.0f}% | Similarity: {ev.similarity:.2f}\n\n"
        
        return context
    


if __name__ == "__main__":
    print("=" * 60)
    print("Testing RAG System")
    print("=" * 60)
    
    rag = RAG()
    
    if rag.initialized:
        # Test with suspicious APIs
        test_apis = ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "RegSetValue", "InternetOpen"]
        
        print("\nTesting with APIs:", test_apis)
        print("-" * 60)
        
        context = rag.get_context(test_apis, test_apis)
        print(context)
    else:
        print("RAG initialization failed. Installing dependencies...")
        print("Run: pip install chromadb networkx sentence-transformers")
           

        



        


