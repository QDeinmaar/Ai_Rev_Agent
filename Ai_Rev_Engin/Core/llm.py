import ollama 

class LLMAnalyser:
    def __init__(self, model="gemma:2b"):
        self.model = model
        self.available = self._check_model()

    def _check_model(self):
        try:
            result = ollama.list()
            models = [m['model'] for m in result['models']]

            for m in models:
                if self.model in m: 
                    print(f"LLM is ready: {self.model}")
                    return True
                
                print(f"Model {self.model} not Found")
                print(f"Run : Ollama pull {self.model}")
                return False
            
        except Exception:
            print(f"Ollama not running. Start: Ollama serve")
            return False
        

    def analyze_malware(self, results, pseudocode=None):
    
        if not self.available:
            return "LLM not available"
    
        if not results.get('dangerous_apis'):
            return "No dangerous APIs detected - file appears benign."
    
        # Format dangerous APIs for the prompt
        api_list = []
        for api in results.get('dangerous_apis', [])[:10]:
            api_list.append(f"    - {api['api']} (from {api['dll']})")
            api_text = '\n'.join(api_list) if api_list else "None"
    
        # Format MITRE techniques
        mitre_list = []
        for tech in results.get('mitre_techniques', [])[:5]:
            mitre_list.append(f"    - {tech['technique']}: {tech['name']}")
            mitre_text = '\n'.join(mitre_list) if mitre_list else "None"
    
        # Add pseudocode if available (limit size)
        pseudo_text = ""
        if pseudocode and "No decompiled" not in pseudocode:
        # Limit to first 3000 chars
            pseudo_text = f"\nDecompiled Code (C-like pseudocode):\n{pseudocode[:3000]}\n"
    
        prompt = f"""
                You are a professional malware reverse engineer.

                Analyze ONLY the provided evidence.
                Do NOT invent facts.
                Do NOT mention websites, authors, downloads, or external context.

                Binary Evidence:
                Filename: {results.get('filename', 'unknown')}
                Dangerous APIs: 
                {api_text}
                MITRE ATT&CK Techniques found:
                {mitre_text}
                Entropy: {results.get('entropy', 0)}
                Packed: {results.get('is_packed', False)}
                Score: {results.get('score', 0)}/100
                Verdict: {results.get('verdict', 'unknown')}
                {pseudo_text}
                Provide:

                1. Likely behavior
                2. Why it is suspicious
                3. Risk level (Low/Medium/High/Critical)
                4. MITRE ATT&CK technique if applicable
                """
    
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response['message']['content']
        except Exception as e:
            return f"Error calling Ollama: {e}"

        
    def explain_dangerous_apis(self, dangerous_apis, filename, entropy = 0, is_packed = False, score = 0, verdict = "Unkhnown   "):
        results = {
            'filename': filename,
            'dangerous_apis': dangerous_apis,
            'entropy': entropy,
            'is_packed': is_packed,
            'score': score,
            'verdict': verdict
        }
        return self.analyze_malware(results)



if __name__ == "__main__":

        print("=" *60)
        print("Testing LLM Analyser")
        print("="*60)
        print("\nMake sure Ollama is running: ollama serve")
        print("Make sure model is installed: ollama pull gemma:2b\n")

        ai = LLMAnalyser()

        if ai.available:
            test_results = {

                'filename': 'suspicious.exe',
                'dangerous_apis': [
                {'dll': 'kernel32.dll', 'api': 'CreateRemoteThread'},
                {'dll': 'kernel32.dll', 'api': 'WriteProcessMemory'},
                {'dll': 'advapi32.dll', 'api': 'RegSetValue'}
            ],

            'entropy': 7.2,
            'is_packed': True,
            'score': 85,
            'verdict': 'MALICIOUS'
            }

            print("Analyzing test malware...")
            print("-"*60)
            result = ai.analyze_malware(test_results)
            print(result)
            print("-"*60)
        else:
            print("\nTroubleshooting steps:")
            print("1. Open a NEW terminal")
            print("2. Run: ollama serve")
            print("3. Keep that terminal open")
            print("4. In THIS terminal, run: ollama pull gemma:2b")
            print("5. Then run this script again")

        




        
    

        
