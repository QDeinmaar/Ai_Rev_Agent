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
        except Exception as e:
            print(f"Ollama not running. Start: Ollama serve")
            return False
        

    def analyze_malware(self, results):
        if not self.available:
            return "LLM not available"

        if not results.get('dangerous_apis'):
            return "No dangerous APIs detected - file appears benign."

        api_list = []
        for api in results.get('dangerous_apis', [])[:10]:
            api_list.append(f"    - {api['api']} (from {api['dll']})")
        api_text = '\n'.join(api_list) if api_list else "None"

        prompt = f"""
                        You are a senior malware reverse engineer.

                        Analyze ONLY the provided evidence.

                        Rules:
                        - Do NOT invent facts
                        - Do NOT mention exploits unless explicitly shown
                        - Do NOT mention remote code execution unless explicitly shown
                        - Base conclusions strictly on APIs, entropy, packing, and score

                        Evidence:
                        Dangerous APIs: {results['dangerous_apis']}
                        Entropy: {results['entropy']}
                        Packed: {results['is_packed']}
                        Score: {results['score']}
                        Verdict: {results['verdict']}

                        Return:

                        1. Likely behavior
                        2. Why suspicious
                        3. Risk level
                        4. MITRE ATT&CK techniques

                        Keep response concise and technical.
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

        




        
    

        
