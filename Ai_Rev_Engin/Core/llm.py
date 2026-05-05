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
                    You are a professional malware reverse engineer.

                    Analyze ONLY the provided evidence.
                    Do NOT invent facts.
                    Do NOT mention websites, authors, downloads, or external context.

                    Binary Evidence:
                    Filename: {results.get('filename', 'unknown')}
                    Dangerous APIs: 
                    {api_text}
                    Entropy: {results.get('entropy', 0)}
                    Packed: {results.get('is_packed', False)}
                    Score: {results.get('score', 0)}/100
                    Verdict: {results.get('verdict', 'unknown')}

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
        
        
