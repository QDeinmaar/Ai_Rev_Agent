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
        
