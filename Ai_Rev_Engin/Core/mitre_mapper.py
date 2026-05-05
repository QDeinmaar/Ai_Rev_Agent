class MitreMapper:
    def __init__(self):
        self.api_to_mitre = {
            "CreateRemoteThread": {
                "technique": "T1055",
                "name": "Process Injection"
            },
            "WriteProcessMemory": {
                "technique": "T1055",
                "name": "Process Injection"
            },
            "VirtualAllocEx": {
                "technique": "T1055",
                "name": "Process Injection"
            },
            "RegSetValueExA": {
                "technique": "T1112",
                "name": "Modify Registry"
            },
            "RegSetValueExW": {
                "technique": "T1112",
                "name": "Modify Registry"
            },
            "URLDownloadToFileA": {
                "technique": "T1105",
                "name": "Ingress Tool Transfer"
            },
            "URLDownloadToFileW": {
                "technique": "T1105",
                "name": "Ingress Tool Transfer"
            },
            "WinExec": {
                "technique": "T1204",
                "name": "User Execution"
            },
            "ShellExecuteA": {
                "technique": "T1204",
                "name": "User Execution"
            },
            "ShellExecuteW": {
                "technique": "T1204",
                "name": "User Execution"
            },
            "CreateProcessA": {
                "technique": "T1106",
                "name": "Native API Execution"
            },
            "CreateProcessW": {
                "technique": "T1106",
                "name": "Native API Execution"
            },
            "GetAsyncKeyState": {
                "technique": "T1056",
                "name": "Input Capture"
            },
            "SetWindowsHookEx": {
                "technique": "T1056",
                "name": "Input Capture"
            }
        }

    def map_apis(self, dangerous_apis):
        detected = []

        for api in dangerous_apis:
            if api in self.api_to_mitre:
                detected.append(self.api_to_mitre[api])

        return detected