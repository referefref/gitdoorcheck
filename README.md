# gitdoorcheck - Static code analyser for git repos using OpenAI compatible LLMs
![image](https://github.com/referefref/gitdoorcheck/assets/56499429/35b0ae13-1b56-4562-bffd-fea852809d54)

* I find myself pulling way too many random git repos, this is just a simple means of doing some static analysis.
* Uses GPT-4 (or another openAI compatible API endpoint) to check for any backdoors, malicious code and so on within compilable or executable code.
* Outputs as a json file
* Uses list of programming languages extensions from: https://github.com/aymen-mouelhi

## Setup
* Place your openAI API key in the .env file (if required)

## Usage
```usage: gitdoorcheck.py [-h] --repo-url REPO_URL --local-repo-path LOCAL_REPO_PATH [--output OUTPUT]```

## Example usage
```python3 gitdoorcheck.py --repo-url="https://github.com/alexAubin/evilBunnyTrojan" --local-repo-path ./test
Cloning repository...
Repository successfully cloned into ./test.
Preparing analysis for ./test/evilBunnyServer.py...
Preparing analysis for ./test/README.md...
Preparing analysis for ./test/evilBunnyTrojan.py...
{
  "project_name": "evilBunnyTrojan",
  "project_url": "https://github.com/alexAubin/evilBunnyTrojan",
  "analysis_date": "2024-02-29T17:32:48.612167",
  "total_files_analyzed": 3,
  "total_threats_detected": 5,
  "detected_threats": [
    {
      "type": "Backdoor",
      "line_number": "15",
      "code_snippet": "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
      "severity": "High",
      "description": "Creates a socket connection to a potentially malicious server, allowing for data exfiltration or command and control."
    },
    {
      "type": "Keylogger",
      "line_number": "63",
      "code_snippet": "with keyboard.Listener(on_press=on_press) as listener:",
      "severity": "Critical",
      "description": "Starts a keylogger that captures and sends every keystroke to a remote server."
    },
    {
      "type": "Remote Command Execution",
      "line_number": "81",
      "code_snippet": "data = sock.recv(1024).decode('utf-8')",
      "severity": "High",
      "description": "Receives commands from the remote server, which could lead to arbitrary code execution."
    },
    {
      "type": "Data Exfiltration",
      "line_number": "67",
      "code_snippet": "sock.send(bytes(str(key).encode('utf-8')))",
      "severity": "High",
      "description": "Sends captured keystrokes to a remote server, potentially leaking sensitive information."
    },
    {
      "type": "Uncontrolled Resource Consumption",
      "line_number": "109",
      "code_snippet": "while True:",
      "severity": "Medium",
      "description": "The infinite loop in animatedBunny function can lead to uncontrolled resource consumption."
    }
  ]
}```
