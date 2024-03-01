# gitdoorcheck - Static code analyser for git repos using OpenAI compatible LLMs
![image](https://github.com/referefref/gitdoorcheck/assets/56499429/35b0ae13-1b56-4562-bffd-fea852809d54)

* I find myself pulling way too many random git repos, this is just a simple means of doing some static analysis.
* Uses GPT-4 (or another openAI compatible API endpoint) to check for any backdoors, malicious code and so on within compilable or executable code.
* Outputs as a json file
* Can be used in CI pipeline and fail build if threshold is exceeded
* Uses list of programming languages extensions from: https://github.com/aymen-mouelhi

## Hive mind 
* The day this was published there was also [***an article on arstechnica***](https://arstechnica.com/security/2024/02/github-besieged-by-millions-of-malicious-repositories-in-ongoing-attack/) about git repos containing backdoor code and mimicking common libraries (typosquatting etc.)

## Setup
* Place your openAI API key in the .env file (if required)

## Usage
```usage: gitdoorcheck.py [-h] --repo-url REPO_URL --local-repo-path LOCAL_REPO_PATH [--output OUTPUT]```

## Example usage
```python3

python3 gitdoorcheck.py --repo-url="https://github.com/Inplex-sys/BlackCap-Grabber-NoDualHook" --local-repo-path ./blackcap-grabber
{
  "project_name": "BlackCap-Grabber-NoDualHook",
  "project_url": "https://github.com/Inplex-sys/BlackCap-Grabber-NoDualHook",
  "analysis_date": "2024-03-01T05:11:35.762317",
  "total_files_analyzed": 8,
  "total_threats_detected": 18,
  "detected_threats": [
    {
      "type": "Credential Theft",
      "file_name": "builder.py",
      "line_number": "23",
      "code_snippet": "self.webhook = input(...)",
      "confidence": "100",
      "severity": "High",
      "description": "Collects a webhook URL from the user, which could be used to exfiltrate data."
    },
    {
      "type": "Suspicious Input Handling",
      "file_name": "builder.py",
      "line_number": "92",
      "code_snippet": "self.address_replacer = input(...)",
      "confidence": "80",
      "severity": "Medium",
      "description": "Asks if the user wants to replace all copied cryptocurrency addresses, which could be used for cryptocurrency theft."
    },
    {
      "type": "Suspicious Code Execution",
      "file_name": "builder.py",
      "line_number": "284",
      "code_snippet": "eval(compile(__import__('zlib').decompress(...",
      "confidence": "90",
      "severity": "High",
      "description": "Uses eval to execute compressed code, which could hide malicious behavior."
    },
    {
      "type": "Potential Backdoor",
      "file_name": "builder.py",
      "line_number": "149",
      "code_snippet": "self.killprocess = input(...)",
      "confidence": "70",
      "severity": "Medium",
      "description": "Option to kill the victim's Discord Client could be used as part of a backdoor."
    },
    {
      "type": "Suspicious File Manipulation",
      "file_name": "builder.py",
      "line_number": "201",
      "code_snippet": "os.rename(...)",
      "confidence": "60",
      "severity": "Medium",
      "description": "Renames files in a way that could be used to disguise malicious files."
    },
    {
      "type": "Suspicious Obfuscation Technique",
      "file_name": "builder.py",
      "line_number": "312",
      "code_snippet": "os.system(f\"python obfuscation.py {filename}.py\")",
      "confidence": "75",
      "severity": "Medium",
      "description": "Uses an external script for obfuscation, which could be used to make analysis of the payload more difficult."
    },
    {
      "type": "Auto Execution",
      "file_name": "builder.py",
      "line_number": "126",
      "code_snippet": "self.startup = input(...)",
      "confidence": "90",
      "severity": "High",
      "description": "Asks if the user wants to add the file to startup, which could be used for persistence."
    },
    {
      "type": "Malicious Code Injection",
      "file_name": "README.md",
      "line_number": "2",
      "code_snippet": "An investigation has uncovered that the `main.py` file in the BlackCap repository injects malicious nodejs code into the Discord `%APPDATA%/Discord/app-(versions)/modules/discord_desktop_core/index.js` module.",
      "confidence": "90",
      "severity": "High",
      "description": "Description of injecting malicious code into Discord's core module to steal session tokens and other information."
    },
    {
      "type": "Data Exfiltration",
      "file_name": "README.md",
      "line_number": "6",
      "code_snippet": "The `inject.js` file, which is executed by the main thread of Electron (Discord), is responsible for stealing the Discord session token and collecting various information about the victim.",
      "confidence": "90",
      "severity": "High",
      "description": "Stealing Discord session tokens and other victim information."
    },
    {
      "type": "Remote Data Transmission",
      "file_name": "README.md",
      "line_number": "7",
      "code_snippet": "a copy is also sent to `https://login.blackcap-grabber.com:3000/premium/` using a `POST` method",
      "confidence": "90",
      "severity": "High",
      "description": "Transmits stolen data to a remote server."
    },
    {
      "type": "Crypto Address Manipulation",
      "file_name": "README.md",
      "line_number": "Various",
      "code_snippet": "This option replaces each of the crypto addresses copied by the victim with yours",
      "confidence": "80",
      "severity": "High",
      "description": "Manipulates cryptocurrency transactions by replacing the recipient's address with the attacker's."
    },
    {
      "type": "Persistence Mechanism",
      "file_name": "README.md",
      "line_number": "Various",
      "code_snippet": "This option will make a copy of the .exe in the windows startup of your victims and blackcap will therefore launch at each start",
      "confidence": "85",
      "severity": "High",
      "description": "Ensures persistence by adding itself to Windows startup."
    },
    {
      "type": "Malicious Code",
      "file_name": "inject.js",
      "line_number": "1",
      "code_snippet": "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0",
      "confidence": "100",
      "severity": "High",
      "description": "Disables TLS/SSL certificate validation which can expose the application to man-in-the-middle attacks."
    },
    {
      "type": "Credential Theft",
      "file_name": "inject.js",
      "line_number": "N/A",
      "code_snippet": "var tokenScript = ...getToken()",
      "confidence": "100",
      "severity": "Critical",
      "description": "Extracts Discord tokens, potentially leading to account compromise."
    },
    {
      "type": "Data Exfiltration",
      "file_name": "inject.js",
      "line_number": "N/A",
      "code_snippet": "const post = async (params) => {...}",
      "confidence": "100",
      "severity": "Critical",
      "description": "Sends collected data to an external server, indicating data exfiltration."
    },
    {
      "type": "Malicious Code",
      "file_name": "inject.js",
      "line_number": "N/A",
      "code_snippet": "electron.session.defaultSession.webRequest.onBeforeRequest(...)",
      "confidence": "100",
      "severity": "High",
      "description": "Intercepts and potentially alters web requests, which can be used for malicious purposes."
    },
    {
      "type": "Persistence",
      "file_name": "inject.js",
      "line_number": "N/A",
      "code_snippet": "const checUpdate = () => {...}",
      "confidence": "90",
      "severity": "Medium",
      "description": "Attempts to persistently inject malicious code into the application."
    },
    {
      "type": "Malicious Code",
      "file_name": "inject.js",
      "line_number": "N/A",
      "code_snippet": "electron.session.defaultSession.webRequest.onHeadersReceived(...)",
      "confidence": "90",
      "severity": "High",
      "description": "Modifies HTTP headers to bypass content security policies."
    }
  ],
  "overall_confidence": "90"
}
```

## Integrating as a Github Action
```yaml
name: Security Analysis Workflow

on: [push, pull_request]

jobs:
  security-analysis:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v2

    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.8'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install gitpython openai dotenv shutil

    - name: Run Security Analysis
      run: |
        python gitdoorcheck.py --repo-url ${{ github.event.repository.html_url }} --local-repo-path ./repo --threshold 50
      env:
        OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

    - name: Save Analysis Report
      if: always()
      uses: actions/upload-artifact@v2
      with:
        name: security-analysis-report
        path: analysis-report.json
```
