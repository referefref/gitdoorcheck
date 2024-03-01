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
...
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
