import argparse
import asyncio
import os
import re
import git
import openai
from dotenv import load_dotenv
from colorama import Fore, Style, init
import aiohttp
import json
from datetime import datetime

init(autoreset=True)

load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")

def load_language_extensions():
    with open('Programming_Languages_Extensions.json', 'r') as file:
        languages_data = json.load(file)
    extensions = set()
    for language in languages_data:
        for extension in language.get("extensions", []):
            extensions.add(extension)
    return extensions

file_extensions = load_language_extensions()

def parse_extracted_json(extracted_json_str):
    """
    Interpret escape sequences in the extracted JSON string and attempt to parse it.
    Args:
        extracted_json_str (str): The JSON string extracted, including escape sequences.
    Returns:
        The parsed JSON object if successful, None otherwise.
    """
    try:
        interpreted_str = bytes(extracted_json_str, "utf-8").decode("unicode_escape")
        return json.loads(interpreted_str)
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON after interpreting escape sequences: {e}")
        return None

async def analyze_code_with_openai(session, content, file_path, retry_count=0, max_retries=1):
    if retry_count > max_retries:
        print(Fore.RED + "Maximum retry limit reached. Moving on without additional retries.")
        return {"error": "Analysis failed due to retry limit."}

    system_prompt = 'Analyze the following source code for any potential backdoors, extraction of credentials, secrets or access tokens, vulnerabilities, privilege escalation, persistence or any other potentially malicious functions. If there are no obvious back doors or remote connections just return 0 otherwise return a json body matching the following [{ "type": "", "file_name": "", "line_number": "", "code_snippet": "", "confidence": "", "severity": "", "description": "" }]. Files that are supporting or describing backdoors, vulnerabilities or malicious activity should be ignored or treated as benign, this includes names of vulnerabilities and so on. Only executable code that is confirmed to be malicious should be flagged. Confidence should be a number between 0 and 100.'
    prompt = f"{system_prompt}\n\nSource code from {file_path}:\n{content}"

    message = [
        {"role": "assistant", "content": system_prompt},
        {"role": "user", "content": prompt}
    ]

    try:
        async with session.post('https://api.openai.com/v1/chat/completions',
                                json={
                                    "model": "gpt-4-turbo-preview",
                                    "messages": message,
                                    "temperature": 0.3,
                                    "max_tokens": 4096,
                                    "top_p": 1.0,
                                    "frequency_penalty": 0.0,
                                    "presence_penalty": 0.0
                                },
                                headers={"Authorization": f"Bearer {openai.api_key}"}) as response:
            if response.status == 200:
                resp_text = await response.text()

                match = re.search(r'```json\n?([\s\S]*?)\n?```', resp_text)
                if match:
                    json_str = match.group(1).strip()
                    analysis_result = parse_extracted_json(json_str)
                    if analysis_result is not None:
                        return analysis_result
                    else:
                        print(Fore.YELLOW + "Failed to interpret JSON data correctly.")
                        return {"error": "Failed to interpret JSON data correctly"}
                else:
                    print(Fore.YELLOW + "No valid JSON data found in response.")
                    return {"error": "No JSON data found"}
            else:
                print(Fore.RED + f"Non-200 response from OpenAI API. Status: {response.status}")
                return {"error": "Non-200 response from OpenAI API"}
    except Exception as e:
        print(Fore.RED + f"An error occurred while querying OpenAI for file {file_path}: {e}")
        return {"error": str(e)}

async def analyze_repo_files(session, repo_dir):
    tasks = []
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            _, ext = os.path.splitext(file)
            if ext in file_extensions:
                file_path = os.path.join(root, file)
                print(Fore.BLUE + f"Preparing analysis for {file_path}...")
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file_content:
                    content = file_content.read()
                    tasks.append(analyze_code_with_openai(session, content, file_path))
    results = await asyncio.gather(*tasks)
    return results

async def main(repo_url, local_repo_path, output_file=None):
    clone_repo(repo_url, local_repo_path)
    async with aiohttp.ClientSession() as session:
        analysis_results = await analyze_repo_files(session, local_repo_path)
        filtered_results = [result for result in analysis_results if not isinstance(result, dict) or "error" not in result]
        detected_threats = [item for sublist in filtered_results for item in (sublist if isinstance(sublist, list) else [sublist])]
        overall_confidence = max(detected_threat["confidence"] for detected_threat in detected_threats if "confidence" in detected_threat)
    
        report = {
            "project_name": repo_url.split('/')[-1],
            "project_url": repo_url,
            "analysis_date": datetime.now().isoformat(),
            "total_files_analyzed": len(analysis_results),
            "total_threats_detected": len(detected_threats),
            "detected_threats": detected_threats,
            "overall_confidence": overall_confidence
        }
    
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Analysis report saved to {output_file}")
        else:
            print(json.dumps(report, indent=2))

def clone_repo(repo_url, repo_dir):
    print(Fore.BLUE + "Cloning repository...")
    try:
        git.Repo.clone_from(repo_url, repo_dir)
        print(Fore.GREEN + f"Repository successfully cloned into {repo_dir}.")
    except Exception as e:
        print(Fore.RED + f"Failed to clone repository: {e}")
        exit(1)
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyse a GitHub repository for potential backdoors.')
    parser.add_argument('--repo-url', required=True, help='The URL of the GitHub repository to analyse')
    parser.add_argument('--local-repo-path', required=True, help='Local directory path to clone the repository into')
    parser.add_argument('--output', help='Path to save the analysis report as a JSON file (optional)')
    args = parser.parse_args()

    asyncio.run(main(args.repo_url, args.local_repo_path, args.output))
