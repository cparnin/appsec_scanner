import os
import requests

def suggest_remediation(finding):
    api_key = os.getenv("OPENAI_API_KEY")
    prompt = f"Suggest a secure fix for this finding: {finding}"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    data = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 300
    }
    r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data, timeout=30)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]