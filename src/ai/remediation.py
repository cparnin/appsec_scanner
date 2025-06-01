import os
import requests
import logging
from typing import List, Dict, Any
import re

def batch_suggest_remediation(findings: List[Dict[str, Any]], batch_size: int = 10) -> None:
    """
    Batch findings and send them to OpenAI for AI-powered remediation suggestions.
    Adds the AI suggestion to each finding in-place.
    Args:
        findings: List of findings to remediate
        batch_size: Number of findings per OpenAI API call
    """
    logger = logging.getLogger(__name__)
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.error("No OpenAI API key found. Set OPENAI_API_KEY in your .env file.")
        for finding in findings:
            finding["ai_remediation"] = "No API key, unable to suggest fix."
        return

    def make_prompt(batch: List[Dict[str, Any]]) -> str:
        prompt = "Suggest secure, actionable fixes for the following security findings. Answer as a numbered list matching each finding.\n\n"
        for idx, finding in enumerate(batch, 1):
            msg = finding.get("extra", {}).get("message") or finding.get("description", "No message")
            file_path = finding.get("path") or finding.get("file", "unknown file")
            line = finding.get("start", {}).get("line") or finding.get("line", "?")
            prompt += f"{idx}. [{file_path}:{line}] {msg}\n"
        prompt += "\nRespond as:\n1. [Your fix recommendation]\n2. [Your fix recommendation]\n..."
        return prompt

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    endpoint = "https://api.openai.com/v1/chat/completions"
    model = "gpt-4o-mini"

    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        prompt = make_prompt(batch)
        logger.info(f"[OpenAI] Sending findings {i+1}-{i+len(batch)} of {len(findings)} (batch size {batch_size})...")
        try:
            data = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1200,
            }
            r = requests.post(endpoint, headers=headers, json=data, timeout=60)
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            answers = []
            for line in content.split("\n"):
                if line.strip() and (line.strip()[0].isdigit() and line.strip()[1] in [".", ")"]):
                    answers.append(line[line.find('.')+1:].strip())
                elif answers:
                    answers[-1] += " " + line.strip()
            for idx, finding in enumerate(batch):
                raw = answers[idx] if idx < len(answers) else "N/A"
                finding["ai_remediation"] = clean_ai_remediation(raw)
        except Exception as e:
            logger.error(f"[OpenAI] Batch failed: {e}")
            for finding in batch:
                finding["ai_remediation"] = "Error or rate limited from OpenAI."
            import time
            time.sleep(2)  # avoid slamming API if repeated errors

def clean_ai_remediation(text):
    # Remove "Fix details for finding X:" or similar prefixes
    cleaned = re.sub(r"^\s*(\*\*)?(Fix (details )?for finding \d+)\*\*:?\s*", "", text, flags=re.IGNORECASE)
    # Convert **text** to <strong>text</strong> for proper HTML bold formatting
    cleaned = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", cleaned)
    # Add line break after first sentence if it ends with a colon
    cleaned = re.sub(r"(<strong>.*?</strong>):\s*", r"\1:<br><br>", cleaned)
    return cleaned
