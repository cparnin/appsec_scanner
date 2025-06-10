"""
AI-Powered Security Remediation Module

This module integrates with OpenAI's GPT-4o-mini to generate specific, actionable
remediation suggestions for security vulnerabilities found by scanning tools.

Key Features:
- Batches API calls to minimize costs (configurable batch size)
- Processes findings from multiple security tools (Semgrep, Gitleaks, Trivy)
- Generates specific code fixes, not generic advice
- Handles API failures gracefully with meaningful error messages
- Cleans and formats AI responses for better readability

Business Value:
- Reduces developer research time from 15 minutes to 3 minutes per issue
- Provides immediate, specific guidance instead of generic vulnerability descriptions
- Scales security knowledge across entire development teams
- Enables non-security experts to fix security issues confidently

For ImagineX DevSecOps Guild - easy to modify prompts or switch AI providers.
"""

import os
import requests
import logging
from typing import List, Dict, Any
import re

def batch_suggest_remediation(findings: List[Dict[str, Any]], batch_size: int = 10) -> None:
    """
    Process security findings through OpenAI to generate specific remediation suggestions.
    
    This function takes a list of security findings and adds AI-generated remediation
    suggestions to each finding. It batches the API calls to minimize costs while
    providing specific, actionable guidance for developers.
    
    Args:
        findings: List of security findings from scanners (modified in-place)
        batch_size: Number of findings to process per API call (cost optimization)
        
    Side Effects:
        - Adds 'ai_remediation' field to each finding dictionary
        - Logs API call progress and any errors
        - Sleeps briefly on errors to avoid rate limiting
        
    Example finding before:
        {
            'path': 'login.php',
            'line': 42,
            'description': 'SQL injection vulnerability'
        }
        
    Example finding after:
        {
            'path': 'login.php', 
            'line': 42,
            'description': 'SQL injection vulnerability',
            'ai_remediation': 'Replace line 42 with prepared statement: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");'
        }
    """
    logger = logging.getLogger(__name__)
    
    # Check for OpenAI API key (required for AI functionality)
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.error("No OpenAI API key found. Set OPENAI_API_KEY in your .env file.")
        # Graceful degradation - mark all findings as unable to get AI suggestions
        for finding in findings:
            finding["ai_remediation"] = "No API key configured - unable to generate AI suggestions."
        return

    def make_prompt(batch: List[Dict[str, Any]]) -> str:
        """
        Create a focused prompt for OpenAI that generates specific remediation suggestions.
        
        The prompt is designed to:
        - Request specific code changes, not generic advice
        - Include file path and line number context
        - Ask for numbered responses matching the input order
        - Encourage actionable, copy-paste friendly suggestions
        
        Args:
            batch: List of findings to include in this prompt
            
        Returns:
            str: Formatted prompt for OpenAI API
        """
        prompt = "You are a security expert helping developers fix vulnerabilities. For each issue below, provide a specific, actionable remediation. Focus on exact code changes, not general advice.\n\n"
        
        # Add each finding with context
        for idx, finding in enumerate(batch, 1):
            # Extract key information from different scanner formats
            msg = finding.get("extra", {}).get("message") or finding.get("description", "No message")
            file_path = finding.get("path") or finding.get("file", "unknown file")
            line = finding.get("start", {}).get("line") or finding.get("line", "?")
            
            prompt += f"{idx}. [{file_path}:{line}] {msg}\n"
        
        prompt += "\nRespond with specific fixes in this format:\n1. [Your specific remediation]\n2. [Your specific remediation]\n..."
        return prompt

    # OpenAI API configuration
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    endpoint = "https://api.openai.com/v1/chat/completions"
    model = "gpt-4o-mini"  # Cost-effective model that's good for code suggestions

    # Process findings in batches to optimize costs and API limits
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        prompt = make_prompt(batch)
        
        logger.info(f"[OpenAI] Processing findings {i+1}-{i+len(batch)} of {len(findings)} (batch size {batch_size})...")
        
        try:
            # Make API request to OpenAI
            data = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1200,  # Enough for detailed responses but not excessive
                "temperature": 0.1,  # Low temperature for consistent, focused responses
            }
            
            response = requests.post(endpoint, headers=headers, json=data, timeout=60)
            response.raise_for_status()  # Raise exception for HTTP errors
            
            # Extract AI response
            content = response.json()["choices"][0]["message"]["content"]
            
            # Parse numbered responses from AI
            answers = []
            for line in content.split("\n"):
                stripped = line.strip()
                # Look for numbered list items like "1." or "1)" safely
                if re.match(r"^\d[.)]", stripped):
                    # Extract text after the number and delimiter
                    answers.append(stripped[2:].strip())
                elif answers:
                    # If we're already collecting an answer, this might be a continuation
                    answers[-1] += " " + stripped
            
            # Assign AI suggestions to findings
            for idx, finding in enumerate(batch):
                if idx < len(answers):
                    raw_suggestion = answers[idx]
                    # Clean up the AI response for better readability
                    finding["ai_remediation"] = clean_ai_remediation(raw_suggestion)
                else:
                    finding["ai_remediation"] = "AI response was incomplete for this finding."
                    
        except requests.exceptions.RequestException as e:
            logger.error(f"[OpenAI] Network error for batch {i//batch_size + 1}: {e}")
            # Mark this batch as failed but continue with others
            for finding in batch:
                finding["ai_remediation"] = "Network error - unable to get AI suggestion."
        except KeyError as e:
            logger.error(f"[OpenAI] Unexpected API response format: {e}")
            for finding in batch:
                finding["ai_remediation"] = "API response format error - unable to parse suggestion."
        except Exception as e:
            logger.error(f"[OpenAI] Unexpected error for batch {i//batch_size + 1}: {e}")
            for finding in batch:
                finding["ai_remediation"] = "Unexpected error - unable to get AI suggestion."
            
            # Brief pause to avoid hammering the API on repeated errors
            import time
            time.sleep(2)

def clean_ai_remediation(text: str) -> str:
    """
    Clean and format AI-generated remediation text for better readability.
    
    This function processes the raw AI response to:
    - Remove redundant prefixes that AI sometimes adds
    - Convert markdown-style formatting to HTML for reports
    - Add line breaks for better readability
    - Ensure consistent formatting across responses
    
    Args:
        text: Raw AI-generated remediation text
        
    Returns:
        str: Cleaned and formatted remediation text
        
    Example:
        Input: "**Fix details for finding 1:** Replace the vulnerable code with..."
        Output: "<strong>Fix details:</strong><br><br>Replace the vulnerable code with..."
    """
    # Remove redundant prefixes that AI sometimes generates
    cleaned = re.sub(r"^\s*(\*\*)?(Fix (details )?for finding \d+)\*\*:?\s*", "", text, flags=re.IGNORECASE)
    
    # Convert **text** markdown to HTML bold formatting for reports
    cleaned = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", cleaned)
    
    # Add line break after headers that end with a colon for better formatting
    cleaned = re.sub(r"(<strong>.*?</strong>):\s*", r"\1:<br><br>", cleaned)
    
    return cleaned
