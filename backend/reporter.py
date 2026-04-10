import os
from typing import List, Dict, Any
from dotenv import load_dotenv
import anthropic

# Load environment variables from .env file
load_dotenv()

def generate_report(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Takes a list of vulnerability findings and uses Anthropic's Claude API
    to explain the vulnerability securely and cleanly.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key == "your_api_key_here":
        print("ANTHROPIC_API_KEY not found or default. Skipping AI explanations.")
        return findings

    try:
        client = anthropic.Anthropic(api_key=api_key)
    except Exception as e:
        print(f"Failed to initialize Anthropic client: {e}")
        return findings

    enriched_findings = []
    for finding in findings:
        prompt = (
            f"Explain this vulnerability in simple terms and suggest a fix:\n"
            f"Type: {finding.get('type')}\n"
            f"Input: {finding.get('input')}\n"
            f"Payload that triggered it: {finding.get('payload')}"
        )

        try:
            # We are using Claude-3-Sonnet model here as a reliable default.
            response = client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=300,
                temperature=0.3,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            explanation = response.content[0].text
            enriched_finding = dict(finding)
            enriched_finding["description"] = explanation
            # Assigning simple severity based on type (for demonstration)
            enriched_finding["severity"] = "High" if finding.get("type") in ["SQLi", "XSS"] else "Medium"
            enriched_findings.append(enriched_finding)
            
        except Exception as e:
            print(f"Failed to get AI explanation for finding: {e}")
            finding_copy = dict(finding)
            finding_copy["description"] = "Failed to generate AI explanation."
            finding_copy["severity"] = "High"
            enriched_findings.append(finding_copy)

    return enriched_findings
