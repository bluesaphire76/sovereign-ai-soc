import os
import json
from database import SessionLocal
from models import Incident
import requests
import urllib3
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import ollama
from rich import print
from llm_output import is_invalid_llm_output, sanitize_llm_output

urllib3.disable_warnings()

load_dotenv()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL")


def get_latest_alerts(limit=3):

    query = {
        "size": limit,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ],
        "query": {
            "match_all": {}
        }
    }

    response = requests.get(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        auth=HTTPBasicAuth(
            WAZUH_USER,
            WAZUH_PASSWORD
        ),
        json=query,
        verify=False
    )

    response.raise_for_status()

    data = response.json()

    return [
        hit["_source"]
        for hit in data["hits"]["hits"]
    ]


def analyze_alert(alert):

    prompt = f"""
/no_think

You are a professional defensive AI SOC Assistant.

Analyze the following Wazuh alert.

Respond in English using the following sections:

1. Event type
2. Actual severity
3. Likely MITRE ATT&CK mapping
4. Business risk
5. Recommended checks
6. Suggested remediation
7. Short executive summary

Output constraints:
- English only.
- Return only the final SOC analysis.
- Do not include hidden reasoning, chain-of-thought, internal deliberation, or <think> tags.
- Do not use Chinese, Italian, or any other language unless explicitly configured.

Alert:
{alert}
"""

    response = ollama.chat(
        model=OLLAMA_MODEL,
        messages=[
            {
                "role": "system",
                "content": """
You are a defensive AI SOC Assistant.

Do not propose offensive activities.
Do not generate exploits.
Do not perform or suggest automatic remediation without human validation.
Always require human analyst validation before any operational action.
Return only the final answer. Do not include chain-of-thought, hidden reasoning, or <think> tags.
"""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    raw_analysis = response["message"]["content"]
    analysis = sanitize_llm_output(raw_analysis)

    if is_invalid_llm_output(raw_analysis) or is_invalid_llm_output(analysis):
        retry_response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The previous output was invalid. You must answer in English only. "
                        "Return only the final SOC analysis. Do not include chain-of-thought, "
                        "hidden reasoning, Chinese text, Italian text, or <think> tags."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "/no_think\n\n"
                        "Regenerate the Wazuh alert analysis below in English only. "
                        "Return only the final answer.\n\n"
                        f"{prompt}"
                    ),
                },
            ],
        )

        analysis = sanitize_llm_output(retry_response["message"]["content"])

    return analysis

def save_incident(alert, analysis):

    db = SessionLocal()

    incident = Incident(

        timestamp=alert.get("@timestamp"),

        agent=alert.get("agent", {}).get("name"),

        rule=alert.get("rule", {}).get("description"),

        level=alert.get("rule", {}).get("level"),

        mitre=str(
            alert.get("rule", {}).get("mitre", {})
        ),

        risk_score=alert.get("rule", {}).get("level", 0),

        ai_analysis=analysis,

        raw_alert=json.dumps(alert)
    )

    db.add(incident)

    db.commit()

    db.close()


if __name__ == "__main__":

    alerts = get_latest_alerts()

    for alert in alerts:

        print("\n[bold cyan]==============================[/bold cyan]")
        print("[bold cyan]WAZUH ALERT[/bold cyan]")

        print({
            "timestamp": alert.get("@timestamp"),
            "rule": alert.get("rule", {}).get("description"),
            "level": alert.get("rule", {}).get("level"),
            "agent": alert.get("agent", {}).get("name")
        })

        print("\n[bold green]AI ANALYSIS[/bold green]\n")

        analysis = analyze_alert(alert)

        save_incident(alert, analysis)

        print(analysis)
