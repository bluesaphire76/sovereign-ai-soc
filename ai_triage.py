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
Sei un AI SOC Assistant professionale.

Analizza questo alert Wazuh.

Rispondi in italiano con:

1. Tipo evento
2. Severità reale
3. MITRE ATT&CK probabile
4. Rischio per l'azienda
5. Verifiche consigliate
6. Remediation suggerita
7. Executive summary breve

Alert:
{alert}
"""

    response = ollama.chat(
        model=OLLAMA_MODEL,
        messages=[
            {
                "role": "system",
                "content": """
Sei un AI SOC Assistant difensivo.

NON proporre attività offensive.
NON generare exploit.
NON eseguire remediation automatiche.
Richiedi sempre validazione umana.
"""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response["message"]["content"]

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
