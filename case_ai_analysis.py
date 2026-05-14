import json
import os

import ollama
from dotenv import load_dotenv

from database import SessionLocal
from models import CaseAIAnalysis, CaseIncident, Incident, IncidentCase
from rag_retriever import retrieve_security_context

load_dotenv()

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")


def safe_json_loads(value: str | None):
    if not value:
        return None

    try:
        return json.loads(value)
    except Exception:
        return None


def load_case_bundle(db, case_id: int):
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == case_id)
        .first()
    )

    if not case:
        return None, []

    incidents = (
        db.query(Incident)
        .join(CaseIncident, CaseIncident.incident_id == Incident.id)
        .filter(CaseIncident.case_id == case_id)
        .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
        .all()
    )

    return case, incidents


def build_case_prompt(case: IncidentCase, incidents: list[Incident]) -> str:
    case_summary = safe_json_loads(case.summary) or case.summary or ""

    rag_query = " ".join(
        [
            str(case.title or ""),
            str(case.correlation_type or ""),
            str(case.agent or ""),
            " ".join(str(incident.rule or "") for incident in incidents),
            " ".join(str(incident.mitre or "") for incident in incidents),
        ]
    )

    security_context = retrieve_security_context(rag_query, limit=4)

    context_text = "\n\n".join(
        [
            f"Source: {item['source']}\n{item['text']}"
            for item in security_context
        ]
    )

    incident_summaries = []

    for incident in incidents:
        correlation_summary = safe_json_loads(incident.correlation_summary)

        incident_summaries.append(
            {
                "id": incident.id,
                "timestamp": incident.timestamp,
                "status": incident.status,
                "agent": incident.agent,
                "rule": incident.rule,
                "level": incident.level,
                "mitre": incident.mitre,
                "risk_score": incident.risk_score,
                "correlation_score": incident.correlation_score,
                "correlation_type": incident.correlation_type,
                "recommended_priority": incident.recommended_priority,
                "attack_chain": incident.attack_chain,
                "escalation_reason": incident.escalation_reason,
                "ai_analysis": incident.ai_analysis,
                "correlation_summary": correlation_summary,
            }
        )

    payload = {
        "case": {
            "id": case.id,
            "title": case.title,
            "status": case.status,
            "severity": case.severity,
            "agent": case.agent,
            "correlation_type": case.correlation_type,
            "risk_score": case.risk_score,
            "summary": case_summary,
        },
        "incidents": incident_summaries,
    }

    return f"""
Sei un AI SOC Assistant difensivo e professionale.

Devi analizzare un CASE investigativo composto da più incidenti Wazuh correlati.
Il tuo compito è aiutare un analista SOC umano a capire cosa sta succedendo e cosa fare.

Knowledge base context:
{context_text}

CASE DATA:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Rispondi in italiano, in modo pragmatico e operativo, con queste sezioni:

1. Executive summary
   - Sintesi breve del caso in 3-5 righe.

2. Valutazione del rischio
   - Severità reale.
   - Perché il caso è o non è critico.
   - Impatto potenziale su host, account, privilegi o servizi.

3. Evidenze principali
   - Elenca gli incidenti più importanti.
   - Spiega come sono collegati.
   - Evidenzia MITRE ATT&CK se presente.

4. Ipotesi SOC
   - Possibile falso positivo?
   - Possibile attività amministrativa legittima?
   - Possibile compromissione?
   - Cosa manca per confermare.

5. Azioni immediate consigliate
   - Verifiche concrete da fare ora.
   - Log da controllare.
   - Account/processi/host da validare.
   - Nessuna azione offensiva.

6. Remediation suggerita
   - Azioni difensive e conservative.
   - Hardening o controlli da applicare.
   - Validazione umana obbligatoria.

7. Raccomandazione operativa
   - Status consigliato tra: OPEN, TRIAGED, ESCALATED, CLOSED, FALSE_POSITIVE.
   - Severità consigliata tra: LOW, MEDIUM, HIGH, CRITICAL.
   - Prossimo passo più importante.

Regole:
- Non inventare dati non presenti.
- Se mancano evidenze, dillo chiaramente.
- Non proporre attività offensive.
- Non eseguire remediation automatica.
- Sii concreto, sintetico e utile per un SOC analyst.
"""


def extract_recommendation(analysis: str):
    text = analysis.upper()

    status = None
    severity = None

    for candidate in ["FALSE_POSITIVE", "ESCALATED", "TRIAGED", "CLOSED", "OPEN"]:
        if candidate in text:
            status = candidate
            break

    for candidate in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if candidate in text:
            severity = candidate
            break

    return status, severity


def generate_case_ai_analysis(case_id: int) -> CaseAIAnalysis:
    db = SessionLocal()

    try:
        case, incidents = load_case_bundle(db, case_id)

        if not case:
            raise ValueError(f"Case {case_id} not found")

        if not incidents:
            raise ValueError(f"Case {case_id} has no linked incidents")

        prompt = build_case_prompt(case, incidents)

        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Sei un AI SOC Assistant difensivo, orientato al triage, "
                        "alla correlazione e alla risposta operativa."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        )

        analysis_text = response["message"]["content"]
        recommended_status, recommended_severity = extract_recommendation(analysis_text)

        row = CaseAIAnalysis(
            case_id=case.id,
            model=OLLAMA_MODEL,
            analysis=analysis_text,
            recommended_status=recommended_status,
            recommended_severity=recommended_severity,
            created_by="llm",
        )

        db.add(row)
        db.commit()
        db.refresh(row)

        return row

    finally:
        db.close()
