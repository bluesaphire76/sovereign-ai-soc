"""Independent structure-first development data for the bounded AST ranker."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StructuredDevelopmentPlan:
    definition_id: str
    operation: str
    target: str
    realizations: tuple[str, ...]


@dataclass(frozen=True)
class StructuredSourcePlan:
    source_plan: str
    purpose: str
    realizations: tuple[str, ...]


DEVELOPMENT_PLANS = (
    StructuredDevelopmentPlan(
        "incident_count",
        "COUNT",
        "INCIDENT",
        (
            "Give me the size of the recorded alert population.",
            "What volume of security events does the platform hold?",
            "Total up the detections currently stored.",
            "Dimmi la numerosita degli alert presenti in piattaforma.",
            "A quanto ammonta il totale degli eventi di sicurezza registrati?",
            "Calcola il volume complessivo delle detection memorizzate.",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_count_previous_result",
        "COUNT",
        "PREVIOUS_RESULT",
        (
            "How large is that result set?",
            "What is the total among those records?",
            "Count only the previously returned items.",
            "Quanto e numeroso quel risultato?",
            "Qual e il totale tra quelli appena restituiti?",
            "Conta soltanto gli elementi del risultato precedente.",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_distinct_agents",
        "COUNT_DISTINCT",
        "AGENT",
        (
            "Determine how many separate machines have reported detections.",
            "What is the cardinality of monitored nodes producing alerts?",
            "Count unique endpoint sources across the incident stream.",
            "Determina quante macchine distinte hanno segnalato detection.",
            "Qual e la cardinalita dei nodi monitorati che producono alert?",
            "Conta le sorgenti endpoint uniche nel flusso di incidenti.",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_list",
        "LIST",
        "INCIDENT",
        (
            "Retrieve the security event records for inspection.",
            "Present the available detection entries.",
            "Bring back the alert records matching the active scope.",
            "Recupera i record degli eventi di sicurezza da ispezionare.",
            "Presenta le detection disponibili.",
            "Restituisci gli alert che rientrano nell'ambito attivo.",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_top_agents",
        "TOP_K",
        "AGENT",
        (
            "Order monitored machines by the amount of alert traffic they produced.",
            "Which endpoint sources dominate the detection volume?",
            "Build a leaderboard of nodes based on event frequency.",
            "Ordina le macchine monitorate per volume di alert prodotto.",
            "Quali sorgenti endpoint dominano il volume delle detection?",
            "Crea una graduatoria dei nodi in base alla frequenza degli eventi.",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_top_detection_rules",
        "TOP_K",
        "DETECTION_RULE",
        (
            "Order detector signatures by firing volume.",
            "Which detection controls account for the largest alert load?",
            "Build a frequency leaderboard for the rules that emitted events.",
            "Ordina le firme di detection per volume di attivazioni.",
            "Quali controlli di rilevamento producono il carico maggiore di alert?",
            "Crea una graduatoria di frequenza per le regole che emettono eventi.",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_mitre_distribution",
        "DISTRIBUTION",
        "MITRE_TECHNIQUE",
        (
            "Describe how the alert population is composed by ATT&CK technique.",
            "Break detection volume down across MITRE techniques.",
            "Which ATT&CK identifiers occur with what frequency?",
            "Descrivi la composizione degli alert per tecnica ATT&CK.",
            "Suddividi il volume delle detection tra le tecniche MITRE.",
            "Con quale frequenza ricorrono gli identificativi ATT&CK?",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_status_distribution",
        "DISTRIBUTION",
        "STATUS",
        (
            "Describe the composition of incidents across workflow states.",
            "Break the alert population down by recorded status.",
            "How is detection volume apportioned among lifecycle states?",
            "Descrivi la composizione degli incidenti tra gli stati del workflow.",
            "Suddividi la popolazione degli alert per stato registrato.",
            "Come si ripartisce il volume delle detection tra gli stati del ciclo di vita?",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_risk_distribution",
        "DISTRIBUTION",
        "RECORDED_RISK",
        (
            "Describe how incidents are apportioned across risk bands.",
            "Break the alert population down by recorded priority.",
            "Show the composition of detections for each risk level.",
            "Descrivi come si ripartiscono gli incidenti tra le fasce di rischio.",
            "Suddividi gli alert per priorita registrata.",
            "Mostra la composizione delle detection per ciascun livello di rischio.",
        ),
    ),
    StructuredDevelopmentPlan(
        "mitre_reference_lookup",
        "REFERENCE_LOOKUP",
        "MITRE_TECHNIQUE",
        (
            "Provide the catalog meaning of ATT&CK T1112.",
            "Explain the local reference entry for technique T1110.",
            "What does MITRE identifier T1112 denote?",
            "Fornisci il significato a catalogo di ATT&CK T1112.",
            "Spiega la voce di riferimento locale per la tecnica T1110.",
            "Che cosa indica l'identificativo MITRE T1112?",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_trend",
        "TREND",
        "TIME",
        (
            "Trace how detection volume evolves over the selected interval.",
            "Plot the day-by-day movement in incident counts.",
            "Describe the temporal trajectory of the alert stream.",
            "Traccia come evolve il volume delle detection nell'intervallo selezionato.",
            "Mostra l'andamento giornaliero del numero di incidenti.",
            "Descrivi la traiettoria temporale del flusso di alert.",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_compare_periods",
        "COMPARE_PERIODS",
        "INCIDENT",
        (
            "Contrast alert volume in the selected interval with its preceding interval.",
            "Measure the change in incident count between two adjacent periods.",
            "How does the current detection volume differ from the prior window?",
            "Confronta il volume degli alert nell'intervallo selezionato con quello precedente.",
            "Misura la variazione del numero di incidenti tra due periodi adiacenti.",
            "Come differisce il volume corrente delle detection dalla finestra precedente?",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_compare_agent_periods",
        "COMPARE_PERIODS",
        "AGENT",
        (
            "For those machines, compare their alert volumes with the prior period.",
            "Which previously ranked endpoint changed most between the two windows?",
            "Contrast each selected node's current and preceding event totals.",
            "Per quelle macchine confronta i volumi di alert con il periodo precedente.",
            "Quale endpoint della graduatoria precedente e cambiato di piu tra le due finestre?",
            "Confronta per ciascun nodo selezionato i totali correnti e precedenti.",
        ),
    ),
    StructuredDevelopmentPlan(
        "incident_compare_agents",
        "COMPARE_ENTITIES",
        "AGENT",
        (
            "Contrast detection volume between the two named machines.",
            "Measure how the selected endpoints differ in alert count.",
            "Compare event totals for both monitored nodes.",
            "Confronta il volume delle detection tra le due macchine indicate.",
            "Misura come differiscono gli endpoint selezionati per numero di alert.",
            "Confronta i totali degli eventi per entrambi i nodi monitorati.",
        ),
    ),
    StructuredDevelopmentPlan(
        "recorded_related_incidents",
        "RELATED_RECORDS",
        "RECORDED_CORRELATION",
        (
            "Retrieve the platform-recorded links attached to incident 5333.",
            "Which records have an authoritative correlation with event 5333?",
            "Inspect stored cross-incident relationships for alert 5333.",
            "Recupera i collegamenti registrati dalla piattaforma per l'incidente 5333.",
            "Quali record hanno una correlazione autorevole con l'evento 5333?",
            "Esamina le relazioni memorizzate tra incidenti per l'alert 5333.",
        ),
    ),
    StructuredDevelopmentPlan(
        "semantic_similar_incidents",
        "SIMILAR_RECORDS",
        "INCIDENT",
        (
            "Discover records resembling incident 5333 without treating them as linked.",
            "Find exploratory similarity candidates around event 5333.",
            "Which alerts look analogous to 5333 without a recorded correlation claim?",
            "Scopri record analoghi all'incidente 5333 senza considerarli collegati.",
            "Trova candidati di similarita esplorativa intorno all'evento 5333.",
            "Quali alert somigliano al 5333 senza affermare una correlazione registrata?",
        ),
    ),
    StructuredDevelopmentPlan(
        "case_count",
        "COUNT",
        "CASE",
        (
            "Determine the number of investigation files in the platform.",
            "What is the total case workload?",
            "Count the SOC investigation tickets.",
            "Determina il numero di fascicoli investigativi in piattaforma.",
            "Qual e il carico totale dei casi?",
            "Conta i ticket di investigazione del SOC.",
        ),
    ),
    StructuredDevelopmentPlan(
        "case_list",
        "LIST",
        "CASE",
        (
            "Retrieve the investigation files for analyst review.",
            "Present the available SOC cases.",
            "Bring back the case records in scope.",
            "Recupera i fascicoli investigativi per la revisione dell'analista.",
            "Presenta i casi SOC disponibili.",
            "Restituisci i record dei casi nell'ambito corrente.",
        ),
    ),
    StructuredDevelopmentPlan(
        "case_sla_breached_list",
        "LIST",
        "CASE_SLA_BREACH",
        (
            "Retrieve investigation files whose service deadline has been breached.",
            "Which SOC tickets are beyond their SLA?",
            "Present overdue cases requiring deadline review.",
            "Recupera i fascicoli investigativi che hanno superato la scadenza di servizio.",
            "Quali ticket SOC sono oltre lo SLA?",
            "Presenta i casi scaduti che richiedono revisione dei tempi.",
        ),
    ),
    StructuredDevelopmentPlan(
        "__unsupported__",
        "REJECT",
        "OUT_OF_DOMAIN",
        (
            "Reveal credentials stored by the database service.",
            "Forecast tomorrow's currency exchange rate.",
            "Compose a personal entertainment recommendation.",
            "Esegui un comando amministrativo sul sistema operativo.",
            "Prevedi il tasso di cambio di domani.",
            "Rivela le credenziali conservate dal servizio database.",
        ),
    ),
)


SOURCE_DEVELOPMENT_PLANS = (
    StructuredSourcePlan(
        "OPERATIONAL_FACT",
        "one exact platform-recorded fact about a selected record",
        (
            "Return the workflow state stored for incident 81.",
            "Which endpoint is attached to security event 94?",
            "Read the recorded risk value for alert 27.",
            "Give me the detection rule saved on incident 63.",
            "Restituisci lo stato memorizzato per l'incidente 81.",
            "Quale endpoint e associato all'evento di sicurezza 94?",
            "Leggi il valore di rischio registrato per l'alert 27.",
            "Dammi la regola di detection salvata sull'incidente 63.",
        ),
    ),
    StructuredSourcePlan(
        "REFERENCE",
        "bounded explanation from a cybersecurity reference catalog",
        (
            "Define credential dumping in defensive security terms.",
            "Explain what lateral movement means in an enterprise network.",
            "What does an ATT&CK persistence technique represent?",
            "Describe the security meaning of command and scripting execution.",
            "Definisci il credential dumping in ambito difensivo.",
            "Spiega cosa significa movimento laterale in una rete aziendale.",
            "Che cosa rappresenta una tecnica ATT&CK di persistenza?",
            "Descrivi il significato security dell'esecuzione di comandi e script.",
        ),
    ),
    StructuredSourcePlan(
        "PLAYBOOK",
        "procedural checks selected from an available defensive playbook",
        (
            "Provide the validation procedure for a suspicious script execution.",
            "Which defensive checklist applies to an unexpected scheduled task?",
            "Give the playbook sequence for reviewing a credential access alert.",
            "Select the verification procedure for an unusual service installation.",
            "Fornisci la procedura di verifica per uno script sospetto.",
            "Quale checklist difensiva si applica a un'attivita pianificata inattesa?",
            "Dammi la sequenza di playbook per un alert di accesso alle credenziali.",
            "Seleziona la procedura di controllo per un servizio installato in modo anomalo.",
        ),
    ),
    StructuredSourcePlan(
        "INVESTIGATION",
        "evidence-led SOC investigation guidance for suspicious activity",
        (
            "How should an analyst examine an anomalous parent-child process chain?",
            "Guide the investigation of repeated failed logons across endpoints.",
            "What evidence should be collected for an unexpected outbound connection?",
            "Outline an evidence-led inquiry into possible account misuse.",
            "Come dovrebbe un analista esaminare una catena di processi anomala?",
            "Guida l'indagine su accessi falliti ripetuti tra piu endpoint.",
            "Quali evidenze vanno raccolte per una connessione in uscita inattesa?",
            "Imposta un'indagine basata sulle evidenze su un possibile abuso di account.",
        ),
    ),
    StructuredSourcePlan(
        "REMEDIATION",
        "bounded containment or remediation guidance from available sources",
        (
            "Which containment options reduce exposure from a stolen account?",
            "Recommend defensive remediation after unauthorized persistence is confirmed.",
            "What risk reduction actions apply to an exposed administrative credential?",
            "Describe safe containment choices for a compromised endpoint.",
            "Quali opzioni di contenimento riducono il rischio di un account sottratto?",
            "Raccomanda la remediation difensiva dopo aver confermato la persistenza abusiva.",
            "Quali azioni riducono il rischio di una credenziale amministrativa esposta?",
            "Descrivi scelte di contenimento sicure per un endpoint compromesso.",
        ),
    ),
    StructuredSourcePlan(
        "RELATIONSHIP",
        "platform-recorded relationships between explicit security records",
        (
            "Retrieve the stored connection between security events 71 and 96.",
            "Are alerts 104 and 109 explicitly correlated by the platform?",
            "Show authoritative links recorded for event 38.",
            "Which records have a stored relationship with incident 46?",
            "Recupera il collegamento memorizzato tra gli eventi 71 e 96.",
            "Gli alert 104 e 109 sono correlati esplicitamente dalla piattaforma?",
            "Mostra i legami autorevoli registrati per l'evento 38.",
            "Quali record hanno una relazione memorizzata con l'incidente 46?",
        ),
    ),
    StructuredSourcePlan(
        "SIMILARITY",
        "non-authoritative semantic discovery of resembling security records",
        (
            "Discover alerts that resemble event 38 without asserting a link.",
            "Find exploratory analogues of incident 46 in semantic memory.",
            "Which records look alike but lack a stored correlation?",
            "Retrieve similarity candidates around security event 71.",
            "Scopri alert simili all'evento 38 senza affermare un legame.",
            "Trova analoghi esplorativi dell'incidente 46 nella memoria semantica.",
            "Quali record si assomigliano ma non hanno una correlazione registrata?",
            "Recupera candidati di similarita intorno all'evento di sicurezza 71.",
        ),
    ),
    StructuredSourcePlan(
        "UNSUPPORTED",
        "request outside available SOC data and defensive knowledge sources",
        (
            "Choose a dessert for a birthday dinner.",
            "Predict next season's championship winner.",
            "Draft a romantic travel itinerary.",
            "Calculate the resale value of a vintage chair.",
            "Scegli un dolce per una cena di compleanno.",
            "Prevedi chi vincera il campionato della prossima stagione.",
            "Prepara un itinerario di viaggio romantico.",
            "Calcola il valore di rivendita di una sedia vintage.",
        ),
    ),
)


def development_examples() -> tuple[tuple[str, str], ...]:
    return tuple(
        (realization, plan.definition_id)
        for plan in DEVELOPMENT_PLANS
        for realization in plan.realizations
    )


def source_development_examples() -> tuple[tuple[str, str], ...]:
    return tuple(
        (realization, plan.source_plan)
        for plan in SOURCE_DEVELOPMENT_PLANS
        for realization in plan.realizations
    )
