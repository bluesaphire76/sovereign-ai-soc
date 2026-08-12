from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from services.assistant.focus import (
    cosine_similarity,
    get_shared_semantic_embedding_provider,
    normalize_embedding_text,
)
from services.assistant.v3.contracts import AnswerIntent, IntentScore, IntentSelection


class IntentEmbeddingProvider(Protocol):
    def embed(self, text: str) -> Sequence[float]:
        ...


@dataclass(frozen=True)
class IntentDescriptor:
    intent: AnswerIntent
    description: str
    semantic_examples: tuple[str, ...]

    @property
    def embedding_text(self) -> str:
        examples = " ".join(f"Example: {value}" for value in self.semantic_examples)
        return f"{self.description} {examples}"

    @property
    def prototype_texts(self) -> tuple[str, ...]:
        return (self.description, *self.semantic_examples)

    @property
    def prototype_embedding_texts(self) -> tuple[str, ...]:
        label = self.intent.value.replace("_", " ").title()
        return tuple(f"{label} intent. {value}" for value in self.prototype_texts)


INTENT_REGISTRY = (
    IntentDescriptor(
        AnswerIntent.FACT_LOOKUP,
        "Retrieve one or a few explicitly recorded operational values without interpretation.",
        (
            "What status is recorded?",
            "Qual e il valore attuale registrato?",
            "Retrieve a precise stored field from the scoped record.",
            "Read the exact recorded state, endpoint, detector, score, priority, technique, time, or escalation flag.",
            "Recupera un attributo preciso dal record corrente.",
            "Leggi il valore registrato di stato, endpoint, regola, punteggio, priorita, tecnica, orario o escalation.",
            "Return the platform's recorded status for one incident.",
            "Identify the endpoint host or monitoring agent attached to one record.",
            "Return only the stored numeric risk score or recommended priority.",
            "Name the recorded detection rule or MITRE ATT&CK technique.",
            "Return the timestamp stored for this record.",
            "Report whether an authoritative escalation boolean is stored.",
            "Riporta lo stato registrato in piattaforma per un incidente.",
            "Identifica host, agent, regola o tecnica associati al singolo record.",
            "Restituisci il risk score, la priorita o l'orario memorizzati.",
            "Riporta se e memorizzato un booleano autorevole di escalation.",
            "Which detection rule produced the current record?",
            "Which MITRE technique has been recorded on this record?",
            "At what time was the current incident recorded?",
            "Quale regola di rilevamento ha prodotto il record corrente?",
            "Quale raccomandazione di priorita e memorizzata nel record?",
            "Quale tecnica MITRE risulta memorizzata?",
            "Quale regola di detection ha prodotto l'incidente?",
            "Quale tecnica MITRE risulta registrata?",
        ),
    ),
    IntentDescriptor(
        AnswerIntent.EXPLAIN,
        "Explain the meaning and significance of the scoped security record using supporting facts.",
        (
            "Help me understand this detection.",
            "Spiegami cosa rappresenta questo incidente.",
            "Interpret the detection and connect its technical meaning to supporting facts.",
            "Clarify the significance of the alert, endpoint, rule, risk, technique, and correlation context.",
            "Provide a technical walkthrough of one security incident.",
            "Interpreta la detection collegando il significato tecnico ai fatti.",
            "Chiarisci il significato di alert, endpoint, regola, rischio, tecnica e correlazione.",
            "Fornisci una lettura tecnica di un singolo incidente di sicurezza.",
            "Explain why the existing evidence is technically significant.",
            "Interpret one security record without adding assumptions.",
            "Explain the meaning of its MITRE technique and correlation context.",
            "Spiega perche le evidenze registrate sono tecnicamente significative.",
            "Interpreta un singolo record senza aggiungere assunzioni.",
            "Chiarisci il significato del contesto MITRE e di correlazione.",
            "Explain the event and why the supporting recorded evidence matters.",
            "How should a security analyst interpret the current record?",
            "Guide me through the current incident using technical language.",
            "Walk me through the current incident in technical terms.",
            "Che significato ha questa detection rispetto ai fatti del record?",
            "Spiega quali fatti supportano la detection e quali aspetti rimangono incerti.",
            "Quali fatti supportano la detection e quali restano incerti?",
        ),
    ),
    IntentDescriptor(
        AnswerIntent.SUMMARY,
        "Provide a balanced operational overview of the scoped incident or case.",
        (
            "Summarize this record.",
            "Dammi una panoramica operativa.",
            "Give a balanced overview of the incident or case.",
            "Recap the main facts, current state, and caveats concisely.",
            "Fornisci una panoramica bilanciata del record.",
            "Riepiloga in modo conciso fatti principali, stato corrente e limiti.",
            "Produce a short recap rather than an investigation.",
            "Condense the main recorded facts into a brief operational summary.",
            "Summarize current state and the leading detection detail.",
            "State the main facts briefly without investigative analysis.",
            "Produci un riepilogo breve invece di un'analisi investigativa.",
            "Condensa i fatti registrati in una sintesi operativa.",
            "Riassumi stato corrente e principale dettaglio di detection.",
            "Esponi brevemente i fatti principali senza analisi investigativa.",
            "Summarize the current incident exclusively from authoritative evidence.",
            "Give the primary facts recorded for this incident.",
            "Recap the incident without drawing conclusions beyond recorded facts.",
            "Riassumi il record utilizzando soltanto le evidenze disponibili.",
            "Condensa questo record per una rapida consultazione operativa.",
        ),
    ),
    IntentDescriptor(
        AnswerIntent.INVESTIGATE,
        "Analyze what happened and identify the recorded evidence and timeline that support it.",
        (
            "What happened and what evidence supports it?",
            "Analizza eventi ed evidenze disponibili.",
            "Analyze the event using evidence, chronology, gaps, and verification questions.",
            "Build an evidence-led investigative assessment of what happened.",
            "Analizza evento, evidenze, cronologia, lacune e verifiche.",
            "Costruisci una valutazione investigativa basata sulle evidenze.",
            "Identify the most material elements for an investigation.",
            "Assess evidence, safe conclusions, and gaps that require verification.",
            "Determine which evidence supports the detection and which evidence is missing.",
            "Determine the safe conclusions supported by recorded evidence during an investigation.",
            "Individua gli elementi piu rilevanti per l'indagine.",
            "Valuta evidenze, conclusioni sicure e lacune da verificare.",
            "Determina quali evidenze supportano la detection e quali mancano.",
            "How should this incident be investigated using the facts currently available?",
            "Valuta cosa si puo concludere e quali aspetti richiedono verifica.",
            "Imposta l'indagine sull'incidente utilizzando i fatti a disposizione.",
            "Come imposteresti l'indagine su questo incidente dai fatti disponibili?",
        ),
    ),
    IntentDescriptor(
        AnswerIntent.COMPARE,
        "Compare two or more explicit security records and describe evidenced differences and similarities.",
        (
            "Compare these two incidents.",
            "Confronta i record selezionati.",
            "Contrast an explicitly selected pair of security records.",
            "Describe factual similarities and differences between two chosen incidents.",
            "Metti a confronto una coppia esplicita di record di sicurezza.",
            "Descrivi somiglianze e differenze fattuali tra due incidenti selezionati.",
            "State what two selected records share and how they differ.",
            "Compare risk, state, and detection evidence across an explicit pair.",
            "Provide a bounded pair comparison with clear non-implications.",
            "Contrast the host, rule, state, and evidence fields of one selected pair.",
            "Compare two records while explicitly avoiding a causal conclusion.",
            "Indica cosa condividono due record selezionati e come differiscono.",
            "Confronta rischio, stato ed evidenze nella coppia esplicita.",
            "Fornisci un confronto circoscritto con non-implicazioni chiare.",
            "Confronta host, regola, stato ed evidenze di una coppia selezionata.",
            "Confronta due record evitando esplicitamente conclusioni causali.",
            "Do two selected incidents share evidence worth investigating?",
            "I due incidenti condividono evidenze che meritano indagine?",
            "Confronta il contesto delle detection e le relazioni supportate.",
            "Quali somiglianze costituiscono fatti e quali derivazioni analitiche?",
        ),
    ),
    IntentDescriptor(
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        "Discover and analyze candidate connections between the scoped incident and other incidents.",
        (
            "Could this connect to other incidents?",
            "Cerca possibili collegamenti con altri incidenti.",
            "Discover other incidents related to the current record.",
            "Explain evidence-backed cross-record relationships and their provenance.",
            "Cerca altri incidenti collegati al record corrente.",
            "Spiega relazioni tra record e relativa provenance sulla base delle evidenze.",
            "Identify which other incidents are relevant to the current one and why.",
            "Select related incidents for broader analyst inspection.",
            "Analyze similarities across records without attributing a common actor.",
            "Identifica quali altri incidenti sono rilevanti e perche.",
            "Seleziona incidenti collegati da esaminare in un contesto piu ampio.",
            "Analizza somiglianze tra record senza attribuire un attaccante comune.",
            "Which recorded similarities help exploratory cross-record analysis?",
            "What wider cross-incident context is supported by authoritative evidence?",
            "Il record corrente puo essere collegato ad altri incidenti?",
            "Questo record potrebbe avere collegamenti con altri incidenti?",
            "Quali altri incidenti correlati dovrebbe esaminare l'analista?",
            "Quali somiglianze registrate aiutano l'analisi tra incidenti?",
            "Quali somiglianze registrate sono utili nell'analisi cross-incident?",
            "Identifica i record collegati e descrivi la classe di provenance della relazione.",
        ),
    ),
    IntentDescriptor(
        AnswerIntent.PATTERN_ANALYSIS,
        "Find recurring evidence-backed patterns across multiple security incidents.",
        (
            "Find recurring patterns across alerts.",
            "Individua schemi ricorrenti tra gli incidenti.",
            "Identify recurring evidence-backed structures across several incidents.",
            "Analyze repeated endpoints, rules, techniques, timing, or detections across records.",
            "Individua schemi ricorrenti supportati tra piu incidenti.",
            "Analizza ripetizioni di endpoint, regole, tecniche, tempi o detection.",
            "Describe the strongest recurring pattern supported across incidents.",
            "Find evidence that repeats across related security records.",
            "Analyze repeated signals together with their limitations.",
            "Descrivi lo schema ricorrente piu forte supportato tra incidenti.",
            "Trova evidenze che si ripetono nei record collegati.",
            "Analizza segnali ripetuti insieme ai relativi limiti.",
            "Describe the most significant recurring cross-incident pattern supported by evidence.",
            "Quali schemi di host, regole, MITRE o case si ripetono tra gli incidenti?",
            "Quale schema ricorrente comune emerge da questi incidenti?",
        ),
    ),
    IntentDescriptor(
        AnswerIntent.NEXT_ACTION,
        "Identify bounded analyst verification steps or investigation guidance without executing actions.",
        (
            "Which evidence collection or validation step should be performed now?",
            "Quali controlli conviene fare adesso?",
            "Recommend bounded analyst checks and verification steps.",
            "Prioritize practical evidence gathering without treating guidance as fact.",
            "Suggerisci controlli e passi di verifica per l analista.",
            "Dai priorita alla raccolta di evidenze distinguendo i consigli dai fatti.",
            "Recommend immediate evidence gathering and investigation steps.",
            "Select relevant playbook checks for the available evidence.",
            "Describe what should be verified before escalation or containment review.",
            "List actions the analyst should perform now.",
            "Choose the immediate evidence verification action.",
            "Indica passi investigativi pratici da eseguire successivamente.",
            "Seleziona controlli di playbook pertinenti alle evidenze.",
            "Descrivi cosa verificare prima di valutare escalation o contenimento.",
            "Elenca le azioni che l'analista dovrebbe eseguire ora.",
            "Scegli una verifica operativa immediata sulle evidenze.",
            "Recommend immediate evidence checks while keeping guidance distinct from facts.",
            "Give concrete investigative actions to perform now.",
            "Provide practical investigative actions for the current workflow.",
            "Prioritize practical investigative actions for the current workflow.",
            "Recommend practical next steps for investigating the current evidence.",
            "Quali azioni investigative immediate vanno eseguite sulle evidenze?",
            "Quali azioni investigative concrete sono supportate dalle evidenze?",
        ),
    ),
    IntentDescriptor(
        AnswerIntent.HANDOVER,
        "Prepare a factual analyst handover with state, evidence, outstanding checks and context.",
        (
            "Prepare this for shift handover.",
            "Prepara il passaggio di consegne per il SOC.",
            "Prepare a factual SOC shift handoff.",
            "Organize state, evidence, gaps, and outstanding checks for the incoming analyst.",
            "Prepara un passaggio di consegne fattuale per il turno SOC.",
            "Organizza stato, evidenze, lacune e controlli per il prossimo analista.",
            "State what the incoming analyst needs to know and verify.",
            "Prepare the record for continuity into the next SOC shift or session.",
            "Create a handover summary for the analyst receiving the investigation.",
            "Transfer facts, gaps, and open checks to another analyst taking over.",
            "Package the investigation context for continuation by a different analyst.",
            "Handover to the next analyst the known facts and verification items.",
            "Carry investigation context into the next analyst session.",
            "Shift handover summarizing the record for incoming SOC staff.",
            "Handover that separates established facts from recommended guidance.",
            "Indica cosa deve sapere e verificare l'analista in ingresso.",
            "Prepara il record per la continuita nel turno o nella sessione successiva.",
            "Crea una sintesi di consegna per chi riceve l'indagine.",
            "Trasferisci fatti, lacune e controlli aperti all'analista subentrante.",
            "Organizza il contesto per la prosecuzione da parte di un altro analista.",
            "Mantieni il contesto dell'indagine nella prossima sessione analista.",
            "Riassumi il record per il personale SOC del turno in ingresso.",
            "Separa i fatti registrati dalla guida nel passaggio di consegne.",
            "What context and checks must the receiving analyst know at handover?",
            "What should an incoming analyst know and check?",
            "What should the receiving analyst know and verify?",
            "What should the next analyst know and verify during handover?",
            "Brief the next analyst on what is known and what still requires verification.",
            "Preserve the context and open checks that must carry into the next analyst session.",
            "Prepare continuity context so a different analyst can resume this investigation.",
            "Prepare the investigation context so the next analyst can continue.",
            "Prepare the current record for continuity of investigation.",
            "Quali fatti e verifiche deve ricevere l'analista subentrante?",
            "Che cosa deve conoscere e controllare l'analista subentrante?",
            "Trasferisci alla prossima sessione il contesto noto e le verifiche ancora aperte.",
            "Riassumi per il prossimo analista cosa e noto e cosa resta da verificare.",
            "Prepara il contesto affinche un altro analista continui l'indagine.",
            "Prepara questo record per assicurare la continuita dell'indagine.",
        ),
    ),
    IntentDescriptor(
        AnswerIntent.EXECUTIVE_SUMMARY,
        "Provide a concise leadership-oriented summary of operational impact and current handling state.",
        (
            "Give leadership an executive summary.",
            "Prepara una sintesi per il management.",
            "Prepare a concise nontechnical security overview for leadership.",
            "Explain operational significance and handling state to management without overstatement.",
            "Prepara una sintesi non tecnica per la direzione.",
            "Descrivi rilevanza operativa e stato di gestione al management senza sovrastime.",
            "State what a SOC manager or decision maker needs to understand.",
            "Summarize known impact boundaries and handling for leadership.",
            "Provide management with status, risk, and uncertainty at a nontechnical level.",
            "Indica cosa deve comprendere un responsabile SOC o decisore.",
            "Riassumi per la leadership i limiti dell'impatto e la gestione corrente.",
            "Presenta al management stato, rischio e incertezza in modo non tecnico.",
            "Provide leadership a concise recap based on authoritative platform evidence.",
            "Provide an executive recap grounded in authoritative system records.",
            "Riassumi stato e impatto per chi prende decisioni senza competenze tecniche.",
            "Riassumi la situazione a un decisore privo di competenze tecniche.",
        ),
    ),
)


@dataclass(frozen=True)
class IntentRoutingConfig:
    minimum_similarity: float = 0.27
    secondary_intent_margin: float = 0.035
    max_selected_intents: int = 2
    degraded_intent: AnswerIntent = AnswerIntent.SUMMARY


class SemanticIntentRouter:
    def __init__(
        self,
        *,
        embedding_provider: IntentEmbeddingProvider | None = None,
        registry: tuple[IntentDescriptor, ...] = INTENT_REGISTRY,
        config: IntentRoutingConfig | None = None,
    ) -> None:
        self._embedding_provider = (
            embedding_provider or get_shared_semantic_embedding_provider()
        )
        self._registry = registry
        self._config = config or IntentRoutingConfig()
        self._vectors: dict[AnswerIntent, tuple[tuple[float, ...], ...]] = {}
        self._lock = threading.Lock()

    @property
    def descriptor_cache_size(self) -> int:
        with self._lock:
            return len(self._vectors)

    def _ensure_vectors(self) -> None:
        with self._lock:
            if len(self._vectors) == len(self._registry):
                return
            self._vectors = {
                item.intent: tuple(
                    tuple(
                        float(value)
                        for value in self._embedding_provider.embed(
                            normalize_embedding_text(prototype)
                        )
                    )
                    for prototype in item.prototype_embedding_texts
                )
                for item in self._registry
            }

    def warm(self) -> bool:
        try:
            self._ensure_vectors()
        except Exception:
            return False
        return True

    def _degraded(
        self,
        *,
        started: float,
        clock: Callable[[], float],
        status: str,
    ) -> IntentSelection:
        return IntentSelection(
            primary_intent=self._config.degraded_intent,
            confidence=0.0,
            routing_status=status,
            degraded=status == "embedding_unavailable",
            routing_ms=max(0.0, (clock() - started) * 1000),
        )

    def route(
        self,
        analyst_question: str,
        *,
        request_embedding: Sequence[float] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> IntentSelection:
        started = clock()
        question = normalize_embedding_text(analyst_question)
        if not question:
            return self._degraded(started=started, clock=clock, status="empty_question")
        try:
            self._ensure_vectors()
            vector = (
                tuple(float(value) for value in request_embedding)
                if request_embedding is not None
                else self._embedding_provider.embed(question)
            )
            ranked = sorted(
                (
                    (
                        item.intent,
                        max(
                            cosine_similarity(vector, prototype_vector)
                            for prototype_vector in self._vectors[item.intent]
                        ),
                    )
                    for item in self._registry
                ),
                key=lambda item: (-item[1], item[0].value),
            )
        except Exception:
            return self._degraded(
                started=started,
                clock=clock,
                status="embedding_unavailable",
            )
        scores = [IntentScore(intent=intent, similarity=score) for intent, score in ranked]
        primary, confidence = ranked[0]
        if confidence < self._config.minimum_similarity:
            return IntentSelection(
                primary_intent=self._config.degraded_intent,
                scores=scores,
                confidence=confidence,
                routing_status="low_confidence",
                routing_ms=max(0.0, (clock() - started) * 1000),
            )
        secondary = [
            intent
            for intent, score in ranked[1:]
            if score >= self._config.minimum_similarity
            and confidence - score <= self._config.secondary_intent_margin
        ][: max(0, self._config.max_selected_intents - 1)]
        return IntentSelection(
            primary_intent=primary,
            secondary_intents=secondary,
            scores=scores,
            confidence=confidence,
            routing_status="ok",
            routing_ms=max(0.0, (clock() - started) * 1000),
        )


_DEFAULT_INTENT_ROUTER = SemanticIntentRouter()


def neutral_intent_selection(
    *,
    degraded: bool = True,
    routing_status: str = "embedding_unavailable",
) -> IntentSelection:
    return IntentSelection(
        primary_intent=AnswerIntent.SUMMARY,
        confidence=0.0,
        routing_status=routing_status,
        degraded=degraded,
        routing_ms=0.0,
    )


def get_semantic_intent_router() -> SemanticIntentRouter:
    return _DEFAULT_INTENT_ROUTER
