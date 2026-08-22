from __future__ import annotations

import inspect
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Sequence

import pytest
from pydantic import ValidationError

from scripts import benchmark_assistant_v32_semantic_proof as benchmark_harness
from services.assistant.v3.contracts import (
    AuthorityClass,
    CompromiseStateAtom,
    SourceRegistryEntry,
    StatusAtom,
)
from services.assistant.v3.semantic_proof.compiler import EvidenceProofUnitCompiler
from services.assistant.v3.semantic_proof.contracts import (
    AllowedSemanticRole,
    EntailmentDecision,
    EntailmentDecisionReason,
    EntailmentLabel,
    EntailmentPair,
    EntailmentProviderInfo,
    EvidenceKind,
    EvidenceProofUnit,
    HypothesisFragment,
    ProofPredicate,
)
from services.assistant.v3.semantic_proof.corpus import (
    GoldenProofCategory,
    build_golden_proof_corpus,
)
from services.assistant.v3.semantic_proof.evaluation import SemanticProofEvaluator
from services.assistant.v3.semantic_proof.guards import (
    TypedGuardReason,
    TypedSemanticGuard,
)
from services.assistant.v3.semantic_proof.hybrid import (
    HybridProofReason,
    HybridSemanticProofEvaluator,
)
from services.assistant.v3.semantic_proof.models import (
    MDEBERTA_V3_BASE,
    MULTILINGUAL_MINILMV2_L6,
    SemanticProofModelStatus,
)
from services.assistant.v3.semantic_proof.provider import (
    TransformersNliProvider,
    normalize_entailment_label,
)
from services.assistant.v3.semantic_proof.runtime import (
    UnavailableEntailmentProvider,
    get_semantic_proof_provider,
    get_semantic_proof_runtime_settings,
    reset_semantic_proof_runtime_for_tests,
    semantic_proof_runtime_snapshot,
)
from tests.assistant_v3_test_support import analytical_package, operational_provenance


REPO_ROOT = Path(__file__).resolve().parents[1]


def _unit_for(
    units: Sequence[EvidenceProofUnit],
    source_ref: str,
    language: str = "en",
) -> EvidenceProofUnit:
    return next(
        item
        for item in units
        if source_ref in item.source_refs and item.premise_language == language
    )


class _StaticProvider:
    def __init__(
        self,
        labels: dict[str, EntailmentLabel] | None = None,
        *,
        fail: bool = False,
        drop_last: bool = False,
    ) -> None:
        self._labels = labels or {}
        self._fail = fail
        self._drop_last = drop_last

    @property
    def info(self) -> EntailmentProviderInfo:
        return EntailmentProviderInfo(
            backend="static_test",
            model="none",
            precision="none",
            quantization="none",
            device="none",
        )

    def evaluate(
        self,
        pairs: Sequence[EntailmentPair],
        *,
        batch_size: int,
    ) -> Sequence[EntailmentDecision]:
        del batch_size
        if self._fail:
            raise RuntimeError("provider failed")
        selected = pairs[:-1] if self._drop_last else pairs
        result = []
        for pair in selected:
            label = self._labels.get(pair.hypothesis_id, EntailmentLabel.NEUTRAL)
            accepted = label is EntailmentLabel.ENTAILMENT
            result.append(
                EntailmentDecision(
                    pair_id=pair.pair_id,
                    proof_unit_id=pair.proof_unit_id,
                    hypothesis_id=pair.hypothesis_id,
                    label=label,
                    entailment_score=1.0 if accepted else 0.0,
                    neutral_score=1.0 if label is EntailmentLabel.NEUTRAL else 0.0,
                    contradiction_score=(
                        1.0 if label is EntailmentLabel.CONTRADICTION else 0.0
                    ),
                    accepted=accepted,
                    reason=(
                        EntailmentDecisionReason.ENTAILED
                        if accepted
                        else EntailmentDecisionReason.NOT_ENTAILED
                    ),
                )
            )
        return result


def test_semantic_proof_contracts_are_closed_and_authority_typed() -> None:
    unit = build_golden_proof_corpus()[0].proof_unit
    payload = unit.model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        EvidenceProofUnit.model_validate(payload)

    payload.pop("unexpected")
    payload["authority_class"] = AuthorityClass.REFERENCE_KNOWLEDGE.value
    with pytest.raises(ValidationError):
        EvidenceProofUnit.model_validate(payload)

    with pytest.raises(ValidationError):
        EntailmentDecision(
            pair_id="pair:1",
            proof_unit_id=unit.proof_unit_id,
            hypothesis_id="hypothesis:1",
            label=EntailmentLabel.NEUTRAL,
            accepted=True,
            reason=EntailmentDecisionReason.ENTAILED,
        )


def test_semantic_model_manifest_is_pinned_and_records_rejection_boundary() -> None:
    assert len(MULTILINGUAL_MINILMV2_L6.revision) == 40
    assert len(MULTILINGUAL_MINILMV2_L6.weight_sha256) == 64
    assert MULTILINGUAL_MINILMV2_L6.license == "MIT"
    assert MULTILINGUAL_MINILMV2_L6.status is (
        SemanticProofModelStatus.SELECTED_HYBRID_GATE
    )
    assert MDEBERTA_V3_BASE.status is (
        SemanticProofModelStatus.REJECTED_AS_SOLE_GATE
    )


def test_semantic_runtime_is_gpu_only_offline_and_fails_closed(monkeypatch) -> None:
    reset_semantic_proof_runtime_for_tests()
    monkeypatch.setenv("AI_SOC_ASSISTANT_V32_NLI_DEVICE", "cpu")
    with pytest.raises(ValueError, match="GPU-only"):
        get_semantic_proof_runtime_settings()

    monkeypatch.setenv("AI_SOC_ASSISTANT_V32_NLI_DEVICE", "cuda:0")
    monkeypatch.setenv(
        "AI_SOC_ASSISTANT_V32_NLI_MODEL_PATH",
        "/tmp/not-the-pinned-model",
    )
    provider = get_semantic_proof_provider()
    snapshot = semantic_proof_runtime_snapshot()

    assert isinstance(provider, UnavailableEntailmentProvider)
    assert snapshot["state"] == "unavailable"
    assert snapshot["safe_error"] == "RuntimeError"
    runtime_source = inspect.getsource(sys.modules[provider.__module__])
    assert "local_files_only=True" in runtime_source
    assert "from_pretrained" not in runtime_source
    reset_semantic_proof_runtime_for_tests()


def test_compiler_preserves_literal_values_without_semantic_expansion() -> None:
    package = analytical_package()
    units = EvidenceProofUnitCompiler().compile(package)

    status = _unit_for(units, "incident:1:status")
    mitre = _unit_for(units, "incident:1:mitre:T1112")
    correlation_units = [
        item
        for item in units
        if "incident:1:recorded-correlation" in item.source_refs
        and item.premise_language == "en"
        and item.predicate is ProofPredicate.RECORDED_CORRELATION_STATE
    ]

    assert status.canonical_premise == "Incident 1 status recorded as OPEN."
    assert status.predicate is ProofPredicate.STATUS
    assert status.value.canonical_values == ["OPEN"]
    assert status.value.required_anchors == ["OPEN"]
    assert mitre.canonical_premise == (
        "Incident 1 recorded MITRE technique: T1112: Modify Registry."
    )
    assert {item.canonical_premise for item in correlation_units} == {
        (
            "Incident 1 recorded correlation state: flag true; "
            "type endpoint_pattern; score 75."
        ),
    }
    assert correlation_units[0].predicate is (
        ProofPredicate.RECORDED_CORRELATION_STATE
    )
    assert correlation_units[0].value.canonical_values == [
        "true",
        "endpoint_pattern",
        "75",
    ]
    compiled = " ".join(item.canonical_premise.lower() for item in correlation_units)
    assert "other events" not in compiled
    assert "malicious" not in compiled
    assert "caused" not in compiled


def test_typed_guard_preserves_supported_facts_and_blocks_known_false_accepts() -> None:
    cases = build_golden_proof_corpus()
    guard = TypedSemanticGuard()
    supported_rejects = [
        item.case_id
        for item in cases
        if item.expected_accept
        and not guard.evaluate(item.proof_unit, item.hypothesis).accepted
    ]
    known_false_accept_keys = {
        "low_threat_interpretation:it_it",
        "low_threat_interpretation:en_it",
        "host_contradiction:it_it",
        "host_contradiction:en_it",
        "lateral_movement:it_it",
        "urgency:it_it",
        "urgency:en_it",
        "semantic_similarity_promotion:it_it",
        "semantic_similarity_promotion:en_it",
    }
    guard_results = {
        item.case_id: guard.evaluate(item.proof_unit, item.hypothesis)
        for item in cases
        if item.case_id in known_false_accept_keys
    }

    assert supported_rejects == []
    assert set(guard_results) == known_false_accept_keys
    assert all(not item.accepted for item in guard_results.values())
    assert {
        item.reason for item in guard_results.values()
    } <= {
        TypedGuardReason.MISSING_REQUIRED_ANCHOR,
        TypedGuardReason.INCOMPATIBLE_SEMANTIC_CONCEPT,
    }


def test_hybrid_evaluator_requires_typed_guard_and_entailment() -> None:
    cases = build_golden_proof_corpus()
    pairs = [
        EntailmentPair(
            pair_id=item.case_id,
            proof_unit_id=item.proof_unit.proof_unit_id,
            premise=item.proof_unit.canonical_premise,
            premise_language=item.proof_unit.premise_language,
            hypothesis_id=item.case_id,
            hypothesis=item.hypothesis,
            hypothesis_language=item.hypothesis_language,
        )
        for item in cases
    ]
    labels = {item.case_id: item.expected_label for item in cases}
    proof_units = {
        item.proof_unit.proof_unit_id: item.proof_unit for item in cases
    }
    result = HybridSemanticProofEvaluator(_StaticProvider(labels)).evaluate(
        proof_units=list(proof_units.values()),
        pairs=pairs,
        batch_size=8,
    )
    expected_by_id = {item.case_id: item.expected_accept for item in cases}

    assert {
        item.pair_id: item.accepted for item in result.decisions
    } == expected_by_id
    assert result.typed_guard_reject_count == 129
    assert result.provider_pair_count == 6
    assert all(
        item.reason is HybridProofReason.TYPED_GUARD_REJECTED
        for item in result.decisions
        if item.pair_id.startswith("low_threat_interpretation")
    )


def test_compiler_preserves_authority_roles_and_relationship_distinctions() -> None:
    units = EvidenceProofUnitCompiler().compile(analytical_package())
    operational = _unit_for(units, "incident:1:status")
    analytical = _unit_for(units, "relationship:shared-host")
    semantic = _unit_for(units, "relationship:semantic")
    reference = _unit_for(units, "reference:mitre:T1112", "und")
    advisory = _unit_for(units, "advisory:registry-review", "und")

    assert (
        operational.authority_class,
        operational.evidence_kind,
        operational.allowed_semantic_role,
    ) == (
        AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        EvidenceKind.OPERATIONAL_FACT,
        AllowedSemanticRole.RECORDED_VALUE,
    )
    assert (
        analytical.authority_class,
        analytical.evidence_kind,
        analytical.allowed_semantic_role,
    ) == (
        AuthorityClass.ANALYTICAL_DERIVATION,
        EvidenceKind.ANALYTICAL_RELATIONSHIP,
        AllowedSemanticRole.ANALYTICAL_COMPARISON,
    )
    assert semantic.authority_class is AuthorityClass.SEMANTIC_CANDIDATE
    assert semantic.evidence_kind is EvidenceKind.SEMANTIC_CANDIDATE
    assert reference.authority_class is AuthorityClass.REFERENCE_KNOWLEDGE
    assert advisory.authority_class is AuthorityClass.ADVISORY_KNOWLEDGE
    assert reference.canonical_premise.endswith("T1112 = Modify Registry.")
    assert advisory.canonical_premise.endswith(
        "Review registry and adjacent process telemetry."
    )
    assert "caus" not in analytical.canonical_premise.lower()
    assert "correlation" not in semantic.canonical_premise.lower()


def test_compiler_keeps_records_isolated_and_drops_out_of_scope_atoms() -> None:
    package = analytical_package()
    rogue_provenance = operational_provenance(999)
    rogue = StatusAtom(
        atom_id="incident:999:status",
        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        provenance=rogue_provenance,
        incident_id=999,
        status="CLOSED",
        canonical_severity=None,
    )
    package = package.model_copy(
        update={
            "operational_atoms": [*package.operational_atoms, rogue],
            "source_registry": [
                *package.source_registry,
                SourceRegistryEntry(
                    source_ref=rogue.atom_id,
                    authority_class=rogue.authority_class,
                    source_type="incident",
                    source_record_id="999",
                ),
            ],
        }
    )
    units = EvidenceProofUnitCompiler().compile(package)

    assert not any("incident:999:status" in item.source_refs for item in units)
    assert {
        tuple(item.scope.incident_ids)
        for item in units
        if item.evidence_kind is EvidenceKind.OPERATIONAL_FACT
        and item.scope.incident_ids
    } <= {(1,), (2,)}
    assert _unit_for(units, "relationship:shared-host").scope.incident_ids == [1, 2]


def test_compiler_does_not_materialize_unknown_compromise_state() -> None:
    package = analytical_package()
    atom = CompromiseStateAtom(
        atom_id="incident:1:compromise-state",
        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        provenance=operational_provenance(1),
        incident_id=1,
        compromise_confirmed=None,
    )
    package = package.model_copy(
        update={
            "operational_atoms": [*package.operational_atoms, atom],
            "source_registry": [
                *package.source_registry,
                SourceRegistryEntry(
                    source_ref=atom.atom_id,
                    authority_class=atom.authority_class,
                    source_type="incident",
                    source_record_id="1",
                ),
            ],
        }
    )

    units = EvidenceProofUnitCompiler().compile(package)

    assert not any(atom.atom_id in item.source_refs for item in units)


def test_golden_corpus_is_closed_bounded_and_covers_every_required_class() -> None:
    cases = build_golden_proof_corpus()

    assert len(cases) == 210
    assert len({item.case_id for item in cases}) == len(cases)
    assert {item.category for item in cases} == set(GoldenProofCategory)
    assert Counter(item.language_pair for item in cases) == {
        "IT_IT": 70,
        "EN_IT": 70,
        "EN_EN": 70,
    }
    assert {item.expected_label for item in cases} == {
        EntailmentLabel.ENTAILMENT,
        EntailmentLabel.NEUTRAL,
        EntailmentLabel.CONTRADICTION,
    }
    assert sum(item.security_critical for item in cases) == 126


@pytest.mark.parametrize(
    ("hypothesis", "expected_label"),
    [
        ("L'incidente non è ancora stato valutato o risolto.", EntailmentLabel.NEUTRAL),
        (
            "L'evento è stato correlato con altri eventi in un intervallo temporale.",
            EntailmentLabel.NEUTRAL,
        ),
        (
            "L'attività non è malevola a causa della correlazione.",
            EntailmentLabel.NEUTRAL,
        ),
        (
            "L'evento è classificato come MITRE T1112 - Modify Registry.",
            EntailmentLabel.ENTAILMENT,
        ),
        (
            "La normalizzazione del rischio registrata è LOW.",
            EntailmentLabel.ENTAILMENT,
        ),
        ("L'incidente rappresenta una minaccia bassa.", EntailmentLabel.NEUTRAL),
        (
            "Lo stato è NEW e l'incidente non è ancora stato investigato.",
            EntailmentLabel.NEUTRAL,
        ),
    ],
)
def test_golden_corpus_contains_mandatory_real_failures(
    hypothesis: str,
    expected_label: EntailmentLabel,
) -> None:
    matching = [
        item
        for item in build_golden_proof_corpus()
        if item.hypothesis == hypothesis
    ]
    assert matching
    assert {item.expected_label for item in matching} == {expected_label}
    assert all(item.expected_accept == (expected_label is EntailmentLabel.ENTAILMENT) for item in matching)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("entailment", EntailmentLabel.ENTAILMENT),
        ("ENTAILED", EntailmentLabel.ENTAILMENT),
        ("neutral", EntailmentLabel.NEUTRAL),
        ("contradiction", EntailmentLabel.CONTRADICTION),
        ("label_0", None),
        ("unknown", None),
    ],
)
def test_provider_label_normalization_is_explicit(raw, expected) -> None:
    assert normalize_entailment_label(raw) is expected


def test_provider_label_index_mapping_rejects_generic_or_incomplete_labels() -> None:
    assert TransformersNliProvider._validated_label_map(
        {0: "entailment", 1: "neutral", 2: "contradiction"}
    ) == {
        0: EntailmentLabel.ENTAILMENT,
        1: EntailmentLabel.NEUTRAL,
        2: EntailmentLabel.CONTRADICTION,
    }
    with pytest.raises(ValueError):
        TransformersNliProvider._validated_label_map(
            {0: "LABEL_0", 1: "LABEL_1", 2: "LABEL_2"}
        )
    with pytest.raises(ValueError):
        TransformersNliProvider._validated_label_map(
            {0: "entailment", 1: "neutral"}
        )


def test_semantic_evaluator_fails_closed_on_provider_failure_or_bad_shape() -> None:
    unit = build_golden_proof_corpus()[0].proof_unit
    fragments = [
        HypothesisFragment(fragment_id="f1", text="The status is NEW.", language="en")
    ]

    failed = SemanticProofEvaluator(_StaticProvider(fail=True)).evaluate(
        proof_units=[unit],
        fragments=fragments,
    )
    malformed = SemanticProofEvaluator(_StaticProvider(drop_last=True)).evaluate(
        proof_units=[unit],
        fragments=fragments,
    )

    assert not failed.accepted
    assert failed.reason == "provider_unavailable"
    assert all(item.label is EntailmentLabel.UNAVAILABLE for item in failed.decisions)
    assert not malformed.accepted
    assert malformed.reason == "invalid_provider_output"


def test_compound_partial_support_requires_every_fragment() -> None:
    unit = build_golden_proof_corpus()[0].proof_unit
    fragments = [
        HypothesisFragment(fragment_id="recorded", text="The status is NEW.", language="en"),
        HypothesisFragment(
            fragment_id="interpretation",
            text="The incident has not been investigated.",
            language="en",
        ),
    ]
    evaluator = SemanticProofEvaluator(
        _StaticProvider(
            {
                "recorded": EntailmentLabel.ENTAILMENT,
                "interpretation": EntailmentLabel.NEUTRAL,
            }
        )
    )

    result = evaluator.evaluate(proof_units=[unit], fragments=fragments)

    assert not result.accepted
    assert result.reason == "fragment_not_entailed"
    assert result.supported_fragment_ids == ["recorded"]


def test_production_proof_compiler_has_no_qdrant_or_router_dependency() -> None:
    compiler_source = inspect.getsource(EvidenceProofUnitCompiler)
    orchestrator = (REPO_ROOT / "services/assistant/orchestrator.py").read_text()
    router = (REPO_ROOT / "routers/assistant.py").read_text()

    assert "qdrant" not in compiler_source.lower()
    assert "semantic_proof" in orchestrator
    assert "semantic_proof" not in router


def test_gpu_harness_help_is_offline_and_qwen_probe_needs_double_opt_in() -> None:
    script = REPO_ROOT / "scripts/benchmark_assistant_v32_semantic_proof.py"
    help_result = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    guarded_result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--model",
            "/local/nli-model",
            "--entailment-threshold",
            "0.8",
            "--measure-qwen-latency",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert help_result.returncode == 0
    assert "GPU-only" in help_result.stdout
    assert guarded_result.returncode != 0
    assert "require both" in guarded_result.stderr
    source = script.read_text()
    assert "systemctl" not in source
    assert "stop-ai-soc" not in source
    assert "start-ai-soc" not in source


@pytest.mark.parametrize(
    ("status_payload", "expected"),
    [
        ({"value": "loaded"}, "resident"),
        ({"value": "loading"}, "warming"),
        ({"value": "unloaded"}, "not_resident"),
        (None, "listed_status_unknown"),
    ],
)
def test_qwen_coexistence_requires_an_explicit_active_router_status(
    monkeypatch,
    status_payload,
    expected,
) -> None:
    monkeypatch.setattr(
        benchmark_harness,
        "_request_json",
        lambda *args, **kwargs: {
            "data": [{"id": "ai-soc-standard", "status": status_payload}]
        },
    )

    assert benchmark_harness._qwen_residency(
        url="http://127.0.0.1:8081/models",
        model="ai-soc-standard",
        api_key="",
        timeout_seconds=1,
    ) == expected


@pytest.mark.parametrize(
    ("unavailable", "coexistence", "false_accepts", "expected"),
    [
        (1, True, 0, ("provider_failed_closed", 2)),
        (0, False, 0, ("completed_coexistence_not_verified", 2)),
        (0, True, 1, ("completed", 1)),
        (0, True, 0, ("completed", 0)),
    ],
)
def test_gpu_harness_outcome_fails_closed(
    unavailable,
    coexistence,
    false_accepts,
    expected,
) -> None:
    assert benchmark_harness._benchmark_outcome(
        unavailable_count=unavailable,
        coexistence_verified=coexistence,
        security_critical_false_accept_count=false_accepts,
    ) == expected
