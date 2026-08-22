"""Typed hybrid semantic proof system for Assistant V3.2."""

from services.assistant.v3.semantic_proof.compiler import EvidenceProofUnitCompiler
from services.assistant.v3.semantic_proof.contracts import (
    AllowedSemanticRole,
    EntailmentDecision,
    EntailmentLabel,
    EntailmentPair,
    EntailmentProvider,
    EvidenceKind,
    EvidenceProofUnit,
    HypothesisFragment,
    PremiseLanguage,
    ProofPredicate,
    ProofScope,
    ProofScopeKind,
    ProofValue,
    SemanticProofResult,
)
from services.assistant.v3.semantic_proof.evaluation import SemanticProofEvaluator
from services.assistant.v3.semantic_proof.guards import TypedSemanticGuard
from services.assistant.v3.semantic_proof.hybrid import HybridSemanticProofEvaluator

__all__ = [
    "AllowedSemanticRole",
    "EntailmentDecision",
    "EntailmentLabel",
    "EntailmentPair",
    "EntailmentProvider",
    "EvidenceKind",
    "EvidenceProofUnit",
    "EvidenceProofUnitCompiler",
    "HypothesisFragment",
    "HybridSemanticProofEvaluator",
    "PremiseLanguage",
    "ProofPredicate",
    "ProofScope",
    "ProofScopeKind",
    "ProofValue",
    "SemanticProofResult",
    "SemanticProofEvaluator",
    "TypedSemanticGuard",
]
