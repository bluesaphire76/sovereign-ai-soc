"""
AI governance shared models, validators, and policy primitives.
"""

from ai_governance.models import (
    AIEvidenceCoverage,
    AIGovernanceAssessment,
    AIGovernanceSeverity,
    AIGovernanceStatus,
    AIRemediationGovernanceAssessment,
    AIPresentationSafetyLabel,
    AIClaimClassification,
)
from ai_governance.validators import assess_claim_governance, assess_remediation_plan_governance

__all__ = [
    "AIEvidenceCoverage",
    "AIGovernanceAssessment",
    "AIGovernanceSeverity",
    "AIGovernanceStatus",
    "AIRemediationGovernanceAssessment",
    "AIPresentationSafetyLabel",
    "AIClaimClassification",
    "assess_claim_governance",
    "assess_output_governance",
    "assess_remediation_output_governance",
    "assess_remediation_plan_governance",
    "is_safe_to_present_as_evidence_backed",
    "requires_visible_human_review",
    "should_block_as_fact",
]

from ai_governance.policy import (
    assess_output_governance,
    assess_remediation_output_governance,
    is_safe_to_present_as_evidence_backed,
    requires_visible_human_review,
    should_block_as_fact,
)
