from __future__ import annotations

from enum import Enum

from pydantic import Field

from services.assistant.v3.contracts import ClosedModel


class SemanticProofModelStatus(str, Enum):
    REJECTED_AS_SOLE_GATE = "REJECTED_AS_SOLE_GATE"
    SELECTED_HYBRID_GATE = "SELECTED_HYBRID_GATE"


class SemanticProofModelSpec(ClosedModel):
    model_id: str = Field(min_length=1, max_length=240)
    revision: str = Field(min_length=40, max_length=40)
    license: str = Field(min_length=1, max_length=40)
    local_path: str = Field(min_length=1, max_length=500)
    weight_file: str = Field(min_length=1, max_length=120)
    weight_size_bytes: int = Field(gt=0)
    weight_sha256: str = Field(min_length=64, max_length=64)
    status: SemanticProofModelStatus


MDEBERTA_V3_BASE = SemanticProofModelSpec(
    model_id="MoritzLaurer/mDeBERTa-v3-base-mnli-xnli",
    revision="8adb042d524ecd5c26d3e3ba0e3fbcf7e2d0864c",
    license="MIT",
    local_path=(
        "/opt/ai-soc/models/semantic-proof/mdeberta-v3-base-mnli-xnli"
    ),
    weight_file="model.safetensors",
    weight_size_bytes=557_652_046,
    weight_sha256=(
        "65af59b1ff4450b09ecbf13ca35c840dbf038b26ff8e10e5ea89ca724828ed1e"
    ),
    status=SemanticProofModelStatus.REJECTED_AS_SOLE_GATE,
)


MULTILINGUAL_MINILMV2_L6 = SemanticProofModelSpec(
    model_id="MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli",
    revision="0a71e92a985b6e1ad1828cf67ce9c459639c1dca",
    license="MIT",
    local_path=(
        "/opt/ai-soc/models/semantic-proof/multilingual-minilmv2-l6-mnli-xnli"
    ),
    weight_file="model.safetensors",
    weight_size_bytes=427_997_022,
    weight_sha256=(
        "91b323ccf247ec1e3b5925d566230bae7c52de8147e6062b42e250089a3fc80b"
    ),
    status=SemanticProofModelStatus.SELECTED_HYBRID_GATE,
)


SEMANTIC_PROOF_MODEL_CANDIDATES = (
    MDEBERTA_V3_BASE,
    MULTILINGUAL_MINILMV2_L6,
)
