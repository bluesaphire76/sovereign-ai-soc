import type { AssistantCapabilities } from "@/lib/assistant";
import { SOC_CONTROL_CLASSES, cx } from "@/lib/semantic-styles";
import { humanizeAssistantValue } from "./assistantPresentation";

type AssistantCapabilityDetailsProps = {
  capabilities: AssistantCapabilities;
  className?: string;
};

function shown(value: string | null | undefined) {
  return value ? humanizeAssistantValue(value) : "N/A";
}

function yesNo(value: boolean) {
  return value ? "Yes" : "No";
}

export default function AssistantCapabilityDetails({
  capabilities,
  className,
}: AssistantCapabilityDetailsProps) {
  const details = [
    { label: "Feature key", value: capabilities.feature_key },
    { label: "Enabled", value: yesNo(capabilities.enabled) },
    { label: "Runtime state", value: shown(capabilities.runtime_state) },
    { label: "Runtime message", value: shown(capabilities.runtime_message) },
    { label: "Default profile", value: shown(capabilities.default_profile) },
    { label: "Loaded profile", value: shown(capabilities.loaded_profile) },
    {
      label: "Supported scopes",
      value: capabilities.supported_scopes.map(humanizeAssistantValue).join(", "),
    },
    {
      label: "Supported modes",
      value: capabilities.supported_modes.map(humanizeAssistantValue).join(", "),
    },
    {
      label: "Persistent conversations",
      value: yesNo(capabilities.persistent_conversations),
    },
    { label: "Streaming", value: yesNo(capabilities.streaming) },
    {
      label: "Project documentation indexed",
      value: yesNo(capabilities.project_documentation_indexed),
    },
    {
      label: "Semantic memory supported",
      value: yesNo(capabilities.semantic_memory_supported),
    },
    {
      label: "Write actions supported",
      value: yesNo(capabilities.write_actions_supported),
    },
    {
      label: "Semantic runtime state",
      value: shown(capabilities.semantic_runtime_state),
    },
    { label: "Embedding backend", value: shown(capabilities.embedding_backend) },
    {
      label: "Embedding cache state",
      value: shown(capabilities.embedding_cache_state),
    },
    {
      label: "Semantic proof runtime",
      value: shown(capabilities.semantic_proof_runtime_state),
    },
    {
      label: "Semantic proof model",
      value: shown(capabilities.semantic_proof_model),
    },
    {
      label: "Semantic proof revision",
      value: shown(capabilities.semantic_proof_revision),
    },
    { label: "Decision boundary", value: capabilities.decision_boundary },
  ];

  return (
    <details className={cx("border-t border-slate-800 pt-2", className)}>
      <summary
        className={cx(
          "w-fit cursor-pointer rounded-sm text-[11px] font-medium text-slate-500 hover:text-slate-300",
          SOC_CONTROL_CLASSES.focus,
        )}
      >
        Runtime details
      </summary>
      <dl className="mt-3 grid gap-x-5 gap-y-2 text-[11px] text-slate-500 sm:grid-cols-2 xl:grid-cols-3">
        {details.map((detail) => (
          <div key={detail.label} className="min-w-0">
            <dt>{detail.label}</dt>
            <dd className="mt-0.5 break-words text-slate-300">{detail.value}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
