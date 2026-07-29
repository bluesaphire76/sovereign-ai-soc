import { AlertTriangle, CheckCircle2, Clock3, Server } from "lucide-react";

import type { AssistantQueryResponse } from "@/lib/assistant";
import AssistantSources from "./AssistantSources";
import {
  formatAssistantLatency,
  humanizeAssistantValue,
  sourceAnchorId,
  tokenizeAssistantAnswer,
} from "./assistantPresentation";

type AssistantAnswerProps = {
  response: AssistantQueryResponse;
  anchorPrefix: string;
};

function safeMetadataValue(value: string | null) {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return null;
  if (
    trimmed.startsWith("/") ||
    trimmed.startsWith("./") ||
    trimmed.startsWith("../") ||
    trimmed.includes("\\") ||
    /[\u0000-\u001f\u007f]/.test(trimmed)
  ) {
    return null;
  }
  return trimmed.slice(0, 160);
}

export default function AssistantAnswer({
  response,
  anchorPrefix,
}: AssistantAnswerProps) {
  const tokens = tokenizeAssistantAnswer(response.answer, response.sources);
  const latency = formatAssistantLatency(response.metadata.latency_ms);
  const provider =
    safeMetadataValue(response.metadata.provider_key) ??
    safeMetadataValue(response.metadata.provider_type);
  const profile = safeMetadataValue(response.metadata.profile);
  const model = safeMetadataValue(response.metadata.model);
  const isFallback = response.status === "fallback" || response.metadata.fallback_used;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-slate-800 pb-3">
        <span
          className={`inline-flex items-center gap-1.5 text-xs font-semibold ${
            response.status === "success"
              ? "text-emerald-300"
              : response.status === "fallback"
                ? "text-amber-300"
                : "text-red-300"
          }`}
        >
          {response.status === "success" ? (
            <CheckCircle2 aria-hidden="true" className="h-3.5 w-3.5" />
          ) : (
            <AlertTriangle aria-hidden="true" className="h-3.5 w-3.5" />
          )}
          {humanizeAssistantValue(response.status).toUpperCase()}
        </span>
        {provider ? (
          <span
            className="inline-flex min-w-0 items-center gap-1.5 text-[11px] text-slate-400"
            title={provider}
          >
            <Server aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />
            <span className="max-w-56 truncate">{provider}</span>
          </span>
        ) : null}
        {profile ? (
          <span className="max-w-48 truncate text-[11px] text-slate-400" title={profile}>
            Profile: {profile}
          </span>
        ) : null}
        {model ? (
          <span className="max-w-64 truncate text-[11px] text-slate-400" title={model}>
            Model: {model}
          </span>
        ) : null}
        {latency ? (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-slate-400">
            <Clock3 aria-hidden="true" className="h-3.5 w-3.5" />
            {latency}
          </span>
        ) : null}
        <span className="text-[11px] text-slate-400">
          {response.sources.length} source{response.sources.length === 1 ? "" : "s"}
        </span>
        {isFallback ? (
          <span className="text-[11px] font-medium text-amber-300">
            Deterministic fallback used
          </span>
        ) : null}
      </div>

      <div>
        <h3 className="text-sm font-semibold text-slate-100">Assistant response</h3>
        {response.answer.trim() ? (
          <p className="mt-2 whitespace-pre-wrap break-words text-sm leading-6 text-slate-300">
            {tokens.map((token, index) =>
              token.kind === "text" ? (
                <span key={`text-${index}`}>{token.value}</span>
              ) : (
                <a
                  key={`citation-${token.source.source_id}-${index}`}
                  href={`#${sourceAnchorId(anchorPrefix, token.sourceIndex)}`}
                  className="font-semibold text-cyan-300 underline decoration-cyan-800 underline-offset-2 hover:text-cyan-200"
                  aria-label={`View source ${token.source.source_id}: ${token.source.label}`}
                  title={token.source.label}
                >
                  {token.value}
                </a>
              ),
            )}
          </p>
        ) : (
          <p className="mt-2 text-xs leading-5 text-slate-500">
            The assistant returned no narrative answer. Review the normalized
            sources and limitations below.
          </p>
        )}
      </div>

      {response.limitations.length > 0 ? (
        <section
          aria-labelledby={`${anchorPrefix}-limitations-heading`}
          className="border-l-2 border-amber-700 bg-amber-950/20 px-3 py-2"
        >
          <h4
            id={`${anchorPrefix}-limitations-heading`}
            className="text-xs font-semibold text-amber-200"
          >
            Limitations
          </h4>
          <ul className="mt-1 space-y-1 text-xs leading-5 text-amber-100/80">
            {response.limitations.map((limitation, index) => (
              <li key={`${limitation}-${index}`}>{limitation}</li>
            ))}
          </ul>
        </section>
      ) : null}

      <AssistantSources sources={response.sources} anchorPrefix={anchorPrefix} />
    </div>
  );
}
