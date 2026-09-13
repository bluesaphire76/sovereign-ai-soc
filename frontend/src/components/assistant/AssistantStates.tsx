"use client";

import { AlertTriangle, Loader2, RefreshCw } from "lucide-react";

import { EnterpriseBadge, EnterpriseButton } from "@/components/enterprise";
import type {
  AssistantScope,
  NormalizedAssistantError,
} from "@/lib/assistant";

const FAILURE_TITLES: Record<NormalizedAssistantError["kind"], string> = {
  aborted: "Request cancelled",
  validation: "Request needs review",
  unauthorized: "Session unavailable",
  forbidden: "Assistant access restricted",
  not_found: "Context unavailable",
  disabled: "Assistant disabled",
  unavailable: "Generation unavailable",
  unknown: "Request failed safely",
};

type AssistantFailureStateProps = {
  error: NormalizedAssistantError;
  scope: AssistantScope;
  onRetry?: () => void | Promise<void>;
};

export function AssistantFailureState({
  error,
  scope,
  onRetry,
}: AssistantFailureStateProps) {
  const retryAvailable = error.retryable && Boolean(onRetry);

  return (
    <div
      role="alert"
      className="border-l-2 border-amber-700 bg-amber-950/20 px-3 py-3 text-xs leading-5 text-amber-100"
    >
      <div className="flex items-start gap-2">
        <AlertTriangle
          aria-hidden="true"
          className="mt-0.5 h-4 w-4 shrink-0 text-amber-300"
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="font-semibold">{FAILURE_TITLES[error.kind]}</p>
            <EnterpriseBadge tone="warning" size="compact">
              No answer published
            </EnterpriseBadge>
          </div>
          <p className="mt-1 break-words text-amber-100/90">{error.message}</p>
          <dl className="mt-2 grid gap-x-4 gap-y-1 text-[11px] text-amber-100/70 sm:grid-cols-3">
            <div>
              <dt className="font-medium text-amber-200">Usable result</dt>
              <dd>None returned</dd>
            </div>
            <div>
              <dt className="font-medium text-amber-200">Fallback</dt>
              <dd>No fallback answer returned</dd>
            </div>
            <div>
              <dt className="font-medium text-amber-200">Retry</dt>
              <dd>{retryAvailable ? "Available" : "Not recommended"}</dd>
            </div>
          </dl>
          <p className="mt-2 text-[11px] text-slate-400">
            No {scope} state was changed.
          </p>
          {retryAvailable ? (
            <EnterpriseButton
              onClick={() => void onRetry?.()}
              tone="secondary"
              size="xs"
              icon={<RefreshCw aria-hidden="true" className="h-3.5 w-3.5" />}
              className="mt-3"
            >
              Try again
            </EnterpriseButton>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function AssistantGenerationState({ scope }: { scope: AssistantScope }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex min-h-10 items-start gap-2 text-xs leading-5 text-slate-400"
    >
      <Loader2
        aria-hidden="true"
        className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-cyan-300"
      />
      <div>
        <p className="font-medium text-slate-300">Preparing governed analysis</p>
        <p>
          Validating {scope} scope and evidence before publishing the response.
        </p>
      </div>
    </div>
  );
}
