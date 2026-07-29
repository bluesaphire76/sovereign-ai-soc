"use client";

import {
  AlertTriangle,
  Bot,
  Database,
  Loader2,
  RefreshCw,
  Send,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from "react";

import {
  ASSISTANT_MESSAGE_MAX_LENGTH,
  fetchAssistantCapabilities,
  normalizeAssistantApiError,
  submitAssistantQuery,
  type AssistantCapabilities,
  type AssistantMode,
  type AssistantQueryResponse,
  type ContextualAssistantScope,
  type NormalizedAssistantError,
} from "@/lib/assistant";
import AssistantAnswer from "./AssistantAnswer";
import {
  ASSISTANT_MODE_OPTIONS,
  ASSISTANT_SUGGESTIONS,
} from "./assistantPresentation";

type ContextualAssistantPanelProps = {
  scope: ContextualAssistantScope;
  targetId: number;
  targetLabel: string;
  userRole?: string | null;
};

function capabilityBadge(
  loading: boolean,
  capabilities: AssistantCapabilities | null,
  error: NormalizedAssistantError | null,
  scopeSupported: boolean,
  runtimeDisabled: boolean,
) {
  if (loading) {
    return {
      label: "CHECKING",
      className: "border-cyan-900 text-cyan-300",
    };
  }
  if (error?.kind === "forbidden") {
    return {
      label: "RESTRICTED",
      className: "border-red-900 text-red-300",
    };
  }
  if (error || !scopeSupported) {
    return {
      label: "UNAVAILABLE",
      className: "border-amber-900 text-amber-300",
    };
  }
  if (!capabilities?.enabled || runtimeDisabled) {
    return {
      label: "DISABLED",
      className: "border-slate-700 text-slate-400",
    };
  }
  return {
    label: "AVAILABLE",
    className: "border-emerald-800 text-emerald-300",
  };
}

export default function ContextualAssistantPanel(
  props: ContextualAssistantPanelProps,
) {
  const eligible = props.userRole === "ADMIN" || props.userRole === "ANALYST";

  if (!eligible) return null;

  return (
    <ContextualAssistantPanelContent
      key={`${props.scope}:${props.targetId}`}
      {...props}
    />
  );
}

function ContextualAssistantPanelContent({
  scope,
  targetId,
  targetLabel,
}: ContextualAssistantPanelProps) {
  const [capabilities, setCapabilities] = useState<AssistantCapabilities | null>(
    null,
  );
  const [capabilitiesLoading, setCapabilitiesLoading] = useState(true);
  const [capabilityError, setCapabilityError] =
    useState<NormalizedAssistantError | null>(null);
  const [question, setQuestion] = useState("");
  const [mode, setMode] = useState<AssistantMode>("auto");
  const [includeSemanticMemory, setIncludeSemanticMemory] = useState(true);
  const [response, setResponse] = useState<AssistantQueryResponse | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [queryError, setQueryError] =
    useState<NormalizedAssistantError | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const capabilityControllerRef = useRef<AbortController | null>(null);
  const queryControllerRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const responseRef = useRef<HTMLDivElement | null>(null);

  const suggestions = ASSISTANT_SUGGESTIONS[scope];
  const anchorPrefix = `assistant-${scope}-${targetId}`;
  const scopeSupported =
    capabilities?.supported_scopes.includes(scope) ?? true;
  const supportedModes = useMemo(
    () =>
      ASSISTANT_MODE_OPTIONS.filter((option) =>
        capabilities?.supported_modes.includes(option.value),
      ),
    [capabilities],
  );
  const semanticMemorySupported =
    capabilities?.semantic_memory_supported ?? false;
  const runtimeDisabled = queryError?.kind === "disabled";
  const interactionLocked =
    Boolean(capabilityError?.locksInteraction) ||
    Boolean(queryError?.locksInteraction) ||
    runtimeDisabled ||
    !scopeSupported;
  const assistantEnabled =
    Boolean(capabilities?.enabled) && !runtimeDisabled && scopeSupported;
  const controlsDisabled =
    capabilitiesLoading ||
    !assistantEnabled ||
    interactionLocked ||
    submitting;
  const trimmedQuestion = question.trim();
  const canSubmit =
    !controlsDisabled &&
    trimmedQuestion.length > 0 &&
    trimmedQuestion.length <= ASSISTANT_MESSAGE_MAX_LENGTH;
  const badge = capabilityBadge(
    capabilitiesLoading,
    capabilities,
    capabilityError,
    scopeSupported,
    runtimeDisabled,
  );
  const safetyStatement =
    scope === "incident"
      ? "Read-only assistance. This response cannot change severity, status, ownership, case linkage, detection controls, or remediation approval."
      : "Read-only assistance. This response cannot change case status, severity, ownership, actions, closure approval, or remediation decisions.";

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    capabilityControllerRef.current = controller;

    fetchAssistantCapabilities(controller.signal)
      .then((payload) => {
        if (!active) return;
        setCapabilities(payload);
        setCapabilityError(null);
        setIncludeSemanticMemory(payload.semantic_memory_supported);
        setMode(
          payload.supported_modes.includes("auto")
            ? "auto"
            : payload.supported_modes[0] ?? "auto",
        );
      })
      .catch((error: unknown) => {
        if (!active) return;
        const normalized = normalizeAssistantApiError(error, scope);
        if (normalized.kind !== "aborted") {
          setCapabilityError(normalized);
        }
      })
      .finally(() => {
        if (active) {
          setCapabilitiesLoading(false);
        }
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [scope]);

  useEffect(() => {
    mountedRef.current = true;

    return () => {
      mountedRef.current = false;
      capabilityControllerRef.current?.abort();
      queryControllerRef.current?.abort();
    };
  }, []);

  async function handleRetryCapabilities() {
    capabilityControllerRef.current?.abort();
    const controller = new AbortController();
    capabilityControllerRef.current = controller;
    setCapabilitiesLoading(true);
    setCapabilityError(null);

    try {
      const payload = await fetchAssistantCapabilities(controller.signal);
      if (!mountedRef.current || capabilityControllerRef.current !== controller) {
        return;
      }
      setCapabilities(payload);
      setIncludeSemanticMemory(payload.semantic_memory_supported);
      setMode(
        payload.supported_modes.includes("auto")
          ? "auto"
          : payload.supported_modes[0] ?? "auto",
      );
    } catch (error) {
      if (!mountedRef.current || capabilityControllerRef.current !== controller) {
        return;
      }
      const normalized = normalizeAssistantApiError(error, scope);
      if (normalized.kind !== "aborted") {
        setCapabilityError(normalized);
      }
    } finally {
      if (mountedRef.current && capabilityControllerRef.current === controller) {
        setCapabilitiesLoading(false);
      }
    }
  }

  async function handleSubmit(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();

    if (submitting || !assistantEnabled || interactionLocked) return;

    if (!trimmedQuestion) {
      setValidationError("Enter a question before submitting.");
      textareaRef.current?.focus();
      return;
    }

    if (trimmedQuestion.length > ASSISTANT_MESSAGE_MAX_LENGTH) {
      setValidationError(
        `Keep the question within ${ASSISTANT_MESSAGE_MAX_LENGTH} characters.`,
      );
      textareaRef.current?.focus();
      return;
    }

    const controller = new AbortController();
    queryControllerRef.current = controller;
    setSubmitting(true);
    setValidationError(null);
    setQueryError(null);
    setNotice(null);
    setResponse(null);

    try {
      const payload = await submitAssistantQuery(
        {
          message: trimmedQuestion,
          scope,
          incident_id: scope === "incident" ? targetId : null,
          case_id: scope === "case" ? targetId : null,
          requested_mode: mode,
          include_semantic_memory:
            semanticMemorySupported && includeSemanticMemory,
        },
        controller.signal,
      );

      if (!mountedRef.current || queryControllerRef.current !== controller) {
        return;
      }

      setResponse(payload);
      setNotice(
        "Response complete. The question remains available for analyst refinement.",
      );
      window.requestAnimationFrame(() => responseRef.current?.focus());
    } catch (error) {
      if (!mountedRef.current || queryControllerRef.current !== controller) {
        return;
      }
      const normalized = normalizeAssistantApiError(error, scope);
      if (normalized.kind !== "aborted") {
        setQueryError(normalized);
      }
    } finally {
      if (mountedRef.current && queryControllerRef.current === controller) {
        queryControllerRef.current = null;
        setSubmitting(false);
      }
    }
  }

  function handleCancel() {
    const controller = queryControllerRef.current;
    if (!controller) return;

    queryControllerRef.current = null;
    controller.abort();
    setSubmitting(false);
    setNotice(
      `Request cancelled. No ${scope} state was changed and the question was retained.`,
    );
  }

  function handleQuestionChange(value: string) {
    setQuestion(value);
    if (validationError) setValidationError(null);
  }

  function handleSuggestion(suggestion: string) {
    setQuestion(suggestion);
    setValidationError(null);
    textareaRef.current?.focus();
  }

  function handleQuestionKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      void handleSubmit();
    }
  }

  return (
    <section
      aria-labelledby={`${anchorPrefix}-heading`}
      className="min-w-0 border-y border-slate-800 bg-slate-950 py-4"
    >
      <div className="flex min-w-0 flex-col gap-3 px-3 sm:px-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Bot aria-hidden="true" className="h-4 w-4 text-cyan-300" />
            <h2
              id={`${anchorPrefix}-heading`}
              className="text-sm font-semibold text-slate-100"
            >
              SOC Assistant
            </h2>
            <span className="text-xs text-slate-400">{targetLabel}</span>
            <span className="border border-cyan-900 px-1.5 py-0.5 text-[10px] font-semibold text-cyan-300">
              READ ONLY
            </span>
            <span
              className={`border px-1.5 py-0.5 text-[10px] font-semibold ${badge.className}`}
            >
              {badge.label}
            </span>
          </div>
          <p className="mt-2 max-w-4xl text-xs leading-5 text-slate-400">
            Grounded analyst support using authoritative platform records and
            optional advisory semantic memory.
          </p>
          <p className="mt-1 max-w-4xl text-[11px] leading-5 text-slate-500">
            {capabilities?.decision_boundary ??
              "Platform records remain authoritative. AI output supports human review and cannot perform operational actions."}
          </p>
        </div>
      </div>

      {capabilitiesLoading ? (
        <div
          className="mt-4 space-y-2 px-3 sm:px-4"
          aria-live="polite"
          aria-label="Checking SOC Assistant availability"
        >
          <div className="h-3 w-48 animate-pulse bg-slate-800" />
          <div className="h-16 w-full animate-pulse bg-slate-900" />
        </div>
      ) : null}

      {!capabilitiesLoading && capabilityError ? (
        <div
          className={`mx-3 mt-4 border-l-2 px-3 py-2 text-xs leading-5 sm:mx-4 ${
            capabilityError.kind === "forbidden"
              ? "border-red-700 bg-red-950/30 text-red-200"
              : "border-amber-700 bg-amber-950/20 text-amber-100"
          }`}
          role="alert"
        >
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <span>{capabilityError.message}</span>
            {capabilityError.retryable ? (
              <button
                type="button"
                onClick={() => void handleRetryCapabilities()}
                className="inline-flex min-h-8 w-fit items-center gap-1.5 border border-slate-700 bg-slate-900 px-2.5 font-medium text-slate-200 hover:bg-slate-800"
              >
                <RefreshCw aria-hidden="true" className="h-3.5 w-3.5" />
                Retry availability check
              </button>
            ) : null}
          </div>
        </div>
      ) : null}

      {!capabilitiesLoading && capabilities ? (
        <div className="mt-4 space-y-4 px-3 sm:px-4">
          {!capabilities.enabled || runtimeDisabled ? (
            <div
              className="border-l-2 border-slate-600 bg-slate-900/60 px-3 py-2 text-xs leading-5 text-slate-300"
              role="status"
            >
              SOC Assistant is currently disabled. An administrator can enable
              the governed backend capability when runtime validation is complete.
            </div>
          ) : null}

          {!scopeSupported ? (
            <div
              className="border-l-2 border-amber-700 bg-amber-950/20 px-3 py-2 text-xs leading-5 text-amber-100"
              role="alert"
            >
              The configured Assistant does not support {scope} context.
            </div>
          ) : null}

          <form className="space-y-4" onSubmit={handleSubmit}>
            <fieldset disabled={controlsDisabled}>
              <legend className="text-xs font-semibold text-slate-200">
                Suggested questions
              </legend>
              <div className="mt-2 flex flex-wrap gap-2">
                {suggestions.map((suggestion) => (
                  <button
                    key={suggestion}
                    type="button"
                    onClick={() => handleSuggestion(suggestion)}
                    className="min-h-8 max-w-full border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-left text-xs leading-5 text-slate-300 hover:border-cyan-800 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            </fieldset>

            <div>
              <label
                htmlFor={`${anchorPrefix}-question`}
                className="text-xs font-semibold text-slate-200"
              >
                Question for {targetLabel}
              </label>
              <textarea
                ref={textareaRef}
                id={`${anchorPrefix}-question`}
                value={question}
                onChange={(event) => handleQuestionChange(event.target.value)}
                onKeyDown={handleQuestionKeyDown}
                disabled={controlsDisabled}
                maxLength={ASSISTANT_MESSAGE_MAX_LENGTH}
                rows={5}
                aria-describedby={`${anchorPrefix}-question-hint ${
                  validationError ? `${anchorPrefix}-validation` : ""
                }`}
                aria-invalid={Boolean(validationError)}
                placeholder={`Ask a read-only question about this ${scope}.`}
                className="mt-2 min-h-28 w-full resize-y border border-slate-700 bg-slate-950 px-3 py-2 text-sm leading-6 text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
              />
              <div className="mt-1 flex flex-col gap-1 text-[11px] text-slate-500 sm:flex-row sm:items-center sm:justify-between">
                <span id={`${anchorPrefix}-question-hint`}>
                  Press Ctrl+Enter or Cmd+Enter to submit. Enter adds a new line.
                </span>
                <span
                  className={
                    question.length >= ASSISTANT_MESSAGE_MAX_LENGTH
                      ? "font-semibold text-amber-300"
                      : ""
                  }
                >
                  {question.length}/{ASSISTANT_MESSAGE_MAX_LENGTH}
                </span>
              </div>
              {validationError ? (
                <p
                  id={`${anchorPrefix}-validation`}
                  className="mt-2 text-xs text-red-300"
                  role="alert"
                >
                  {validationError}
                </p>
              ) : null}
            </div>

            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(16rem,0.7fr)]">
              <fieldset disabled={controlsDisabled}>
                <legend className="text-xs font-semibold text-slate-200">
                  Response mode
                </legend>
                <div className="mt-2 grid gap-px overflow-hidden border border-slate-700 bg-slate-700 sm:grid-cols-3">
                  {supportedModes.map((option) => (
                    <label
                      key={option.value}
                      className={`min-w-0 cursor-pointer bg-slate-950 px-3 py-2 ${
                        mode === option.value ? "text-cyan-200" : "text-slate-300"
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        <input
                          type="radio"
                          name={`${anchorPrefix}-mode`}
                          value={option.value}
                          checked={mode === option.value}
                          onChange={() => setMode(option.value)}
                          className="h-3.5 w-3.5 accent-cyan-500"
                        />
                        <span className="text-xs font-semibold">{option.label}</span>
                      </span>
                      <span className="mt-0.5 block pl-5 text-[10px] text-slate-500">
                        {option.description}
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>

              <div>
                <div className="text-xs font-semibold text-slate-200">
                  Grounding
                </div>
                <label className="mt-2 flex min-h-12 items-start gap-2 border border-slate-800 bg-slate-950 px-3 py-2">
                  <input
                    type="checkbox"
                    checked={semanticMemorySupported && includeSemanticMemory}
                    onChange={(event) =>
                      setIncludeSemanticMemory(event.target.checked)
                    }
                    disabled={controlsDisabled || !semanticMemorySupported}
                    className="mt-0.5 h-4 w-4 accent-cyan-500"
                  />
                  <span>
                    <span className="block text-xs font-medium text-slate-200">
                      Include semantic memory
                    </span>
                    <span className="mt-0.5 block text-[10px] leading-4 text-slate-500">
                      Qdrant similarity is advisory and requires analyst review.
                    </span>
                  </span>
                </label>
              </div>
            </div>

            <div className="flex flex-col gap-3 border-t border-slate-800 pt-3 sm:flex-row sm:items-center sm:justify-between">
              <p className="max-w-4xl text-[11px] leading-5 text-slate-500">
                {safetyStatement}
              </p>
              <div className="flex shrink-0 flex-wrap gap-2">
                {submitting ? (
                  <button
                    type="button"
                    onClick={handleCancel}
                    className="inline-flex min-h-9 items-center gap-2 border border-red-800 bg-red-950/40 px-3 text-xs font-medium text-red-200 hover:bg-red-950/70"
                  >
                    <X aria-hidden="true" className="h-4 w-4" />
                    Cancel
                  </button>
                ) : null}
                <button
                  type="submit"
                  disabled={!canSubmit}
                  className="inline-flex min-h-9 items-center gap-2 border border-cyan-700 bg-cyan-500 px-3 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-800 disabled:text-slate-500"
                >
                  {submitting ? (
                    <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin" />
                  ) : (
                    <Send aria-hidden="true" className="h-4 w-4" />
                  )}
                  {submitting ? "Generating response" : "Ask SOC Assistant"}
                </button>
              </div>
            </div>
          </form>

          <div aria-live="polite" className="min-h-5 text-xs">
            {submitting ? (
              <span className="inline-flex items-center gap-2 text-cyan-200">
                <Loader2 aria-hidden="true" className="h-3.5 w-3.5 animate-spin" />
                Reviewing bounded context. Completion time depends on the selected
                mode and available evidence.
              </span>
            ) : notice ? (
              <span className="inline-flex items-center gap-2 text-emerald-300">
                <ShieldCheck aria-hidden="true" className="h-3.5 w-3.5" />
                {notice}
              </span>
            ) : null}
          </div>

          {queryError && queryError.kind !== "disabled" ? (
            <div
              className={`border-l-2 px-3 py-2 text-xs leading-5 ${
                queryError.kind === "forbidden" ||
                queryError.kind === "not_found"
                  ? "border-red-700 bg-red-950/30 text-red-200"
                  : "border-amber-700 bg-amber-950/20 text-amber-100"
              }`}
              role="alert"
            >
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <span className="inline-flex items-start gap-2">
                  <AlertTriangle
                    aria-hidden="true"
                    className="mt-0.5 h-3.5 w-3.5 shrink-0"
                  />
                  {queryError.message}
                </span>
                {queryError.retryable ? (
                  <button
                    type="button"
                    onClick={() => void handleSubmit()}
                    disabled={!trimmedQuestion || submitting}
                    className="inline-flex min-h-8 w-fit items-center gap-1.5 border border-slate-700 bg-slate-900 px-2.5 font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-50"
                  >
                    <RefreshCw aria-hidden="true" className="h-3.5 w-3.5" />
                    Try again
                  </button>
                ) : null}
              </div>
            </div>
          ) : null}

          {response ? (
            <div
              ref={responseRef}
              tabIndex={-1}
              className="border-t border-slate-800 pt-4 outline-none focus-visible:ring-1 focus-visible:ring-cyan-500"
              aria-live="polite"
            >
              <AssistantAnswer response={response} anchorPrefix={anchorPrefix} />
            </div>
          ) : !submitting && !queryError && assistantEnabled ? (
            <div className="border-t border-slate-800 pt-3 text-xs leading-5 text-slate-500">
              No question has been submitted. Suggested questions only populate
              the input and never run automatically.
            </div>
          ) : null}

          <div className="flex items-start gap-2 border-t border-slate-800 pt-3 text-[11px] leading-5 text-slate-500">
            <Database aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-400" />
            SQL-backed operational records are authoritative. Semantic-memory
            matches and AI synthesis are advisory; human review remains required.
          </div>
        </div>
      ) : null}
    </section>
  );
}
