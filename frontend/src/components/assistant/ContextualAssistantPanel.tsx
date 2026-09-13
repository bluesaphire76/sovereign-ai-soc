"use client";

import {
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
import {
  EnterpriseBadge,
  EnterpriseButton,
  EnterpriseErrorState,
  EnterpriseIconButton,
  EnterpriseSkeleton,
} from "@/components/enterprise";
import { SOC_CONTROL_CLASSES, cx, type SocTone } from "@/lib/semantic-styles";
import AssistantAnswer from "./AssistantAnswer";
import AssistantCapabilityDetails from "./AssistantCapabilityDetails";
import {
  AssistantFailureState,
  AssistantGenerationState,
} from "./AssistantStates";
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

type AssistantTimelineTurn =
  | {
      id: string;
      role: "user";
      text: string;
    }
  | {
      id: string;
      role: "assistant";
      question: string;
      requestedMode: AssistantMode;
      semanticMemoryRequested: boolean;
      status: "pending" | "completed" | "error";
      response?: AssistantQueryResponse;
      error?: NormalizedAssistantError;
    };

function capabilityBadge(
  loading: boolean,
  capabilities: AssistantCapabilities | null,
  error: NormalizedAssistantError | null,
  scopeSupported: boolean,
  runtimeDisabled: boolean,
): { label: string; tone: SocTone } {
  if (loading) {
    return {
      label: "CHECKING",
      tone: "primary",
    };
  }
  if (error?.kind === "forbidden") {
    return {
      label: "RESTRICTED",
      tone: "danger",
    };
  }
  if (error || !scopeSupported) {
    return {
      label: "UNAVAILABLE",
      tone: "warning",
    };
  }
  if (!capabilities?.enabled || runtimeDisabled) {
    return {
      label: "DISABLED",
      tone: "muted",
    };
  }
  if (capabilities.runtime_state === "warming") {
    return {
      label: "WARMING",
      tone: "warning",
    };
  }
  if (capabilities.runtime_state === "ready") {
    return {
      label: "READY",
      tone: "success",
    };
  }
  if (
    capabilities.runtime_state === "failed" ||
    capabilities.runtime_state === "stopped"
  ) {
    return {
      label: "UNAVAILABLE",
      tone: "danger",
    };
  }
  return {
    label: "AVAILABLE",
    tone: "success",
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
  const [turns, setTurns] = useState<AssistantTimelineTurn[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [queryError, setQueryError] =
    useState<NormalizedAssistantError | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const capabilityControllerRef = useRef<AbortController | null>(null);
  const queryControllerRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const timelineRef = useRef<HTMLDivElement | null>(null);
  const timelineEndRef = useRef<HTMLDivElement | null>(null);
  const pendingTurnIdRef = useRef<string | null>(null);
  const keepTimelinePinnedRef = useRef(true);
  const conversationIdRef = useRef<string | null>(null);

  function currentConversationId() {
    if (conversationIdRef.current === null) {
      conversationIdRef.current = globalThis.crypto.randomUUID();
    }
    return conversationIdRef.current;
  }

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

  async function submitQuestion(
    message: string,
    requestContext?: {
      requestedMode: AssistantMode;
      semanticMemoryRequested: boolean;
    },
  ) {
    if (submitting || !assistantEnabled || interactionLocked) return;
    const requestedMode = requestContext?.requestedMode ?? mode;
    const semanticMemoryRequested =
      requestContext?.semanticMemoryRequested ??
      (semanticMemorySupported && includeSemanticMemory);
    const controller = new AbortController();
    const userTurnId = globalThis.crypto.randomUUID();
    const assistantTurnId = globalThis.crypto.randomUUID();
    queryControllerRef.current = controller;
    pendingTurnIdRef.current = assistantTurnId;
    keepTimelinePinnedRef.current = true;
    setSubmitting(true);
    setValidationError(null);
    setQueryError(null);
    setNotice(null);
    setQuestion("");
    setTurns((current) => [
      ...current,
      { id: userTurnId, role: "user", text: message },
      {
        id: assistantTurnId,
        role: "assistant",
        question: message,
        requestedMode,
        semanticMemoryRequested,
        status: "pending",
      },
    ]);
    window.requestAnimationFrame(() => {
      timelineEndRef.current?.scrollIntoView({ block: "nearest" });
    });

    try {
      const payload = await submitAssistantQuery(
        {
          message,
          scope,
          incident_id: scope === "incident" ? targetId : null,
          case_id: scope === "case" ? targetId : null,
          requested_mode: requestedMode,
          include_semantic_memory: semanticMemoryRequested,
          conversation_id: currentConversationId(),
        },
        controller.signal,
      );

      if (!mountedRef.current || queryControllerRef.current !== controller) {
        return;
      }

      setTurns((current) =>
        current.map((turn) =>
          turn.id === assistantTurnId && turn.role === "assistant"
            ? { ...turn, status: "completed", response: payload }
            : turn,
        ),
      );
      setNotice(
        "Response validated. You can continue with a follow-up question.",
      );
      if (keepTimelinePinnedRef.current) {
        window.requestAnimationFrame(() => {
          timelineEndRef.current?.scrollIntoView({ block: "nearest" });
        });
      }
    } catch (error) {
      if (!mountedRef.current || queryControllerRef.current !== controller) {
        return;
      }
      const normalized = normalizeAssistantApiError(error, scope);
      if (normalized.kind !== "aborted") {
        setQueryError(normalized);
        setTurns((current) =>
          current.map((turn) =>
            turn.id === assistantTurnId && turn.role === "assistant"
              ? { ...turn, status: "error", error: normalized }
              : turn,
          ),
        );
      }
    } finally {
      if (mountedRef.current && queryControllerRef.current === controller) {
        queryControllerRef.current = null;
        pendingTurnIdRef.current = null;
        setSubmitting(false);
      }
    }
  }

  async function handleSubmit(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();

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
    await submitQuestion(trimmedQuestion);
  }

  function handleCancel() {
    const controller = queryControllerRef.current;
    if (!controller) return;

    queryControllerRef.current = null;
    controller.abort();
    const pendingTurnId = pendingTurnIdRef.current;
    pendingTurnIdRef.current = null;
    if (pendingTurnId) {
      setTurns((current) =>
        current.map((turn) =>
          turn.id === pendingTurnId && turn.role === "assistant"
            ? {
                ...turn,
                status: "error",
                error: {
                  kind: "aborted",
                  message: "The assistant request was cancelled.",
                  retryable: true,
                  locksInteraction: false,
                },
              }
            : turn,
        ),
      );
    }
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

  function handleTimelineScroll() {
    const timeline = timelineRef.current;
    if (!timeline) return;
    keepTimelinePinnedRef.current =
      timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 80;
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
            <EnterpriseBadge tone="primary" size="compact">
              READ ONLY
            </EnterpriseBadge>
            <EnterpriseBadge tone={badge.tone} size="compact">
              {badge.label}
            </EnterpriseBadge>
            {!capabilitiesLoading && capabilities ? (
              <EnterpriseIconButton
                onClick={() => void handleRetryCapabilities()}
                icon={<RefreshCw aria-hidden="true" className="h-3.5 w-3.5" />}
                label="Refresh Assistant readiness"
                size="xs"
              />
            ) : null}
          </div>
          <p className="mt-2 max-w-4xl text-xs leading-5 text-slate-400">
            Grounded analyst support using authoritative platform records and
            optional advisory semantic memory.
          </p>
          <p className="mt-1 max-w-4xl text-[11px] leading-5 text-slate-500">
            {capabilities?.decision_boundary ??
              "Platform records remain authoritative. AI output supports human review and cannot perform operational actions."}
          </p>
          {capabilities?.runtime_message ? (
            <p className="mt-1 max-w-4xl text-[11px] leading-5 text-slate-400">
              {capabilities.runtime_message}
            </p>
          ) : null}
        </div>
      </div>

      {capabilitiesLoading ? (
        <EnterpriseSkeleton
          label="Checking SOC Assistant availability"
          rows={2}
          className="mx-3 mt-4 sm:mx-4"
        />
      ) : null}

      {!capabilitiesLoading && capabilityError ? (
        <EnterpriseErrorState
          title="Assistant availability could not be confirmed"
          message={capabilityError.message}
          onRetry={
            capabilityError.retryable ? handleRetryCapabilities : undefined
          }
          retryLabel="Retry availability check"
          className="mx-3 mt-4 sm:mx-4"
        />
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

          {turns.length > 0 ? (
            <div
              ref={timelineRef}
              onScroll={handleTimelineScroll}
              role="log"
              aria-label="SOC Assistant conversation"
              aria-live="polite"
              className="max-h-[52rem] space-y-5 overflow-y-auto border-y border-slate-800 py-4 pr-1"
            >
              {turns.map((turn, index) =>
                turn.role === "user" ? (
                  <div key={turn.id} className="flex justify-end pl-8 sm:pl-16">
                    <div className="max-w-3xl rounded-md bg-slate-800 px-3 py-2 text-sm leading-6 text-slate-100">
                      <p className="whitespace-pre-wrap break-words">{turn.text}</p>
                    </div>
                  </div>
                ) : (
                  <div
                    key={turn.id}
                    className="flex min-w-0 items-start gap-3 pr-2"
                  >
                    <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-cyan-900 bg-slate-900 text-cyan-300">
                      <Bot aria-hidden="true" className="h-4 w-4" />
                    </div>
                    <div className="min-w-0 max-w-4xl flex-1">
                      {turn.status === "pending" ? (
                        <AssistantGenerationState scope={scope} />
                      ) : turn.status === "completed" && turn.response ? (
                        <AssistantAnswer
                          response={turn.response}
                          anchorPrefix={`${anchorPrefix}-turn-${index}`}
                          requestedMode={turn.requestedMode}
                          semanticMemoryRequested={turn.semanticMemoryRequested}
                        />
                      ) : turn.error ? (
                        <AssistantFailureState
                          error={turn.error}
                          scope={scope}
                          onRetry={
                            turn.error.retryable && !submitting
                              ? () =>
                                  submitQuestion(turn.question, {
                                    requestedMode: turn.requestedMode,
                                    semanticMemoryRequested:
                                      turn.semanticMemoryRequested,
                                  })
                              : undefined
                          }
                        />
                      ) : null}
                    </div>
                  </div>
                ),
              )}
              <div ref={timelineEndRef} aria-hidden="true" />
            </div>
          ) : null}

          <form className="space-y-4" onSubmit={handleSubmit}>
            {turns.length === 0 ? (
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
                      className={cx(
                        "min-h-8 max-w-full rounded-sm border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-left text-xs leading-5 text-slate-300 hover:border-cyan-800 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50",
                        SOC_CONTROL_CLASSES.focus,
                      )}
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              </fieldset>
            ) : null}

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
                className={cx(
                  "mt-2 min-h-28 w-full resize-y px-3 py-2 text-sm leading-6 placeholder:text-slate-600",
                  SOC_CONTROL_CLASSES.input,
                  SOC_CONTROL_CLASSES.focus,
                )}
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
                          className={cx(
                            "h-3.5 w-3.5 accent-cyan-500",
                            SOC_CONTROL_CLASSES.focus,
                          )}
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
                    className={cx(
                      "mt-0.5 h-4 w-4 accent-cyan-500",
                      SOC_CONTROL_CLASSES.focus,
                    )}
                  />
                  <span>
                    <span className="block text-xs font-medium text-slate-200">
                      Include semantic memory
                    </span>
                    <span className="mt-0.5 block text-[10px] leading-4 text-slate-500">
                      Qdrant similarity is advisory. Encoder: {capabilities.semantic_runtime_state ?? "unknown"}.
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
                  <EnterpriseButton
                    onClick={handleCancel}
                    tone="danger"
                    size="sm"
                    icon={<X aria-hidden="true" className="h-4 w-4" />}
                  >
                    Cancel
                  </EnterpriseButton>
                ) : null}
                <EnterpriseButton
                  type="submit"
                  disabled={!canSubmit}
                  tone="primary"
                  size="sm"
                  icon={
                    submitting ? (
                      <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin" />
                    ) : (
                      <Send aria-hidden="true" className="h-4 w-4" />
                    )
                  }
                >
                  {submitting ? "Generating response" : "Ask SOC Assistant"}
                </EnterpriseButton>
              </div>
            </div>
          </form>

          <div aria-live="polite" className="min-h-5 text-xs">
            {!submitting && notice ? (
              <span className="inline-flex items-center gap-2 text-emerald-300">
                <ShieldCheck aria-hidden="true" className="h-3.5 w-3.5" />
                {notice}
              </span>
            ) : null}
          </div>

          <div className="flex items-start gap-2 border-t border-slate-800 pt-3 text-[11px] leading-5 text-slate-500">
            <Database aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-400" />
            SQL-backed operational records are authoritative. Semantic-memory
            matches and AI synthesis are advisory; human review remains required.
          </div>
          <AssistantCapabilityDetails capabilities={capabilities} />
        </div>
      ) : null}
    </section>
  );
}
