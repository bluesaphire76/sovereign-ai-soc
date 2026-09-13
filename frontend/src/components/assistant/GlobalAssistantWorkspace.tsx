"use client";

import { Bot, RotateCcw, Send, ShieldCheck, Square } from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from "react";

import {
  EnterpriseBadge,
  EnterpriseBreadcrumbs,
  EnterpriseButton,
  EnterpriseEmptyState,
  EnterpriseErrorState,
  EnterpriseIconButton,
  EnterprisePageHeader,
  EnterpriseSkeleton,
} from "@/components/enterprise";
import {
  ASSISTANT_MESSAGE_MAX_LENGTH,
  fetchAssistantCapabilities,
  normalizeAssistantApiError,
  submitAssistantQuery,
  type AssistantCapabilities,
  type AssistantMode,
  type AssistantQueryResponse,
  type NormalizedAssistantError,
} from "@/lib/assistant";
import { fetchCurrentUser, type AuthUser } from "@/lib/auth";
import { SOC_CONTROL_CLASSES, cx, type SocTone } from "@/lib/semantic-styles";
import AssistantAnswer from "./AssistantAnswer";
import AssistantCapabilityDetails from "./AssistantCapabilityDetails";
import {
  AssistantFailureState,
  AssistantGenerationState,
} from "./AssistantStates";

type AssistantRequestContext = {
  question: string;
  requestedMode: AssistantMode;
  semanticMemoryRequested: boolean;
};

type ConversationTurn =
  | { id: string; role: "user"; text: string }
  | ({
      id: string;
      role: "assistant";
      status: "pending" | "completed" | "error";
      response?: AssistantQueryResponse;
      error?: NormalizedAssistantError;
    } & AssistantRequestContext);

const STARTER_QUERIES = [
  "Which hosts generated the most incidents in the last 7 days?",
  "Compare the incident count from the last 7 days with the previous 7 days.",
  "Which incidents are correlated with incident 5333?",
  "Which cases exceeded their SLA?",
];

function runtimePresentation(capabilities: AssistantCapabilities | null): {
  label: string;
  tone: SocTone;
} {
  if (!capabilities) return { label: "Checking", tone: "neutral" };
  if (!capabilities.enabled) return { label: "Disabled", tone: "muted" };
  if (capabilities.runtime_state === "ready") {
    return { label: "Ready", tone: "success" };
  }
  if (capabilities.runtime_state === "warming") {
    return { label: "Warming", tone: "warning" };
  }
  return { label: "Unavailable", tone: "danger" };
}

export default function GlobalAssistantWorkspace() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [capabilities, setCapabilities] = useState<AssistantCapabilities | null>(null);
  const [capabilitiesLoading, setCapabilitiesLoading] = useState(true);
  const [capabilityError, setCapabilityError] =
    useState<NormalizedAssistantError | null>(null);
  const [question, setQuestion] = useState("");
  const [mode, setMode] = useState<AssistantMode>("auto");
  const [semanticDiscovery, setSemanticDiscovery] = useState(true);
  const [turns, setTurns] = useState<ConversationTurn[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const capabilityControllerRef = useRef<AbortController | null>(null);
  const queryControllerRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const conversationIdRef = useRef<string | null>(null);
  const timelineEndRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const eligible = user?.role === "ADMIN" || user?.role === "ANALYST";
  const globalSupported = capabilities?.supported_scopes.includes("global") ?? true;
  const controlsDisabled =
    capabilitiesLoading ||
    submitting ||
    !eligible ||
    !capabilities?.enabled ||
    !globalSupported ||
    Boolean(capabilityError?.locksInteraction);
  const trimmedQuestion = question.trim();
  const canSubmit =
    !controlsDisabled &&
    trimmedQuestion.length > 0 &&
    trimmedQuestion.length <= ASSISTANT_MESSAGE_MAX_LENGTH;
  const supportedModes = useMemo(
    () => capabilities?.supported_modes ?? ["auto", "standard"],
    [capabilities],
  );
  const runtime = runtimePresentation(capabilities);

  function applyCapabilities(payload: AssistantCapabilities) {
    setCapabilities(payload);
    setCapabilityError(null);
    setSemanticDiscovery(payload.semantic_memory_supported);
    setMode(
      payload.supported_modes.includes("auto")
        ? "auto"
        : payload.supported_modes[0] ?? "auto",
    );
  }

  function conversationId() {
    if (!conversationIdRef.current) {
      conversationIdRef.current = globalThis.crypto.randomUUID();
    }
    return conversationIdRef.current;
  }

  useEffect(() => {
    let active = true;
    mountedRef.current = true;
    const controller = new AbortController();
    capabilityControllerRef.current = controller;

    async function loadWorkspace() {
      try {
        const currentUser = await fetchCurrentUser();
        if (!active) return;
        setUser(currentUser);

        if (currentUser.role !== "ADMIN" && currentUser.role !== "ANALYST") {
          return;
        }

        const currentCapabilities = await fetchAssistantCapabilities(
          controller.signal,
        );
        if (!active) return;
        applyCapabilities(currentCapabilities);
      } catch (error: unknown) {
        if (!active) return;
        const normalized = normalizeAssistantApiError(error, "global");
        if (normalized.kind !== "aborted") setCapabilityError(normalized);
      } finally {
        if (active) setCapabilitiesLoading(false);
      }
    }

    void loadWorkspace();
    return () => {
      active = false;
      mountedRef.current = false;
      controller.abort();
      queryControllerRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    timelineEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [turns]);

  async function retryCapabilities() {
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
      applyCapabilities(payload);
    } catch (error: unknown) {
      if (!mountedRef.current || capabilityControllerRef.current !== controller) {
        return;
      }
      const normalized = normalizeAssistantApiError(error, "global");
      if (normalized.kind !== "aborted") setCapabilityError(normalized);
    } finally {
      if (mountedRef.current && capabilityControllerRef.current === controller) {
        setCapabilitiesLoading(false);
      }
    }
  }

  async function submit(
    text: string,
    requestContext?: Omit<AssistantRequestContext, "question">,
  ) {
    const normalized = text.trim();
    if (
      controlsDisabled ||
      !normalized ||
      normalized.length > ASSISTANT_MESSAGE_MAX_LENGTH
    ) {
      return;
    }

    const submittedMode = requestContext?.requestedMode ?? mode;
    const submittedSemanticMemory =
      requestContext?.semanticMemoryRequested ?? semanticDiscovery;
    const turnContext: AssistantRequestContext = {
      question: normalized,
      requestedMode: submittedMode,
      semanticMemoryRequested: submittedSemanticMemory,
    };
    const userTurnId = globalThis.crypto.randomUUID();
    const assistantTurnId = globalThis.crypto.randomUUID();
    const controller = new AbortController();
    queryControllerRef.current = controller;
    setQuestion("");
    setSubmitting(true);
    setTurns((current) => [
      ...current,
      { id: userTurnId, role: "user", text: normalized },
      {
        id: assistantTurnId,
        role: "assistant",
        status: "pending",
        ...turnContext,
      },
    ]);

    try {
      const response = await submitAssistantQuery(
        {
          message: normalized,
          scope: "global",
          incident_id: null,
          case_id: null,
          requested_mode: submittedMode,
          include_semantic_memory: submittedSemanticMemory,
          conversation_id: conversationId(),
        },
        controller.signal,
      );
      if (!mountedRef.current || queryControllerRef.current !== controller) {
        return;
      }
      setTurns((current) =>
        current.map((turn) =>
          turn.id === assistantTurnId && turn.role === "assistant"
            ? { ...turn, status: "completed", response }
            : turn,
        ),
      );
    } catch (error: unknown) {
      if (!mountedRef.current || queryControllerRef.current !== controller) {
        return;
      }
      const normalizedError = normalizeAssistantApiError(error, "global");
      setTurns((current) =>
        current.map((turn) =>
          turn.id === assistantTurnId && turn.role === "assistant"
            ? { ...turn, status: "error", error: normalizedError }
            : turn,
        ),
      );
    } finally {
      if (mountedRef.current && queryControllerRef.current === controller) {
        setSubmitting(false);
        queryControllerRef.current = null;
        textareaRef.current?.focus();
      }
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void submit(question);
  }

  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      if (canSubmit) void submit(question);
    }
  }

  function resetConversation() {
    const controller = queryControllerRef.current;
    queryControllerRef.current = null;
    controller?.abort();
    conversationIdRef.current = null;
    setTurns([]);
    setQuestion("");
    setSubmitting(false);
    textareaRef.current?.focus();
  }

  const header = (
    <EnterprisePageHeader
      density="compact"
      divided
      breadcrumbs={
        <EnterpriseBreadcrumbs
          items={[{ label: "AI" }, { label: "Assistant" }]}
        />
      }
      eyebrow="AI workspace"
      title="AI SOC Assistant"
      description="Read-only global analysis across incidents, cases, trends and recorded relationships."
      icon={<Bot aria-hidden="true" className="h-4 w-4" />}
      metadata={
        <>
          <EnterpriseBadge tone="primary" size="compact">
            Global context
          </EnterpriseBadge>
          <EnterpriseBadge tone="neutral" size="compact">
            Read only
          </EnterpriseBadge>
          <EnterpriseBadge
            tone="neutral"
            size="compact"
            icon={<ShieldCheck aria-hidden="true" className="h-3 w-3" />}
          >
            V3.2 proof gate
          </EnterpriseBadge>
        </>
      }
      status={
        <EnterpriseBadge tone={runtime.tone} size="compact">
          Runtime: {runtime.label}
        </EnterpriseBadge>
      }
      secondaryActions={
        <EnterpriseIconButton
          onClick={resetConversation}
          icon={<RotateCcw aria-hidden="true" className="h-3.5 w-3.5" />}
          label="New conversation"
          size="xs"
        />
      }
    />
  );

  if (user && !eligible) {
    return (
      <div className="min-h-[calc(100vh-2rem)] border border-slate-800 bg-slate-950 p-4 sm:p-6">
        {header}
        <EnterpriseErrorState
          title="Assistant access restricted"
          message="This role is not permitted to use the AI SOC Assistant."
        />
      </div>
    );
  }

  return (
    <div className="flex min-h-[calc(100vh-2rem)] min-w-0 flex-col border border-slate-800 bg-slate-950">
      <div className="px-4 pt-4 sm:px-6">{header}</div>

      {capabilities?.decision_boundary ? (
        <p className="px-4 pb-3 text-[11px] leading-5 text-slate-500 sm:px-6">
          {capabilities.decision_boundary}
        </p>
      ) : null}
      {capabilities ? (
        <div className="px-4 pb-3 sm:px-6">
          <AssistantCapabilityDetails capabilities={capabilities} />
        </div>
      ) : null}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div
          className="mx-auto flex min-h-full w-full max-w-5xl flex-col px-4 py-5 sm:px-8"
        >
          {capabilitiesLoading ? (
            <EnterpriseSkeleton label="Checking Assistant availability" rows={3} />
          ) : capabilityError ? (
            <EnterpriseErrorState
              title="Assistant availability could not be confirmed"
              message={capabilityError.message}
              onRetry={capabilityError.retryable ? retryCapabilities : undefined}
              retryLabel="Retry availability check"
            />
          ) : turns.length === 0 ? (
            <div className="my-auto py-8">
              <EnterpriseEmptyState
                title="Start a global SOC analysis"
                description="Choose a bounded analytics question or enter a question below."
                icon={<Bot aria-hidden="true" className="h-5 w-5" />}
              />
              <div className="grid gap-px border border-slate-800 bg-slate-800 sm:grid-cols-2">
                {STARTER_QUERIES.map((starter) => (
                  <button
                    key={starter}
                    type="button"
                    onClick={() => void submit(starter)}
                    disabled={controlsDisabled}
                    className={cx(
                      "min-h-16 bg-slate-950 px-4 py-3 text-left text-xs leading-5 text-slate-300 transition hover:bg-slate-900 hover:text-cyan-200 disabled:cursor-not-allowed disabled:text-slate-600",
                      SOC_CONTROL_CLASSES.focus,
                    )}
                  >
                    {starter}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div
              role="log"
              aria-label="Global SOC Assistant conversation"
              aria-live="polite"
              className="space-y-7"
            >
              {turns.map((turn) =>
                turn.role === "user" ? (
                  <div key={turn.id} className="flex justify-end pl-8 sm:pl-20">
                    <div className="max-w-3xl rounded-sm border border-slate-700 bg-slate-900 px-3.5 py-2.5 text-sm leading-6 text-slate-100">
                      <p className="whitespace-pre-wrap break-words">{turn.text}</p>
                    </div>
                  </div>
                ) : (
                  <div
                    key={turn.id}
                    className="grid grid-cols-[24px_minmax(0,1fr)] gap-3"
                  >
                    <div className="mt-0.5 flex h-6 w-6 items-center justify-center border border-cyan-900 text-cyan-300">
                      <Bot aria-hidden="true" className="h-3.5 w-3.5" />
                    </div>
                    <div className="min-w-0">
                      {turn.status === "pending" ? (
                        <AssistantGenerationState scope="global" />
                      ) : turn.status === "completed" && turn.response ? (
                        <AssistantAnswer
                          response={turn.response}
                          anchorPrefix={`global-assistant-${turn.id}`}
                          requestedMode={turn.requestedMode}
                          semanticMemoryRequested={turn.semanticMemoryRequested}
                        />
                      ) : turn.error ? (
                        <AssistantFailureState
                          error={turn.error}
                          scope="global"
                          onRetry={
                            turn.error.retryable && !submitting
                              ? () =>
                                  submit(turn.question, {
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
          )}
        </div>
      </div>

      <div className="sticky bottom-0 border-t border-slate-800 bg-slate-950 px-4 py-3 sm:px-6">
        <form onSubmit={handleSubmit} className="mx-auto w-full max-w-5xl">
          <div className="flex items-end gap-2 border border-slate-700 bg-slate-950 p-2 focus-within:border-cyan-700">
            <label htmlFor="global-assistant-question" className="sr-only">
              Assistant question
            </label>
            <textarea
              ref={textareaRef}
              id="global-assistant-question"
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              onKeyDown={handleKeyDown}
              rows={2}
              maxLength={ASSISTANT_MESSAGE_MAX_LENGTH}
              disabled={controlsDisabled}
              placeholder="Ask an authoritative SOC analytics question"
              className="max-h-36 min-h-11 flex-1 resize-y bg-transparent px-1 py-1.5 text-sm leading-5 text-slate-100 outline-none placeholder:text-slate-600 disabled:cursor-not-allowed"
            />
            {submitting ? (
              <EnterpriseIconButton
                onClick={() => queryControllerRef.current?.abort()}
                icon={<Square aria-hidden="true" className="h-3.5 w-3.5" />}
                label="Cancel request"
                tone="danger"
                size="md"
              />
            ) : (
              <EnterpriseIconButton
                type="submit"
                disabled={!canSubmit}
                icon={<Send aria-hidden="true" className="h-4 w-4" />}
                label="Send question"
                tone="primary"
                size="md"
              />
            )}
          </div>
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
            <div
              role="group"
              className="flex flex-wrap gap-1"
              aria-label="Assistant mode"
            >
              {(["auto", "standard"] as AssistantMode[])
                .filter((value) => supportedModes.includes(value))
                .map((value) => (
                  <EnterpriseButton
                    key={value}
                    type="button"
                    onClick={() => setMode(value)}
                    disabled={submitting}
                    tone={mode === value ? "primary" : "ghost"}
                    size="xs"
                    ariaPressed={mode === value}
                    className="capitalize"
                  >
                    {value}
                  </EnterpriseButton>
                ))}
            </div>
            <label className="inline-flex items-center gap-2 text-[11px] text-slate-500">
              <input
                type="checkbox"
                checked={semanticDiscovery}
                onChange={(event) => setSemanticDiscovery(event.target.checked)}
                disabled={!capabilities?.semantic_memory_supported || submitting}
                className={cx("h-3.5 w-3.5 accent-cyan-500", SOC_CONTROL_CLASSES.focus)}
              />
              Semantic discovery
            </label>
          </div>
        </form>
      </div>
    </div>
  );
}
