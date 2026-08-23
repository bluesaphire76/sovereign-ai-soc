"use client";

import {
  Bot,
  CheckCircle2,
  Loader2,
  RotateCcw,
  Send,
  ShieldCheck,
  Square,
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
  type NormalizedAssistantError,
} from "@/lib/assistant";
import { fetchCurrentUser, type AuthUser } from "@/lib/auth";
import AssistantAnswer from "./AssistantAnswer";

type ConversationTurn =
  | { id: string; role: "user"; text: string }
  | {
      id: string;
      role: "assistant";
      status: "pending" | "completed" | "error";
      response?: AssistantQueryResponse;
      error?: NormalizedAssistantError;
    };

const STARTER_QUERIES = [
  "Quali host hanno generato più incidenti negli ultimi 7 giorni?",
  "Confronta il numero di incidenti degli ultimi 7 giorni con i 7 giorni precedenti.",
  "Quali incidenti risultano correlati al 5333?",
  "Quali casi hanno superato lo SLA?",
];

function runtimeLabel(capabilities: AssistantCapabilities | null) {
  if (!capabilities) return "Checking";
  if (!capabilities.enabled) return "Disabled";
  if (capabilities.runtime_state === "ready") return "Ready";
  if (capabilities.runtime_state === "warming") return "Warming";
  return "Unavailable";
}

export default function GlobalAssistantWorkspace() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [capabilities, setCapabilities] = useState<AssistantCapabilities | null>(null);
  const [capabilityError, setCapabilityError] =
    useState<NormalizedAssistantError | null>(null);
  const [question, setQuestion] = useState("");
  const [mode, setMode] = useState<AssistantMode>("auto");
  const [semanticDiscovery, setSemanticDiscovery] = useState(true);
  const [turns, setTurns] = useState<ConversationTurn[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const controllerRef = useRef<AbortController | null>(null);
  const conversationIdRef = useRef<string | null>(null);
  const timelineEndRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const eligible = user?.role === "ADMIN" || user?.role === "ANALYST";
  const globalSupported = capabilities?.supported_scopes.includes("global") ?? true;
  const controlsDisabled =
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

  function conversationId() {
    if (!conversationIdRef.current) {
      conversationIdRef.current = globalThis.crypto.randomUUID();
    }
    return conversationIdRef.current;
  }

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    Promise.all([
      fetchCurrentUser(),
      fetchAssistantCapabilities(controller.signal),
    ])
      .then(([currentUser, currentCapabilities]) => {
        if (!active) return;
        setUser(currentUser);
        setCapabilities(currentCapabilities);
        setSemanticDiscovery(currentCapabilities.semantic_memory_supported);
        setMode(
          currentCapabilities.supported_modes.includes("auto")
            ? "auto"
            : currentCapabilities.supported_modes[0] ?? "auto",
        );
      })
      .catch((error: unknown) => {
        if (!active) return;
        const normalized = normalizeAssistantApiError(error, "global");
        if (normalized.kind !== "aborted") setCapabilityError(normalized);
      });
    return () => {
      active = false;
      controller.abort();
      controllerRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    timelineEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [turns]);

  async function submit(text: string) {
    const normalized = text.trim();
    if (
      controlsDisabled ||
      !normalized ||
      normalized.length > ASSISTANT_MESSAGE_MAX_LENGTH
    ) {
      return;
    }
    const userTurnId = globalThis.crypto.randomUUID();
    const assistantTurnId = globalThis.crypto.randomUUID();
    const controller = new AbortController();
    controllerRef.current = controller;
    setQuestion("");
    setSubmitting(true);
    setTurns((current) => [
      ...current,
      { id: userTurnId, role: "user", text: normalized },
      { id: assistantTurnId, role: "assistant", status: "pending" },
    ]);
    try {
      const response = await submitAssistantQuery(
        {
          message: normalized,
          scope: "global",
          incident_id: null,
          case_id: null,
          requested_mode: mode,
          include_semantic_memory: semanticDiscovery,
          conversation_id: conversationId(),
        },
        controller.signal,
      );
      setTurns((current) =>
        current.map((turn) =>
          turn.id === assistantTurnId
            ? { id: assistantTurnId, role: "assistant", status: "completed", response }
            : turn,
        ),
      );
    } catch (error: unknown) {
      const normalizedError = normalizeAssistantApiError(error, "global");
      if (normalizedError.kind === "aborted") {
        setTurns((current) => current.filter((turn) => turn.id !== assistantTurnId));
      } else {
        setTurns((current) =>
          current.map((turn) =>
            turn.id === assistantTurnId
              ? {
                  id: assistantTurnId,
                  role: "assistant",
                  status: "error",
                  error: normalizedError,
                }
              : turn,
          ),
        );
      }
    } finally {
      setSubmitting(false);
      controllerRef.current = null;
      textareaRef.current?.focus();
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
    controllerRef.current?.abort();
    conversationIdRef.current = null;
    setTurns([]);
    setQuestion("");
    textareaRef.current?.focus();
  }

  if (user && !eligible) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center px-5 text-sm text-slate-400">
        This role is not permitted to use the AI SOC Assistant.
      </div>
    );
  }

  return (
    <div className="flex min-h-[calc(100vh-2rem)] min-w-0 flex-col border border-slate-800 bg-slate-950">
      <header className="flex min-h-14 flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-4 py-3 sm:px-6">
        <div className="flex min-w-0 items-center gap-2.5">
          <Bot className="h-4 w-4 shrink-0 text-cyan-300" strokeWidth={1.75} />
          <div className="min-w-0">
            <h1 className="truncate text-base font-semibold text-slate-100">
              AI SOC Assistant
            </h1>
            <div className="flex items-center gap-2 text-[11px] text-slate-500">
              <span>Global scope</span>
              <span aria-hidden="true">/</span>
              <span className="inline-flex items-center gap-1 text-emerald-300">
                <ShieldCheck className="h-3 w-3" /> V3.2 proof gate
              </span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex h-7 items-center gap-1.5 border border-slate-700 px-2 text-[11px] text-slate-300">
            {capabilities?.runtime_state === "ready" ? (
              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
            ) : (
              <span className="h-1.5 w-1.5 bg-amber-400" />
            )}
            {runtimeLabel(capabilities)}
          </span>
          <button
            type="button"
            onClick={resetConversation}
            title="New conversation"
            aria-label="New conversation"
            className="inline-flex h-7 w-7 items-center justify-center border border-slate-700 text-slate-400 hover:border-slate-600 hover:bg-slate-900 hover:text-slate-100"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto flex min-h-full w-full max-w-5xl flex-col px-4 py-6 sm:px-8">
          {turns.length === 0 ? (
            <div className="my-auto py-10">
              <div className="mb-7 flex items-center gap-3 border-b border-slate-800 pb-4">
                <div className="flex h-9 w-9 items-center justify-center border border-cyan-900 bg-cyan-950/30 text-cyan-300">
                  <Bot className="h-4 w-4" />
                </div>
                <div>
                  <div className="text-sm font-medium text-slate-200">Global analytics</div>
                  <div className="text-xs text-slate-500">Incidents, cases, trends and relationships</div>
                </div>
              </div>
              <div className="grid gap-px border border-slate-800 bg-slate-800 sm:grid-cols-2">
                {STARTER_QUERIES.map((starter) => (
                  <button
                    key={starter}
                    type="button"
                    onClick={() => void submit(starter)}
                    disabled={controlsDisabled}
                    className="min-h-16 bg-slate-950 px-4 py-3 text-left text-xs leading-5 text-slate-300 hover:bg-slate-900 hover:text-cyan-200 disabled:cursor-not-allowed disabled:text-slate-600"
                  >
                    {starter}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="space-y-7">
              {turns.map((turn) =>
                turn.role === "user" ? (
                  <div key={turn.id} className="flex justify-end pl-8 sm:pl-20">
                    <div className="max-w-3xl rounded-sm border border-slate-700 bg-slate-900 px-3.5 py-2.5 text-sm leading-6 text-slate-100">
                      {turn.text}
                    </div>
                  </div>
                ) : (
                  <div key={turn.id} className="grid grid-cols-[24px_minmax(0,1fr)] gap-3">
                    <div className="mt-0.5 flex h-6 w-6 items-center justify-center border border-cyan-900 text-cyan-300">
                      <Bot className="h-3.5 w-3.5" />
                    </div>
                    <div className="min-w-0">
                      {turn.status === "pending" ? (
                        <div className="flex min-h-8 items-center gap-2 text-xs text-slate-400">
                          <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-300" />
                          Waiting for the validated response
                        </div>
                      ) : turn.status === "completed" && turn.response ? (
                        <AssistantAnswer
                          response={turn.response}
                          anchorPrefix={`global-assistant-${turn.id}`}
                        />
                      ) : (
                        <div role="alert" className="text-sm text-red-300">
                          {turn.error?.message ?? "The assistant request failed."}
                        </div>
                      )}
                    </div>
                  </div>
                ),
              )}
              <div ref={timelineEndRef} />
            </div>
          )}
        </div>
      </div>

      <div className="sticky bottom-0 border-t border-slate-800 bg-slate-950 px-4 py-3 sm:px-6">
        <form onSubmit={handleSubmit} className="mx-auto w-full max-w-5xl">
          {capabilityError ? (
            <div role="alert" className="mb-2 text-xs text-amber-300">
              {capabilityError.message}
            </div>
          ) : null}
          <div className="flex items-end gap-2 border border-slate-700 bg-slate-950 p-2 focus-within:border-cyan-700">
            <textarea
              ref={textareaRef}
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              onKeyDown={handleKeyDown}
              rows={2}
              maxLength={ASSISTANT_MESSAGE_MAX_LENGTH}
              disabled={controlsDisabled}
              aria-label="Assistant question"
              placeholder="Ask an authoritative SOC analytics question"
              className="max-h-36 min-h-11 flex-1 resize-y bg-transparent px-1 py-1.5 text-sm leading-5 text-slate-100 outline-none placeholder:text-slate-600 disabled:cursor-not-allowed"
            />
            {submitting ? (
              <button
                type="button"
                onClick={() => controllerRef.current?.abort()}
                title="Cancel request"
                aria-label="Cancel request"
                className="inline-flex h-9 w-9 shrink-0 items-center justify-center border border-slate-700 text-slate-300 hover:bg-slate-900"
              >
                <Square className="h-3.5 w-3.5" />
              </button>
            ) : (
              <button
                type="submit"
                disabled={!canSubmit}
                title="Send"
                aria-label="Send"
                className="inline-flex h-9 w-9 shrink-0 items-center justify-center border border-cyan-600 bg-cyan-500 text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:border-slate-800 disabled:bg-slate-900 disabled:text-slate-600"
              >
                <Send className="h-4 w-4" />
              </button>
            )}
          </div>
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
            <div className="inline-flex border border-slate-800" aria-label="Assistant mode">
              {(["auto", "standard"] as AssistantMode[])
                .filter((value) => supportedModes.includes(value))
                .map((value) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => setMode(value)}
                    disabled={submitting}
                    className={`h-7 px-2.5 text-[11px] font-medium capitalize ${
                      mode === value
                        ? "bg-slate-800 text-cyan-200"
                        : "text-slate-500 hover:text-slate-200"
                    }`}
                  >
                    {value}
                  </button>
                ))}
            </div>
            <label className="inline-flex items-center gap-2 text-[11px] text-slate-500">
              <input
                type="checkbox"
                checked={semanticDiscovery}
                onChange={(event) => setSemanticDiscovery(event.target.checked)}
                disabled={!capabilities?.semantic_memory_supported || submitting}
                className="h-3.5 w-3.5 accent-cyan-500"
              />
              Semantic discovery
            </label>
          </div>
        </form>
      </div>
    </div>
  );
}
