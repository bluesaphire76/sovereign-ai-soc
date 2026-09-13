export type SocTone =
  | "neutral"
  | "muted"
  | "primary"
  | "success"
  | "warning"
  | "danger"
  | "executive"
  | "high"
  | "medium"
  | "low";

export type SocSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type SocToneClassNames = {
  badge: string;
  bar: string;
  card: string;
  dot: string;
  icon: string;
  panel: string;
  text: string;
};

export const SOC_CONTROL_CLASSES = {
  input:
    "rounded-sm border border-slate-700 bg-slate-950 text-slate-100 outline-none focus:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-60",
  section: "rounded-sm border border-slate-800 bg-slate-900/95 shadow-sm",
  panel: "rounded-sm border border-slate-800 bg-slate-950",
  focus: "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-400",
} as const;

export const SOC_TEXT_CLASSES = {
  pageTitle: "text-2xl font-semibold tracking-tight text-slate-100",
  compactPageTitle: "text-xl font-semibold tracking-tight text-slate-100",
  sectionTitle: "text-sm font-semibold uppercase tracking-wide text-slate-200",
  cardTitle: "text-sm font-semibold text-slate-100",
  body: "text-sm leading-6 text-slate-200",
  secondary: "text-xs leading-5 text-slate-500",
  metadata: "text-[11px] leading-5 text-slate-500",
  table: "text-xs text-slate-200",
  caption: "text-[10px] uppercase tracking-wide text-slate-500",
} as const;

export const SOC_TONE_CLASSES: Record<SocTone, SocToneClassNames> = {
  neutral: {
    badge: "border-slate-700 bg-slate-950 text-slate-300",
    bar: "bg-slate-400",
    card: "border-slate-800 bg-slate-900 text-slate-100",
    dot: "bg-slate-500",
    icon: "bg-slate-950 text-slate-400",
    panel: "border-slate-800 bg-slate-900",
    text: "text-slate-300",
  },
  muted: {
    badge: "border-slate-800 bg-slate-950 text-slate-500",
    bar: "bg-slate-600",
    card: "border-slate-900 bg-slate-950 text-slate-500",
    dot: "bg-slate-600",
    icon: "bg-slate-950 text-slate-500",
    panel: "border-slate-800 bg-slate-950",
    text: "text-slate-500",
  },
  primary: {
    badge: "border-cyan-700 bg-cyan-950 text-cyan-200",
    bar: "bg-cyan-400",
    card: "border-cyan-900/70 bg-cyan-950/20 text-cyan-100",
    dot: "bg-cyan-400",
    icon: "bg-cyan-950 text-cyan-300",
    panel: "border-cyan-900/70 bg-cyan-950/20",
    text: "text-cyan-300",
  },
  success: {
    badge: "border-emerald-700 bg-emerald-950 text-emerald-200",
    bar: "bg-emerald-400",
    card: "border-emerald-900/70 bg-emerald-950/20 text-emerald-100",
    dot: "bg-emerald-400",
    icon: "bg-emerald-950 text-emerald-300",
    panel: "border-emerald-900/70 bg-emerald-950/20",
    text: "text-emerald-300",
  },
  warning: {
    badge: "border-orange-700 bg-orange-950 text-orange-200",
    bar: "bg-orange-400",
    card: "border-orange-900/70 bg-orange-950/20 text-orange-100",
    dot: "bg-orange-400",
    icon: "bg-orange-950 text-orange-300",
    panel: "border-orange-900/70 bg-orange-950/20",
    text: "text-orange-300",
  },
  danger: {
    badge: "border-red-800 bg-red-950 text-red-200",
    bar: "bg-red-400",
    card: "border-red-900/70 bg-red-950/25 text-red-100",
    dot: "bg-red-400",
    icon: "bg-red-950 text-red-300",
    panel: "border-red-900/70 bg-red-950/25",
    text: "text-red-300",
  },
  executive: {
    badge: "border-violet-700 bg-violet-950 text-violet-200",
    bar: "bg-violet-400",
    card: "border-violet-900/70 bg-violet-950/20 text-violet-100",
    dot: "bg-violet-400",
    icon: "bg-violet-950 text-violet-300",
    panel: "border-violet-900/70 bg-violet-950/20",
    text: "text-violet-300",
  },
  high: {
    badge: "border-orange-700 bg-orange-950 text-orange-200",
    bar: "bg-orange-400",
    card: "border-orange-900/70 bg-orange-950/20 text-orange-100",
    dot: "bg-orange-400",
    icon: "bg-orange-950 text-orange-300",
    panel: "border-orange-900/70 bg-orange-950/20",
    text: "text-orange-300",
  },
  medium: {
    badge: "border-amber-700 bg-amber-950 text-amber-200",
    bar: "bg-amber-400",
    card: "border-amber-900/70 bg-amber-950/20 text-amber-100",
    dot: "bg-amber-400",
    icon: "bg-amber-950 text-amber-300",
    panel: "border-amber-900/70 bg-amber-950/20",
    text: "text-amber-300",
  },
  low: {
    badge: "border-sky-800 bg-sky-950/60 text-sky-200",
    bar: "bg-sky-400",
    card: "border-sky-900/70 bg-sky-950/20 text-sky-100",
    dot: "bg-sky-500",
    icon: "bg-sky-950 text-sky-300",
    panel: "border-sky-900/70 bg-sky-950/20",
    text: "text-sky-300",
  },
};

export const SOC_BADGE_BASE =
  "inline-flex items-center rounded-sm border px-2 py-0.5 text-[11px] font-medium leading-5";

export function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

export function normalizeSeverity(value: string | null | undefined): SocSeverity | null {
  const severity = (value ?? "").toUpperCase();

  if (
    severity === "CRITICAL" ||
    severity === "HIGH" ||
    severity === "MEDIUM" ||
    severity === "LOW"
  ) {
    return severity;
  }

  return null;
}

export function severityTone(value: string | null | undefined): SocTone {
  const severity = normalizeSeverity(value);

  if (severity === "CRITICAL") return "danger";
  if (severity === "HIGH") return "high";
  if (severity === "MEDIUM") return "medium";
  if (severity === "LOW") return "low";

  return "neutral";
}

export function severityBadgeClasses(value: string | null | undefined) {
  return SOC_TONE_CLASSES[severityTone(value)].badge;
}

export function severityTextClasses(value: string | null | undefined) {
  return SOC_TONE_CLASSES[severityTone(value)].text;
}

export function severityIndicatorClasses(value: string | null | undefined) {
  return SOC_TONE_CLASSES[severityTone(value)].dot;
}

export function riskBand(score: number | null | undefined): SocSeverity {
  const value = score ?? 0;

  if (value >= 80) return "CRITICAL";
  if (value >= 60) return "HIGH";
  if (value >= 40) return "MEDIUM";
  return "LOW";
}

export function riskScoreTone(score: number | null | undefined): SocTone {
  return severityTone(riskBand(score));
}

export function statusTone(value: string | null | undefined): SocTone {
  const status = (value ?? "").toUpperCase();

  if (
    status === "ERROR" ||
    status === "FAILED" ||
    status === "FAILURE" ||
    status === "BLOCKED" ||
    status === "BREACHED" ||
    status === "DENIED" ||
    status === "ESCALATED" ||
    status === "CRITICAL" ||
    status === "UNSUPPORTED"
  ) {
    return "danger";
  }

  if (
    status === "WARN" ||
    status === "WARNING" ||
    status === "ATTENTION" ||
    status === "CONTAINED" ||
    status === "REQUIRES_REVIEW" ||
    status === "PASSED_WITH_WARNINGS" ||
    status === "MISSING_APPROVAL" ||
    status === "MISSING_EVIDENCE" ||
    status === "NOT_READY"
  ) {
    return "warning";
  }

  if (
    status === "OK" ||
    status === "READY" ||
    status === "PASSED" ||
    status === "APPROVED" ||
    status === "APPLIED" ||
    status === "ENABLED" ||
    status === "RESOLVED" ||
    status === "CLOSED" ||
    status === "COMPLETED" ||
    status === "WITHIN_SLA" ||
    status === "DONE" ||
    status === "SUCCESS"
  ) {
    return "success";
  }

  if (
    status === "NEW" ||
    status === "OPEN" ||
    status === "ACTIVE" ||
    status === "TRIAGED" ||
    status === "INVESTIGATING" ||
    status === "RUNNING" ||
    status === "SUBMITTED" ||
    status === "DRAFT" ||
    status === "PROPOSED" ||
    status === "IN_PROGRESS"
  ) {
    return "primary";
  }

  if (
    status === "FALSE_POSITIVE" ||
    status === "DISABLED" ||
    status === "CANCELLED" ||
    status === "SKIPPED" ||
    status === "NOT_SUPPORTED" ||
    status === "NOT_SET"
  ) {
    return "neutral";
  }

  return "neutral";
}

export function slaTone(value: string | null | undefined): SocTone {
  const status = (value ?? "NOT_SET").toUpperCase();

  if (status === "BREACHED") return "danger";
  if (status === "AT_RISK") return "warning";
  if (status === "OK" || status === "WITHIN_SLA" || status === "COMPLETED") {
    return "success";
  }

  return "neutral";
}
