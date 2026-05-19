import type { ReactNode } from "react";

type EnterpriseBadgeTone =
  | "neutral"
  | "primary"
  | "success"
  | "warning"
  | "danger"
  | "executive"
  | "muted";

type EnterpriseBadgeProps = {
  children: ReactNode;
  tone?: EnterpriseBadgeTone;
  className?: string;
};

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

const toneClasses: Record<EnterpriseBadgeTone, string> = {
  neutral: "border-slate-700 bg-slate-900 text-slate-300",
  primary: "border-cyan-700 bg-cyan-950 text-cyan-200",
  success: "border-emerald-700 bg-emerald-950 text-emerald-200",
  warning: "border-orange-700 bg-orange-950 text-orange-200",
  danger: "border-red-800 bg-red-950 text-red-200",
  executive: "border-violet-700 bg-violet-950 text-violet-200",
  muted: "border-slate-800 bg-slate-950 text-slate-500",
};

export default function EnterpriseBadge({
  children,
  tone = "neutral",
  className,
}: EnterpriseBadgeProps) {
  return (
    <span
      className={cx(
        "inline-flex items-center rounded-sm border px-2 py-0.5 text-[11px] font-medium leading-5",
        toneClasses[tone],
        className
      )}
    >
      {children}
    </span>
  );
}
