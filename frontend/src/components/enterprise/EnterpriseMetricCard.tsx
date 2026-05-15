import type { ReactNode } from "react";

type EnterpriseMetricTone =
  | "neutral"
  | "primary"
  | "success"
  | "warning"
  | "danger"
  | "executive";

type EnterpriseMetricCardProps = {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: ReactNode;
  tone?: EnterpriseMetricTone;
  compact?: boolean;
};

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

const toneClasses: Record<EnterpriseMetricTone, string> = {
  neutral: "border-slate-800 bg-slate-900 text-slate-100",
  primary: "border-cyan-900 bg-cyan-950/30 text-cyan-100",
  success: "border-emerald-900 bg-emerald-950/30 text-emerald-100",
  warning: "border-orange-900 bg-orange-950/30 text-orange-100",
  danger: "border-red-900 bg-red-950/30 text-red-100",
  executive: "border-violet-900 bg-violet-950/30 text-violet-100",
};

const iconToneClasses: Record<EnterpriseMetricTone, string> = {
  neutral: "bg-slate-950 text-slate-400",
  primary: "bg-cyan-950 text-cyan-300",
  success: "bg-emerald-950 text-emerald-300",
  warning: "bg-orange-950 text-orange-300",
  danger: "bg-red-950 text-red-300",
  executive: "bg-violet-950 text-violet-300",
};

export default function EnterpriseMetricCard({
  title,
  value,
  subtitle,
  icon,
  tone = "neutral",
  compact = true,
}: EnterpriseMetricCardProps) {
  return (
    <div
      className={cx(
        "rounded-xl border shadow-lg",
        toneClasses[tone],
        compact ? "p-3" : "p-4"
      )}
    >
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="text-[11px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>

        {icon && (
          <div className={cx("rounded-lg p-1.5", iconToneClasses[tone])}>
            {icon}
          </div>
        )}
      </div>

      <div className={compact ? "text-2xl font-semibold" : "text-3xl font-semibold"}>
        {value}
      </div>

      {subtitle && (
        <div className="mt-1 truncate text-[11px] leading-5 text-slate-500">
          {subtitle}
        </div>
      )}
    </div>
  );
}
