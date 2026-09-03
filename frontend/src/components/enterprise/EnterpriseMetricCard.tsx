import type { ReactNode } from "react";
import {
  SOC_TONE_CLASSES,
  cx,
  type SocTone,
} from "@/lib/semantic-styles";

type EnterpriseMetricTone = SocTone;

type EnterpriseMetricCardProps = {
  title: string;
  value: ReactNode;
  subtitle?: string;
  icon?: ReactNode;
  tone?: EnterpriseMetricTone;
  compact?: boolean;
  className?: string;
};

export default function EnterpriseMetricCard({
  title,
  value,
  subtitle,
  icon,
  tone = "neutral",
  compact = true,
  className,
}: EnterpriseMetricCardProps) {
  return (
    <div
      className={cx(
        "rounded-sm border shadow-sm",
        SOC_TONE_CLASSES[tone].card,
        compact
          ? "flex min-h-[58px] items-center justify-between gap-3 px-2.5 py-2"
          : "p-4",
        className
      )}
    >
      <div className="min-w-0">
        <div className="truncate text-[10px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>
        <div className={cx("min-w-0", compact && "mt-0.5 flex items-baseline gap-2")}>
          <span className={compact ? "text-xl font-semibold leading-6" : "text-3xl font-semibold"}>
            {value}
          </span>
          {subtitle && (
            <span
              className={cx(
                "text-[11px] text-slate-500",
                compact ? "min-w-0 truncate leading-4" : "mt-1 block leading-5"
              )}
            >
              {subtitle}
            </span>
          )}
        </div>
      </div>

      {icon && (
        <div className={cx("shrink-0 rounded-sm p-1.5", SOC_TONE_CLASSES[tone].icon)}>
          {icon}
        </div>
      )}
    </div>
  );
}
