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
  stacked?: boolean;
  className?: string;
};

export default function EnterpriseMetricCard({
  title,
  value,
  subtitle,
  icon,
  tone = "neutral",
  compact = true,
  stacked = false,
  className,
}: EnterpriseMetricCardProps) {
  const valueTitle =
    typeof value === "string" || typeof value === "number"
      ? String(value)
      : undefined;

  return (
    <div
      className={cx(
        "relative min-w-0 rounded-sm border shadow-sm",
        SOC_TONE_CLASSES[tone].card,
        compact
          ? "flex min-h-[58px] items-center justify-between gap-3 px-2.5 py-2"
          : "p-4",
        className
      )}
    >
      <div className="min-w-0">
        <div
          title={title}
          className={cx(
            "truncate text-[10px] font-medium uppercase tracking-wide text-slate-500",
            !compact && Boolean(icon) && "pr-7"
          )}
        >
          {title}
        </div>
        <div className={cx("min-w-0", compact && "mt-0.5", compact && !stacked && "flex items-baseline gap-2")}>
          <span
            title={valueTitle}
            className={
              compact
                ? cx("block text-xl font-semibold leading-6", stacked ? "break-words" : "max-w-full shrink-0 truncate")
                : "mt-1 block break-words text-xl font-semibold leading-7"
            }
          >
            {value}
          </span>
          {subtitle && (
            <span
              title={subtitle}
              className={cx(
                "text-[11px] text-slate-500",
                compact ? "block min-w-0 truncate leading-4" : "mt-1 block break-words leading-5"
              )}
            >
              {subtitle}
            </span>
          )}
        </div>
      </div>

      {icon && (
        <div aria-hidden="true" className={cx("shrink-0 rounded-sm p-1.5", !compact && "absolute right-3 top-3", SOC_TONE_CLASSES[tone].icon)}>
          {icon}
        </div>
      )}
    </div>
  );
}
