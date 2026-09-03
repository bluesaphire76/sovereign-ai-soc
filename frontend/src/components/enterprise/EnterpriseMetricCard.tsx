import type { ReactNode } from "react";
import {
  SOC_TONE_CLASSES,
  cx,
  type SocTone,
} from "@/lib/semantic-styles";

type EnterpriseMetricTone = SocTone;

type EnterpriseMetricCardProps = {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: ReactNode;
  tone?: EnterpriseMetricTone;
  compact?: boolean;
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
        "rounded-sm border shadow-sm",
        SOC_TONE_CLASSES[tone].card,
        compact ? "p-3" : "p-4"
      )}
    >
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="text-[11px] font-medium uppercase tracking-wide text-slate-500">
          {title}
        </div>

        {icon && (
          <div className={cx("rounded-sm p-1.5", SOC_TONE_CLASSES[tone].icon)}>
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
