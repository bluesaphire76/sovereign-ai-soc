import {
  EnterpriseBadge,
  EnterpriseSeverityBadge,
} from "@/components/enterprise";

type CaseSeverityRiskProps = {
  severity: string | null | undefined;
  score: number | null | undefined;
  compact?: boolean;
  className?: string;
};

export default function CaseSeverityRisk({
  severity,
  score,
  compact = true,
  className,
}: CaseSeverityRiskProps) {
  const hasScore = typeof score === "number" && Number.isFinite(score);

  return (
    <span className={`inline-flex items-center gap-1.5 ${className ?? ""}`}>
      <EnterpriseSeverityBadge
        value={severity}
        size={compact ? "compact" : "default"}
      />
      <EnterpriseBadge
        tone="neutral"
        size={compact ? "compact" : "default"}
        aria-label={`Risk score: ${hasScore ? score : "unknown"}`}
        className="font-mono tabular-nums"
      >
        {hasScore ? score : "-"}
      </EnterpriseBadge>
    </span>
  );
}
