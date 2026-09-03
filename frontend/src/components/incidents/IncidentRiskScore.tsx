import { riskBand } from "@/lib/semantic-styles";
import { EnterpriseBadge, EnterpriseSeverityBadge } from "@/components/enterprise";

type IncidentRiskScoreProps = {
  score: number | null | undefined;
  compact?: boolean;
  className?: string;
};

export default function IncidentRiskScore({
  score,
  compact = true,
  className,
}: IncidentRiskScoreProps) {
  const hasScore = typeof score === "number" && Number.isFinite(score);
  const severity = hasScore ? riskBand(score) : null;
  const scoreLabel = hasScore ? score : "-";

  return (
    <span className={`inline-flex items-center gap-1.5 ${className ?? ""}`}>
      <EnterpriseSeverityBadge value={severity} size={compact ? "compact" : "default"} />
      <EnterpriseBadge
        tone="neutral"
        size={compact ? "compact" : "default"}
        aria-label={`Risk score: ${hasScore ? score : "unknown"}`}
        className="font-mono tabular-nums"
      >
        {scoreLabel}
      </EnterpriseBadge>
    </span>
  );
}
