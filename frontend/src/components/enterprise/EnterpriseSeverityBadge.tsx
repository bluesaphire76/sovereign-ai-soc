import type { ReactNode } from "react";
import { severityTone } from "@/lib/semantic-styles";
import EnterpriseBadge, { type EnterpriseBadgeSize } from "./EnterpriseBadge";

type EnterpriseSeverityBadgeProps = {
  value: string | null | undefined;
  children?: ReactNode;
  size?: EnterpriseBadgeSize;
  className?: string;
};

export default function EnterpriseSeverityBadge({
  value,
  children,
  size,
  className,
}: EnterpriseSeverityBadgeProps) {
  const label = value ?? "UNKNOWN";

  return (
    <EnterpriseBadge
      tone={severityTone(value)}
      size={size}
      className={className}
      aria-label={`Severity: ${label}`}
    >
      {children ?? label}
    </EnterpriseBadge>
  );
}
