import type { ReactNode } from "react";
import { statusTone } from "@/lib/semantic-styles";
import EnterpriseBadge, { type EnterpriseBadgeSize } from "./EnterpriseBadge";

type EnterpriseStatusBadgeProps = {
  value: string | null | undefined;
  children?: ReactNode;
  size?: EnterpriseBadgeSize;
  className?: string;
};

export default function EnterpriseStatusBadge({
  value,
  children,
  size,
  className,
}: EnterpriseStatusBadgeProps) {
  const label = value ?? "UNKNOWN";

  return (
    <EnterpriseBadge
      tone={statusTone(value)}
      size={size}
      className={className}
      aria-label={`Status: ${label}`}
    >
      {children ?? label}
    </EnterpriseBadge>
  );
}
