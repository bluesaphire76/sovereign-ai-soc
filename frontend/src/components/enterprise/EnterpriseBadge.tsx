import type { ReactNode } from "react";
import {
  SOC_BADGE_BASE,
  SOC_TONE_CLASSES,
  cx,
  type SocTone,
} from "@/lib/semantic-styles";

type EnterpriseBadgeTone = SocTone;

type EnterpriseBadgeProps = {
  children: ReactNode;
  tone?: EnterpriseBadgeTone;
  className?: string;
};

export default function EnterpriseBadge({
  children,
  tone = "neutral",
  className,
}: EnterpriseBadgeProps) {
  return (
    <span
      className={cx(
        SOC_BADGE_BASE,
        SOC_TONE_CLASSES[tone].badge,
        className
      )}
    >
      {children}
    </span>
  );
}
