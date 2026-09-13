import type { HTMLAttributes, ReactNode } from "react";
import {
  SOC_BADGE_BASE,
  SOC_TONE_CLASSES,
  cx,
  type SocTone,
} from "@/lib/semantic-styles";

export type EnterpriseBadgeTone = SocTone;
export type EnterpriseBadgeSize = "compact" | "default";

type EnterpriseBadgeProps = Omit<HTMLAttributes<HTMLSpanElement>, "color"> & {
  children: ReactNode;
  tone?: EnterpriseBadgeTone;
  icon?: ReactNode;
  size?: EnterpriseBadgeSize;
};

export default function EnterpriseBadge({
  children,
  tone = "neutral",
  icon,
  size = "default",
  className,
  ...props
}: EnterpriseBadgeProps) {
  return (
    <span
      className={cx(
        SOC_BADGE_BASE,
        SOC_TONE_CLASSES[tone].badge,
        Boolean(icon) && "gap-1",
        size === "compact" && "h-5 whitespace-nowrap px-1.5 text-[10px] leading-none",
        className
      )}
      {...props}
    >
      {icon}
      {children}
    </span>
  );
}
