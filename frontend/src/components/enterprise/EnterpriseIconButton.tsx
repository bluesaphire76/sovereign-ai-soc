"use client";

import type { ButtonHTMLAttributes, ReactNode } from "react";
import { SOC_CONTROL_CLASSES, cx } from "@/lib/semantic-styles";
import EnterpriseTooltip from "./EnterpriseTooltip";
import {
  ENTERPRISE_BUTTON_TONE_CLASSES,
  type EnterpriseButtonTone,
} from "./EnterpriseButton";

type EnterpriseIconButtonSize = "xs" | "sm" | "md";

type EnterpriseIconButtonProps = Omit<
  ButtonHTMLAttributes<HTMLButtonElement>,
  "aria-label" | "children"
> & {
  icon: ReactNode;
  label: string;
  tone?: EnterpriseButtonTone;
  size?: EnterpriseIconButtonSize;
  tooltip?: string;
};

const sizeClasses: Record<EnterpriseIconButtonSize, string> = {
  xs: "h-7 w-7",
  sm: "h-8 w-8",
  md: "h-9 w-9",
};

export default function EnterpriseIconButton({
  icon,
  label,
  tone = "secondary",
  size = "sm",
  tooltip = label,
  className,
  type = "button",
  ...props
}: EnterpriseIconButtonProps) {
  const button = (
    <button
      type={type}
      aria-label={label}
      title={tooltip}
      className={cx(
        "inline-flex shrink-0 items-center justify-center rounded-sm border shadow-sm transition disabled:cursor-not-allowed disabled:opacity-40",
        SOC_CONTROL_CLASSES.focus,
        ENTERPRISE_BUTTON_TONE_CLASSES[tone],
        sizeClasses[size],
        className
      )}
      {...props}
    >
      {icon}
    </button>
  );

  return tooltip ? (
    <EnterpriseTooltip content={tooltip}>{button}</EnterpriseTooltip>
  ) : (
    button
  );
}
