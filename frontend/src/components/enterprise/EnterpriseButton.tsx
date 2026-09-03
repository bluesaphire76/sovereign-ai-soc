"use client";

import Link from "next/link";
import type { ButtonHTMLAttributes, MouseEventHandler, ReactNode } from "react";
import { SOC_CONTROL_CLASSES, cx } from "@/lib/semantic-styles";

export type EnterpriseButtonTone =
  | "primary"
  | "secondary"
  | "success"
  | "warning"
  | "danger"
  | "executive"
  | "ghost";

export type EnterpriseButtonSize = "xs" | "sm" | "md";

type EnterpriseButtonProps = Pick<
  ButtonHTMLAttributes<HTMLButtonElement>,
  "autoFocus" | "name" | "value"
> & {
  children: ReactNode;
  href?: string;
  onClick?: MouseEventHandler<HTMLButtonElement>;
  disabled?: boolean;
  tone?: EnterpriseButtonTone;
  size?: EnterpriseButtonSize;
  icon?: ReactNode;
  iconPosition?: "start" | "end";
  className?: string;
  type?: "button" | "submit" | "reset";
  ariaLabel?: string;
  title?: string;
};

export const ENTERPRISE_BUTTON_TONE_CLASSES: Record<EnterpriseButtonTone, string> = {
  primary:
    "border-cyan-700 bg-cyan-500 text-slate-950 hover:bg-cyan-400",
  secondary:
    "border-slate-700 bg-slate-900 text-slate-200 hover:border-slate-600 hover:bg-slate-800",
  success:
    "border-emerald-700 bg-emerald-500 text-slate-950 hover:bg-emerald-400",
  warning:
    "border-orange-700 bg-orange-500 text-slate-950 hover:bg-orange-400",
  danger:
    "border-red-800 bg-red-950/60 text-red-200 hover:bg-red-950",
  executive:
    "border-violet-700 bg-violet-500 text-white hover:bg-violet-400",
  ghost:
    "border-slate-800 bg-transparent text-slate-300 hover:border-cyan-800 hover:bg-slate-900 hover:text-cyan-200",
};

const sizeClasses: Record<EnterpriseButtonSize, string> = {
  xs: "h-8 px-2.5 text-xs",
  sm: "h-9 px-3 text-xs",
  md: "h-10 px-4 text-sm",
};

export default function EnterpriseButton({
  children,
  href,
  onClick,
  disabled = false,
  tone = "secondary",
  size = "sm",
  icon,
  iconPosition = "start",
  className,
  type = "button",
  ariaLabel,
  title,
  autoFocus,
  name,
  value,
}: EnterpriseButtonProps) {
  const classes = cx(
    "inline-flex items-center justify-center gap-2 rounded-sm border font-medium shadow-sm transition disabled:cursor-not-allowed disabled:opacity-40",
    SOC_CONTROL_CLASSES.focus,
    ENTERPRISE_BUTTON_TONE_CLASSES[tone],
    sizeClasses[size],
    className
  );

  if (href) {
    if (disabled) {
      return (
        <span
          aria-disabled="true"
          aria-label={ariaLabel}
          title={title}
          className={cx(classes, "cursor-not-allowed opacity-40")}
        >
          {iconPosition === "start" && icon}
          {children}
          {iconPosition === "end" && icon}
        </span>
      );
    }

    return (
      <Link href={href} aria-label={ariaLabel} title={title} className={classes}>
        {iconPosition === "start" && icon}
        {children}
        {iconPosition === "end" && icon}
      </Link>
    );
  }

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      title={title}
      autoFocus={autoFocus}
      name={name}
      value={value}
      className={classes}
    >
      {iconPosition === "start" && icon}
      {children}
      {iconPosition === "end" && icon}
    </button>
  );
}
