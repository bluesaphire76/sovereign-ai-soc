"use client";

import Link from "next/link";
import type { ReactNode } from "react";

type EnterpriseButtonTone =
  | "primary"
  | "secondary"
  | "success"
  | "warning"
  | "danger"
  | "executive"
  | "ghost";

type EnterpriseButtonSize = "xs" | "sm" | "md";

type EnterpriseButtonProps = {
  children: ReactNode;
  href?: string;
  onClick?: () => void | Promise<void>;
  disabled?: boolean;
  tone?: EnterpriseButtonTone;
  size?: EnterpriseButtonSize;
  icon?: ReactNode;
  className?: string;
  type?: "button" | "submit" | "reset";
};

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

const toneClasses: Record<EnterpriseButtonTone, string> = {
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
  className,
  type = "button",
}: EnterpriseButtonProps) {
  const classes = cx(
    "inline-flex items-center justify-center gap-2 rounded-lg border font-medium shadow-sm transition disabled:cursor-not-allowed disabled:opacity-40",
    toneClasses[tone],
    sizeClasses[size],
    className
  );

  if (href) {
    return (
      <Link href={href} className={classes}>
        {icon}
        {children}
      </Link>
    );
  }

  return (
    <button type={type} onClick={onClick} disabled={disabled} className={classes}>
      {icon}
      {children}
    </button>
  );
}
