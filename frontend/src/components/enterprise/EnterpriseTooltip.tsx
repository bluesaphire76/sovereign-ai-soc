"use client";

import {
  cloneElement,
  useId,
  type ReactElement,
} from "react";
import { cx } from "@/lib/semantic-styles";

type EnterpriseTooltipProps = {
  content: string;
  children: ReactElement<{ "aria-describedby"?: string }>;
  className?: string;
};

export default function EnterpriseTooltip({
  content,
  children,
  className,
}: EnterpriseTooltipProps) {
  const tooltipId = useId();
  const describedBy = [children.props["aria-describedby"], tooltipId]
    .filter(Boolean)
    .join(" ");

  return (
    <span className={cx("group relative inline-flex", className)}>
      {cloneElement(children, { "aria-describedby": describedBy })}
      <span
        id={tooltipId}
        role="tooltip"
        className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 hidden -translate-x-1/2 whitespace-nowrap rounded-sm border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] font-normal text-slate-200 shadow-lg group-hover:block group-focus-within:block"
      >
        {content}
      </span>
    </span>
  );
}
