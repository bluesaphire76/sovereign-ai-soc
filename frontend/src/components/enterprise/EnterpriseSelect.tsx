"use client";

import { useId } from "react";
import { SOC_CONTROL_CLASSES, cx } from "@/lib/semantic-styles";

export type EnterpriseSelectOption = {
  label: string;
  value: string;
};

type EnterpriseSelectProps = {
  label: string;
  value: string;
  options: readonly EnterpriseSelectOption[];
  onChange: (value: string) => void;
  disabled?: boolean;
  className?: string;
};

export default function EnterpriseSelect({
  label,
  value,
  options,
  onChange,
  disabled = false,
  className,
}: EnterpriseSelectProps) {
  const selectId = useId();

  return (
    <label htmlFor={selectId} className={cx("block", className)}>
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <select
        id={selectId}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
        className={cx(
          SOC_CONTROL_CLASSES.input,
          SOC_CONTROL_CLASSES.focus,
          "h-8 w-full px-2 text-xs"
        )}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}
