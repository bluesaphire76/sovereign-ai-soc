"use client";

import { useId, type InputHTMLAttributes } from "react";
import { Search, X } from "lucide-react";
import { cx } from "@/lib/semantic-styles";
import EnterpriseIconButton from "./EnterpriseIconButton";

type EnterpriseSearchInputProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  "onChange" | "type" | "value"
> & {
  label: string;
  value: string;
  onChange: (value: string) => void;
  hideLabel?: boolean;
  onClear?: () => void;
  containerClassName?: string;
};

export default function EnterpriseSearchInput({
  label,
  value,
  onChange,
  hideLabel = false,
  onClear,
  className,
  containerClassName,
  disabled,
  ...props
}: EnterpriseSearchInputProps) {
  const inputId = useId();

  return (
    <div className={cx("block", containerClassName)}>
      <label
        htmlFor={inputId}
        className={cx(
          "mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500",
          hideLabel && "sr-only"
        )}
      >
        {label}
      </label>
      <span className="flex h-9 items-center gap-1.5 rounded-sm border border-slate-700 bg-slate-950 px-2 transition focus-within:border-cyan-500 focus-within:ring-2 focus-within:ring-cyan-400/30">
        <Search aria-hidden="true" className="h-3.5 w-3.5 shrink-0 text-slate-500" />
        <input
          id={inputId}
          type="search"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          disabled={disabled}
          className={cx(
            "h-full min-w-0 flex-1 appearance-none bg-transparent text-xs text-slate-100 outline-none placeholder:text-slate-600 disabled:cursor-not-allowed disabled:opacity-60",
            className
          )}
          {...props}
        />
        {value && onClear && !disabled ? (
          <EnterpriseIconButton
            icon={<X className="h-3.5 w-3.5" />}
            label={`Clear ${label.toLowerCase()}`}
            onClick={onClear}
            tone="ghost"
            size="xs"
            className="h-6 w-6"
          />
        ) : null}
      </span>
    </div>
  );
}
