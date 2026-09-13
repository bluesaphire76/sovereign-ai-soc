import type { ReactNode } from "react";
import { AlertTriangle, Inbox } from "lucide-react";
import { SOC_TONE_CLASSES, cx } from "@/lib/semantic-styles";
import EnterpriseButton from "./EnterpriseButton";

type EnterpriseSkeletonProps = {
  label?: string;
  rows?: number;
  className?: string;
};

export function EnterpriseSkeleton({
  label = "Loading",
  rows = 3,
  className,
}: EnterpriseSkeletonProps) {
  return (
    <div role="status" aria-live="polite" className={cx("space-y-2 py-2", className)}>
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, index) => (
        <div
          key={index}
          aria-hidden="true"
          className={cx(
            "h-8 animate-pulse rounded-sm bg-slate-800",
            index === rows - 1 && "w-3/4"
          )}
        />
      ))}
    </div>
  );
}

type EnterpriseEmptyStateProps = {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
};

export function EnterpriseEmptyState({
  title,
  description,
  icon = <Inbox className="h-5 w-5" />,
  action,
  className,
}: EnterpriseEmptyStateProps) {
  return (
    <div className={cx("py-8 text-center", className)}>
      <div className="mx-auto mb-2 flex h-8 w-8 items-center justify-center rounded-sm bg-slate-900 text-slate-500">
        {icon}
      </div>
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {description && <p className="mx-auto mt-1 max-w-xl text-xs text-slate-500">{description}</p>}
      {action && <div className="mt-3 flex justify-center">{action}</div>}
    </div>
  );
}

type EnterpriseErrorStateProps = {
  title: string;
  message?: string;
  onRetry?: () => void | Promise<void>;
  retryLabel?: string;
  className?: string;
};

export function EnterpriseErrorState({
  title,
  message,
  onRetry,
  retryLabel = "Retry",
  className,
}: EnterpriseErrorStateProps) {
  return (
    <div
      role="alert"
      className={cx(
        "flex items-start gap-3 rounded-sm border p-3 text-xs",
        SOC_TONE_CLASSES.danger.panel,
        SOC_TONE_CLASSES.danger.text,
        className
      )}
    >
      <AlertTriangle aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0 flex-1">
        <p className="font-semibold">{title}</p>
        {message && <p className="mt-1 break-words text-red-200/80">{message}</p>}
      </div>
      {onRetry && (
        <EnterpriseButton onClick={onRetry} tone="danger" size="xs">
          {retryLabel}
        </EnterpriseButton>
      )}
    </div>
  );
}
