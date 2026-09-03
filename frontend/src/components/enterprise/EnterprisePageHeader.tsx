import type { ReactNode } from "react";
import { SOC_TEXT_CLASSES, cx } from "@/lib/semantic-styles";

type EnterprisePageHeaderProps = {
  eyebrow?: string;
  title: string;
  description?: string;
  icon?: ReactNode;
  breadcrumbs?: ReactNode;
  metadata?: ReactNode;
  status?: ReactNode;
  primaryAction?: ReactNode;
  secondaryActions?: ReactNode;
  actions?: ReactNode;
  density?: "compact" | "standard";
  divided?: boolean;
  className?: string;
};

export default function EnterprisePageHeader({
  eyebrow,
  title,
  description,
  icon,
  breadcrumbs,
  metadata,
  status,
  primaryAction,
  secondaryActions,
  actions,
  density = "standard",
  divided = false,
  className,
}: EnterprisePageHeaderProps) {
  const hasActions = Boolean(actions || secondaryActions || primaryAction);

  return (
    <header
      className={cx(
        "flex flex-col gap-3 md:flex-row md:items-start md:justify-between",
        density === "compact" ? "mb-4" : "mb-5",
        divided && "border-b border-slate-800 pb-4",
        className
      )}
    >
      <div className="min-w-0 flex-1">
        {breadcrumbs && <div className="mb-2">{breadcrumbs}</div>}

        {(eyebrow || icon) && (
          <div className="mb-1.5 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
            {icon}
            {eyebrow}
          </div>
        )}

        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h1
            className={
              density === "compact"
                ? SOC_TEXT_CLASSES.compactPageTitle
                : SOC_TEXT_CLASSES.pageTitle
            }
          >
            {title}
          </h1>
          {status}
        </div>

        {description && (
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">
            {description}
          </p>
        )}

        {metadata && <div className="mt-2 flex flex-wrap gap-2">{metadata}</div>}
      </div>

      {hasActions && (
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {secondaryActions}
          {actions}
          {primaryAction}
        </div>
      )}
    </header>
  );
}
