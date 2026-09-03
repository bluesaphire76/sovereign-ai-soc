import type { ReactNode } from "react";
import { SOC_CONTROL_CLASSES, SOC_TEXT_CLASSES, cx } from "@/lib/semantic-styles";

type EnterprisePanelProps = {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
};

export default function EnterprisePanel({
  title,
  description,
  actions,
  children,
  className,
}: EnterprisePanelProps) {
  return (
    <section className={cx(SOC_CONTROL_CLASSES.panel, "p-3 shadow-sm", className)}>
      {(title || description || actions) && (
        <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            {title && <h2 className={SOC_TEXT_CLASSES.cardTitle}>{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-slate-500">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}
