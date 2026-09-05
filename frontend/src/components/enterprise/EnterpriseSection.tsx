import type { ReactNode } from "react";
import { SOC_CONTROL_CLASSES, cx } from "@/lib/semantic-styles";

type EnterpriseSectionProps = {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  dense?: boolean;
  className?: string;
};

export default function EnterpriseSection({
  title,
  description,
  actions,
  children,
  dense = true,
  className,
}: EnterpriseSectionProps) {
  return (
    <section
      className={cx(
        SOC_CONTROL_CLASSES.section,
        "min-w-0",
        dense ? "p-4" : "p-5",
        className
      )}
    >
      {(title || description || actions) && (
        <div className="mb-4 flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
          <div className="min-w-0">
            {title && (
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-200">
                {title}
              </h2>
            )}

            {description && (
              <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">
                {description}
              </p>
            )}
          </div>

          {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
        </div>
      )}

      {children}
    </section>
  );
}
