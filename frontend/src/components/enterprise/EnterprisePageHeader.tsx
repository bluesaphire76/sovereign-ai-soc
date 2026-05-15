import type { ReactNode } from "react";

type EnterprisePageHeaderProps = {
  eyebrow?: string;
  title: string;
  description?: string;
  icon?: ReactNode;
  actions?: ReactNode;
};

export default function EnterprisePageHeader({
  eyebrow,
  title,
  description,
  icon,
  actions,
}: EnterprisePageHeaderProps) {
  return (
    <header className="mb-5 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
      <div>
        {(eyebrow || icon) && (
          <div className="mb-1.5 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
            {icon}
            {eyebrow}
          </div>
        )}

        <h1 className="text-2xl font-semibold tracking-tight text-slate-100">
          {title}
        </h1>

        {description && (
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">
            {description}
          </p>
        )}
      </div>

      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </header>
  );
}
