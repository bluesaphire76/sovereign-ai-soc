import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { SOC_CONTROL_CLASSES, cx } from "@/lib/semantic-styles";

export type EnterpriseBreadcrumbItem = {
  label: string;
  href?: string;
};

type EnterpriseBreadcrumbsProps = {
  items: readonly EnterpriseBreadcrumbItem[];
  className?: string;
};

export default function EnterpriseBreadcrumbs({
  items,
  className,
}: EnterpriseBreadcrumbsProps) {
  if (items.length < 2) return null;

  return (
    <nav aria-label="Breadcrumb" className={className}>
      <ol className="flex min-w-0 flex-wrap items-center gap-1 text-[11px] text-slate-500">
        {items.map((item, index) => {
          const current = index === items.length - 1;

          return (
            <li key={`${item.label}-${index}`} className="flex min-w-0 items-center gap-1">
              {index > 0 && (
                <ChevronRight
                  aria-hidden="true"
                  className="h-3 w-3 shrink-0 text-slate-700"
                  strokeWidth={1.75}
                />
              )}

              {item.href && !current ? (
                <Link
                  href={item.href}
                  className={cx(
                    "rounded-sm text-slate-400 transition hover:text-cyan-200",
                    SOC_CONTROL_CLASSES.focus
                  )}
                >
                  {item.label}
                </Link>
              ) : (
                <span
                  aria-current={current ? "page" : undefined}
                  className={cx("truncate", current && "text-slate-300")}
                >
                  {item.label}
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
