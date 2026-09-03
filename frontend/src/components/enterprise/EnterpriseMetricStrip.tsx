import type { ReactNode } from "react";
import { cx } from "@/lib/semantic-styles";

type EnterpriseMetricStripProps = {
  children: ReactNode;
  className?: string;
};

export default function EnterpriseMetricStrip({
  children,
  className,
}: EnterpriseMetricStripProps) {
  return (
    <div className={cx("grid min-w-0 gap-1.5 sm:grid-cols-2 lg:grid-cols-4", className)}>
      {children}
    </div>
  );
}
