import type { ReactNode } from "react";
import EnterpriseSection from "./EnterpriseSection";

type EnterpriseChartCardProps = {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  height?: string;
};

export default function EnterpriseChartCard({
  title,
  description,
  actions,
  children,
  height = "h-64",
}: EnterpriseChartCardProps) {
  return (
    <EnterpriseSection title={title} description={description} actions={actions}>
      <div className={height}>{children}</div>
    </EnterpriseSection>
  );
}
