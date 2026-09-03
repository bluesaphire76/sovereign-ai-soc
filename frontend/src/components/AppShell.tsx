import type { ReactNode } from "react";
import { cx } from "@/lib/semantic-styles";
import AppNavigation from "./AppNavigation";

export type AppShellWidth = "standard" | "wide" | "dense";

type AppShellProps = {
  children: ReactNode;
  width?: AppShellWidth;
  gutter?: "standard" | "compact";
  padding?: "standard" | "compact";
  contentClassName?: string;
};

const widthClasses: Record<AppShellWidth, string> = {
  standard: "max-w-[1600px]",
  wide: "max-w-[1800px]",
  dense: "max-w-[1900px]",
};

export default function AppShell({
  children,
  width = "standard",
  gutter = "standard",
  padding = "standard",
  contentClassName,
}: AppShellProps) {
  return (
    <main className="ai-soc-shell min-h-screen bg-slate-950 text-slate-100">
      <AppNavigation />
      <div className="ai-soc-shell-workspace min-w-0">
        <div
          className={cx(
            "ai-soc-shell-content mx-auto w-full",
            widthClasses[width],
            gutter === "compact" ? "px-3" : "px-4",
            padding === "compact" ? "py-3" : "py-4",
            contentClassName
          )}
        >
          {children}
        </div>
      </div>
    </main>
  );
}
