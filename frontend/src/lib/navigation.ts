export type NavigationMatch = "exact" | "prefix" | "cases";

export type NavigationIcon =
  | "activity"
  | "bot"
  | "briefcase"
  | "chart"
  | "columns"
  | "cpu"
  | "database"
  | "dashboard"
  | "globe"
  | "health"
  | "history"
  | "network"
  | "shield"
  | "shield-alert"
  | "shield-check"
  | "users";

export type NavigationItem = {
  href: string;
  label: string;
  icon: NavigationIcon;
  match: NavigationMatch;
  external?: boolean;
  roles?: readonly string[];
  requiresAuthentication?: boolean;
};

export type NavigationGroup = {
  label: string;
  items: readonly NavigationItem[];
};

const ALL_STANDARD_ROLES = ["ADMIN", "ANALYST", "VIEWER"] as const;
const OPERATOR_ROLES = ["ADMIN", "ANALYST"] as const;

const NAVIGATION_GROUPS: readonly NavigationGroup[] = [
  {
    label: "Overview",
    items: [
      { href: "/", label: "Dashboard", icon: "dashboard", match: "exact" },
      { href: "/executive", label: "Executive", icon: "chart", match: "prefix" },
    ],
  },
  {
    label: "Investigation",
    items: [
      { href: "/incidents", label: "Incidents", icon: "shield-alert", match: "prefix" },
      { href: "/cases", label: "Cases", icon: "briefcase", match: "cases" },
      { href: "/cases/kanban", label: "Case Kanban", icon: "columns", match: "prefix" },
    ],
  },
  {
    label: "Detection",
    items: [
      { href: "/detection-quality", label: "Detection Quality", icon: "shield", match: "prefix" },
      {
        href: "/settings/detection-control",
        label: "Detection Control Plane",
        icon: "shield-check",
        match: "prefix",
        roles: ALL_STANDARD_ROLES,
      },
    ],
  },
  {
    label: "Operations / Telemetry",
    items: [
      { href: "/health", label: "Health", icon: "health", match: "prefix" },
      { href: "/network-events", label: "Network Events", icon: "network", match: "prefix" },
      { href: "/dns-telemetry", label: "DNS Telemetry", icon: "globe", match: "exact" },
      {
        href: "/system-information/operation-history",
        label: "Operation History",
        icon: "history",
        match: "prefix",
        roles: ALL_STANDARD_ROLES,
      },
      {
        href: "__OBSERVABILITY__",
        label: "Observability",
        icon: "activity",
        match: "exact",
        external: true,
        roles: OPERATOR_ROLES,
      },
    ],
  },
  {
    label: "Governance",
    items: [
      {
        href: "/admin/users",
        label: "Users",
        icon: "users",
        match: "prefix",
        requiresAuthentication: true,
      },
      {
        href: "/system-information/security-audit",
        label: "Security Audit",
        icon: "shield-check",
        match: "prefix",
        roles: ["ADMIN"],
      },
      {
        href: "/settings/ai-providers",
        label: "AI Providers",
        icon: "cpu",
        match: "prefix",
        roles: ALL_STANDARD_ROLES,
      },
      {
        href: "/settings/ai-data-control",
        label: "AI Data Control",
        icon: "shield",
        match: "prefix",
        roles: ALL_STANDARD_ROLES,
      },
      {
        href: "/settings/semantic-memory",
        label: "Semantic Memory",
        icon: "database",
        match: "prefix",
        roles: OPERATOR_ROLES,
      },
    ],
  },
  {
    label: "AI",
    items: [
      {
        href: "/assistant",
        label: "Assistant",
        icon: "bot",
        match: "prefix",
        roles: OPERATOR_ROLES,
      },
    ],
  },
];

function canShowNavigationItem(item: NavigationItem, role: string | null) {
  if (item.roles) {
    return role !== null && item.roles.includes(role);
  }

  if (item.requiresAuthentication) {
    return role !== null;
  }

  return true;
}

export function getNavigationGroups(role: string | null): NavigationGroup[] {
  return NAVIGATION_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => canShowNavigationItem(item, role)),
  })).filter((group) => group.items.length > 0);
}

export function isNavigationItemActive(pathname: string, item: NavigationItem) {
  if (item.external) return false;
  if (item.match === "exact") return pathname === item.href;

  if (item.match === "cases") {
    return (
      pathname === "/cases" ||
      (pathname.startsWith("/cases/") && !pathname.startsWith("/cases/kanban"))
    );
  }

  return pathname === item.href || pathname.startsWith(`${item.href}/`);
}
