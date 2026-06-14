import { redirect } from "next/navigation";

export default function AdminSecurityAuditRedirect() {
  redirect("/system-information/security-audit");
}
