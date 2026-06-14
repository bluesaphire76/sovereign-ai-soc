import { redirect } from "next/navigation";

export default function AdminOperationHistoryRedirect() {
  redirect("/system-information/operation-history");
}
