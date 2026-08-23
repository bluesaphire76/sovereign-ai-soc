import AppNavigation from "@/components/AppNavigation";
import GlobalAssistantWorkspace from "@/components/assistant/GlobalAssistantWorkspace";

export default function GlobalAssistantPage() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1900px] px-4 py-4">
        <AppNavigation />
        <GlobalAssistantWorkspace />
      </div>
    </main>
  );
}
