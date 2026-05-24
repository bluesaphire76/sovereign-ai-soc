"use client";

import Link from "next/link";
import { useEffect } from "react";

export default function CaseDetailError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Case detail route failed", error);
  }, [error]);

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-10 text-slate-100">
      <div className="mx-auto max-w-3xl rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
        <div className="text-xs font-semibold uppercase tracking-[0.2em] text-orange-300">
          Case detail unavailable
        </div>
        <h1 className="mt-3 text-2xl font-semibold tracking-tight">
          This case page could not load
        </h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Reload the case view or return to the case queue. No case data was modified.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          <button
            type="button"
            onClick={reset}
            className="rounded-lg border border-cyan-700 bg-cyan-950 px-4 py-2 text-sm font-medium text-cyan-100 hover:border-cyan-500 hover:bg-cyan-900"
          >
            Reload case
          </button>
          <Link
            href="/cases"
            className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-medium text-slate-200 hover:border-slate-500 hover:bg-slate-900"
          >
            Back to cases
          </Link>
        </div>
      </div>
    </main>
  );
}
