"use client";

import { FormEvent, Suspense, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Lock, Shield } from "lucide-react";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const nextPath = useMemo(() => {
    return searchParams.get("next") || "/";
  }, [searchParams]);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    try {
      setSubmitting(true);
      setError(null);

      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          password,
        }),
      });

      if (!response.ok) {
        setError("Invalid username or password.");
        return;
      }

      router.push(nextPath);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="w-full rounded-3xl border border-slate-800 bg-slate-900 p-8 shadow-2xl">
      <div className="mb-8">
        <div className="mb-4 inline-flex rounded-2xl bg-slate-950 p-3 text-cyan-300">
          <Shield className="h-7 w-7" />
        </div>

        <h1 className="text-3xl font-semibold tracking-tight">
          Sovereign AI SOC
        </h1>

        <p className="mt-2 text-sm text-slate-400">
          Local dashboard authentication.
        </p>
      </div>

      {error && (
        <div className="mb-5 rounded-xl border border-red-800 bg-red-950/60 p-3 text-sm text-red-200">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-5">
        <div>
          <label className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
            Username
          </label>
          <input
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-100 outline-none focus:border-cyan-500"
            autoComplete="username"
          />
        </div>

        <div>
          <label className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
            Password
          </label>
          <input
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            type="password"
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-100 outline-none focus:border-cyan-500"
            autoComplete="current-password"
            autoFocus
          />
        </div>

        <button
          type="submit"
          disabled={submitting}
          className="flex w-full items-center justify-center gap-2 rounded-xl border border-cyan-700 bg-cyan-500 px-4 py-3 text-sm font-medium text-slate-950 shadow-sm hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Lock className="h-4 w-4" />
          {submitting ? "Signing in..." : "Sign in"}
        </button>
      </form>

      <p className="mt-6 text-xs leading-5 text-slate-500">
        Credentials are read from the local frontend environment file.
      </p>
    </div>
  );
}

function LoginFallback() {
  return (
    <div className="w-full rounded-3xl border border-slate-800 bg-slate-900 p-8 shadow-2xl">
      <div className="text-sm text-slate-400">Loading login...</div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-md items-center px-6">
        <Suspense fallback={<LoginFallback />}>
          <LoginForm />
        </Suspense>
      </div>
    </main>
  );
}
