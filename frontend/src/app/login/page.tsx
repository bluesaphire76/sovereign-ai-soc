"use client";

import { FormEvent, useEffect, useState } from "react";
import { Shield, LogIn } from "lucide-react";
import { API_BASE, setAuthSession, type AuthUser } from "../../lib/auth";

type LoginResponse = {
  access_token: string;
  token_type: string;
  expires_at: number;
  user: AuthUser;
};



export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loggingIn, setLoggingIn] = useState(false);


  async function handleLogin(event: FormEvent) {
    event.preventDefault();

    try {
      setLoggingIn(true);
      setError(null);

      const response = await fetch(`${API_BASE}/auth/login`, {
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
        let message = `Login failed: ${response.status}`;

        try {
          const body = await response.json();
          message = body?.detail ?? message;
        } catch {
          // keep default message
        }

        throw new Error(String(message));
      }

      const data = (await response.json()) as LoginResponse;
      await setAuthSession(data.access_token, data.user, data.expires_at);

      window.location.assign("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown login error");
    } finally {
      setLoggingIn(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4 text-slate-100">
      <form
        onSubmit={handleLogin}
        className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-2xl"
      >
        <div className="mb-5 flex items-center gap-3">
          <div className="rounded-lg border border-cyan-900 bg-cyan-950 p-2 text-cyan-300">
            <Shield className="h-5 w-5" />
          </div>

          <div>
            <div className="text-sm font-semibold uppercase tracking-wide">
              Sovereign AI SOC
            </div>
            <div className="text-xs text-slate-500">
              Personal login required
            </div>
          </div>
        </div>

        <h1 className="mb-1 text-xl font-semibold tracking-tight">Sign in</h1>

        <p className="mb-5 text-xs leading-5 text-slate-500">
          Use your personal SOC account to access dashboards, cases, incidents
          and administrative functions.
        </p>

        <div className="space-y-3">
          <label>
            <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
              Username
            </span>
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="h-9 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 outline-none focus:border-cyan-500"
              autoComplete="username"
            />
          </label>

          <label>
            <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
              Password
            </span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="h-9 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 outline-none focus:border-cyan-500"
              autoComplete="current-password"
            />
          </label>
        </div>

        {error && (
          <div className="mt-4 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loggingIn || !username.trim() || !password.trim()}
          className="mt-5 flex h-9 w-full items-center justify-center gap-2 rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <LogIn className="h-4 w-4" />
          {loggingIn ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </main>
  );
}
