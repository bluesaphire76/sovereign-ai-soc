"use client";

import { type FormEvent, useEffect, useRef, useState } from "react";
import { Shield, LogIn, Loader2 } from "lucide-react";
import { EnterpriseButton, EnterpriseErrorState } from "@/components/enterprise";
import { SOC_CONTROL_CLASSES, SOC_TONE_CLASSES } from "@/lib/semantic-styles";
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
  const submitting = useRef(false);
  const [sessionNotice, setSessionNotice] = useState(false);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const session = new URLSearchParams(window.location.search).get("session");
      setSessionNotice(session === "expired" || session === "invalid");
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  async function handleLogin(event: FormEvent) {
    event.preventDefault();
    if (submitting.current || !username.trim() || !password.trim()) return;
    submitting.current = true;

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
        setError(
          response.status === 401
            ? "Invalid username or password."
            : response.status === 403
              ? "User account is disabled."
              : response.status === 400 || response.status === 422
                ? "Enter your username and password."
                : "Authentication service unavailable. Please try again.",
        );
        return;
      }

      const data = (await response.json()) as LoginResponse;
      await setAuthSession(data.access_token, data.user, data.expires_at);

      window.location.assign("/");
    } catch {
      setError("Unable to complete sign-in. Check your connection and try again.");
    } finally {
      submitting.current = false;
      setLoggingIn(false);
    }
  }

  return (
    <main className="flex min-h-dvh items-center justify-center bg-slate-950 px-4 py-8 text-slate-100">
      <form
        onSubmit={handleLogin}
        aria-busy={loggingIn}
        aria-describedby={error ? "login-error" : undefined}
        className="w-full max-w-sm rounded-sm border border-slate-800 bg-slate-900 p-5 shadow-sm"
      >
        <div className="mb-5 flex items-center gap-3">
          <div className="rounded-sm border border-cyan-900 bg-cyan-950 p-2 text-cyan-300">
            <Shield aria-hidden="true" className="h-5 w-5" />
          </div>

          <div>
            <div className="text-sm font-semibold uppercase tracking-wide">Sovereign AI SOC</div>
          </div>
        </div>

        <h1 className="mb-5 text-xl font-semibold">Sign in</h1>
        {sessionNotice && (
          <p
            role="status"
            className={`mb-4 rounded-sm border p-3 text-xs ${SOC_TONE_CLASSES.warning.panel} ${SOC_TONE_CLASSES.warning.text}`}
          >
            Your session is no longer available. Please sign in again.
          </p>
        )}

        <fieldset disabled={loggingIn} className="min-w-0 space-y-3">
          <label className="block">
            <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
              Username
            </span>
            <input
              name="username"
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className={`h-9 w-full px-3 text-sm ${SOC_CONTROL_CLASSES.input} ${SOC_CONTROL_CLASSES.focus}`}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              aria-describedby={error ? "login-error" : undefined}
            />
          </label>

          <label className="block">
            <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
              Password
            </span>
            <input
              name="password"
              type="password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className={`h-9 w-full px-3 text-sm ${SOC_CONTROL_CLASSES.input} ${SOC_CONTROL_CLASSES.focus}`}
              autoComplete="current-password"
              aria-describedby={error ? "login-error" : undefined}
            />
          </label>
        </fieldset>

        {error && (
          <div id="login-error" className="mt-4">
            <EnterpriseErrorState title="Sign-in failed" message={error} />
          </div>
        )}

        <EnterpriseButton
          type="submit"
          tone="primary"
          disabled={loggingIn || !username.trim() || !password.trim()}
          className="mt-5 w-full"
          icon={
            loggingIn ? (
              <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin" />
            ) : (
              <LogIn aria-hidden="true" className="h-4 w-4" />
            )
          }
        >
          {loggingIn ? "Signing in..." : "Sign in"}
        </EnterpriseButton>
      </form>
    </main>
  );
}
