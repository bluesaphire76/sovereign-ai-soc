"use client";

import { useEffect, useState, type FormEvent } from "react";
import { KeyRound } from "lucide-react";
import { EnterpriseButton, EnterpriseErrorState, EnterpriseModal } from "@/components/enterprise";
import { SOC_CONTROL_CLASSES } from "@/lib/semantic-styles";
import type { AuthUser } from "@/lib/auth";

export default function UserPasswordDialog({
  user,
  busy,
  error,
  onCancel,
  onSubmit,
}: {
  user: AuthUser | null;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onSubmit: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");

  useEffect(() => {
    if (user) return;
    const timer = window.setTimeout(() => setPassword(""), 0);
    return () => window.clearTimeout(timer);
  }, [user]);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (user && !busy && password.length >= 8) void onSubmit(password);
  }

  return (
    <EnterpriseModal
      open={Boolean(user)}
      title={user ? `Reset password for ${user.username}` : "Reset password"}
      onClose={onCancel}
      closeDisabled={busy}
      className="max-h-[calc(100dvh-2rem)] overflow-y-auto"
    >
      <form onSubmit={submit} aria-busy={busy}>
        <label className="block text-xs">
          <span className="mb-1 block font-medium text-slate-300">New password</span>
          <input
            type="password"
            autoComplete="new-password"
            autoFocus
            required
            minLength={8}
            value={password}
            disabled={busy}
            onChange={(event) => setPassword(event.target.value)}
            aria-describedby={`reset-password-hint${error ? " reset-password-error" : ""}`}
            className={`h-9 w-full px-3 text-sm ${SOC_CONTROL_CLASSES.input} ${SOC_CONTROL_CLASSES.focus}`}
          />
        </label>
        <p id="reset-password-hint" className="mt-1 text-xs text-slate-500">
          Minimum 8 characters.
        </p>
        {error && (
          <div id="reset-password-error" className="mt-3">
            <EnterpriseErrorState title="Password reset failed" message={error} />
          </div>
        )}
        <div className="mt-4 flex flex-wrap justify-end gap-2">
          <EnterpriseButton onClick={onCancel} disabled={busy}>
            Cancel
          </EnterpriseButton>
          <EnterpriseButton
            type="submit"
            tone="primary"
            disabled={busy || password.length < 8}
            icon={<KeyRound className="h-4 w-4" />}
          >
            {busy ? "Updating..." : "Reset password"}
          </EnterpriseButton>
        </div>
      </form>
    </EnterpriseModal>
  );
}
