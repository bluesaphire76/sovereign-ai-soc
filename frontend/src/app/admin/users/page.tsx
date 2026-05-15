"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import AppNavigation from "../../../components/AppNavigation";
import { RefreshCw, UserPlus, Users } from "lucide-react";
import { authFetch, type AuthUser } from "../../../lib/auth";

type UsersResponse = {
  items: AuthUser[];
};

const ROLES = ["ADMIN", "ANALYST", "VIEWER"];

export default function AdminUsersPage() {
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState("ANALYST");
  const [password, setPassword] = useState("");

  const loadUsers = useCallback(async () => {
    try {
      setRefreshing(true);
      setError(null);

      const response = await authFetch("/users");

      if (!response.ok) {
        throw new Error(`API error ${response.status}`);
      }

      const data = (await response.json()) as UsersResponse;
      setUsers(data.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  async function createUser() {
    try {
      setCreating(true);
      setError(null);

      const response = await authFetch("/users", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          display_name: displayName || null,
          role,
          password,
          is_active: true,
        }),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail ?? `API error ${response.status}`));
      }

      setUsername("");
      setDisplayName("");
      setRole("ANALYST");
      setPassword("");
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setCreating(false);
    }
  }

  async function updateUser(userId: number, patch: Partial<AuthUser>) {
    try {
      setError(null);

      const response = await authFetch(`/users/${userId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(patch),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail ?? `API error ${response.status}`));
      }

      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    }
  }

  async function resetPassword(user: AuthUser) {
    const newPassword = window.prompt(
      `New password for ${user.username} - minimum 8 characters`
    );

    if (!newPassword) return;

    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    try {
      setError(null);

      const response = await authFetch(`/users/${user.id}/password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          password: newPassword,
        }),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(String(body?.detail ?? `API error ${response.status}`));
      }

      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-[1600px] px-4 py-4">
        <AppNavigation />

        <header className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div>
            <Link
              href="/"
              className="mb-2 inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200"
            >
              ← Dashboard
            </Link>

            <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-cyan-300">
              <Users className="h-3.5 w-3.5" />
              Administration
            </div>

            <h1 className="text-xl font-semibold tracking-tight">
              User Management
            </h1>

            <p className="mt-1 max-w-4xl text-xs leading-5 text-slate-500">
              Create and manage personal accounts for the Sovereign AI SOC
              console.
            </p>
          </div>

          <button
            onClick={loadUsers}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-slate-200 shadow-sm hover:bg-slate-800"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </header>

        {error && (
          <div className="mb-3 rounded-lg border border-red-800 bg-red-950/60 p-3 text-xs text-red-200">
            {error}
          </div>
        )}

        <div className="space-y-3">
          <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
            <div className="mb-3 flex items-center gap-2">
              <UserPlus className="h-3.5 w-3.5 text-cyan-300" />
              <h2 className="text-sm font-semibold">Create user</h2>
            </div>

            <div className="grid gap-2 md:grid-cols-[1fr_1fr_140px_1fr_120px]">
              <Input label="Username" value={username} onChange={setUsername} />
              <Input label="Display name" value={displayName} onChange={setDisplayName} />

              <label>
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
                  Role
                </span>
                <select
                  value={role}
                  onChange={(event) => setRole(event.target.value)}
                  className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
                >
                  {ROLES.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>

              <Input
                label="Password"
                value={password}
                onChange={setPassword}
                type="password"
              />

              <div className="flex items-end">
                <button
                  onClick={createUser}
                  disabled={creating || !username.trim() || password.length < 8}
                  className="h-8 w-full rounded-lg border border-cyan-700 bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {creating ? "Creating..." : "Create"}
                </button>
              </div>
            </div>
          </section>

          <section className="rounded-lg border border-slate-800 bg-slate-900 p-3 shadow-sm">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-sm font-semibold">Users</h2>
              <span className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                {users.length}
              </span>
            </div>

            {loading ? (
              <div className="rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-400">
                Loading users...
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-left text-xs">
                  <thead className="border-b border-slate-800 text-[10px] uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="px-2 py-1.5">Username</th>
                      <th className="px-2 py-1.5">Display name</th>
                      <th className="px-2 py-1.5">Role</th>
                      <th className="px-2 py-1.5">Status</th>
                      <th className="px-2 py-1.5">Last login</th>
                      <th className="px-2 py-1.5">Actions</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800/80">
                    {users.map((user) => (
                      <tr key={user.id} className="hover:bg-slate-800/40">
                        <td className="px-2 py-1.5 font-medium text-slate-100">
                          {user.username}
                        </td>
                        <td className="px-2 py-1.5 text-slate-300">
                          {user.display_name ?? "-"}
                        </td>
                        <td className="px-2 py-1.5">
                          <select
                            value={user.role}
                            onChange={(event) =>
                              updateUser(user.id, { role: event.target.value })
                            }
                            className="h-7 rounded-md border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-100"
                          >
                            {ROLES.map((item) => (
                              <option key={item} value={item}>
                                {item}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td className="px-2 py-1.5">
                          <button
                            onClick={() =>
                              updateUser(user.id, { is_active: !user.is_active })
                            }
                            className={`rounded-md border px-2 py-0.5 text-[11px] ${
                              user.is_active
                                ? "border-emerald-700 bg-emerald-950 text-emerald-200"
                                : "border-red-800 bg-red-950 text-red-200"
                            }`}
                          >
                            {user.is_active ? "ACTIVE" : "DISABLED"}
                          </button>
                        </td>
                        <td className="whitespace-nowrap px-2 py-1.5 text-slate-400">
                          {user.last_login_at ?? "-"}
                        </td>
                        <td className="px-2 py-1.5">
                          <button
                            onClick={() => resetPassword(user)}
                            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-0.5 text-[11px] text-slate-300 hover:bg-slate-800"
                          >
                            Reset password
                          </button>
                        </td>
                      </tr>
                    ))}

                    {users.length === 0 && (
                      <tr>
                        <td
                          colSpan={6}
                          className="px-2 py-4 text-center text-slate-500"
                        >
                          No users available.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}

function Input({
  label,
  value,
  onChange,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
}) {
  return (
    <label>
      <span className="mb-1 block text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 text-xs text-slate-100 outline-none focus:border-cyan-500"
      />
    </label>
  );
}
