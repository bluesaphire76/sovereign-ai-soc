"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent, type InputHTMLAttributes } from "react";
import AppShell from "@/components/AppShell";
import {
  EnterpriseBadge,
  EnterpriseBreadcrumbs,
  EnterpriseButton,
  EnterpriseConfirmationDialog,
  EnterpriseEmptyState,
  EnterpriseErrorState,
  EnterprisePageHeader,
  EnterpriseSection,
  EnterpriseSelect,
  EnterpriseSkeleton,
} from "@/components/enterprise";
import { KeyRound, Pencil, Power, RefreshCw, Trash2, UserPlus, Users } from "lucide-react";
import { SOC_CONTROL_CLASSES, SOC_TONE_CLASSES } from "@/lib/semantic-styles";
import { authFetch, fetchCurrentUser, type AuthUser } from "@/lib/auth";
import UserPasswordDialog from "./UserPasswordDialog";

type UsersResponse = { items: AuthUser[] };
type Confirmation = { operation: "delete" | "status"; user: AuthUser };
const ROLES = ["ADMIN", "ANALYST", "VIEWER"];
const ROLE_OPTIONS = ROLES.map((value) => ({ value, label: value }));
const ZURICH_DATE_TIME_FORMATTER = new Intl.DateTimeFormat("en-GB", {
  timeZone: "Europe/Zurich",
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  timeZoneName: "short",
});

function formatZurichDateTime(value?: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : ZURICH_DATE_TIME_FORMATTER.format(date);
}

async function userRequestError(response: Response) {
  if (response.status === 401) return "Session expired. Please sign in again.";
  if (response.status === 403) return "You are not authorized to perform this account operation.";
  if (response.status === 404) return "User not found. Refresh the account list.";
  if (response.status === 409) return "Username already exists.";
  if (response.status === 400 || response.status === 422) {
    const body = await response.json().catch(() => null);
    const safeMessages = [
      "Username is required.",
      "You cannot disable your own account.",
      "You cannot delete your own account.",
    ];
    return safeMessages.includes(body?.detail)
      ? (body.detail as string)
      : "Invalid account details. Check the fields and password length (minimum 8 characters).";
  }
  return "Account service unavailable. Please try again.";
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [mutating, setMutating] = useState(false);
  const mutationRunning = useRef(false);
  const loadSequence = useRef(0);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [passwordTarget, setPasswordTarget] = useState<AuthUser | null>(null);
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState("ANALYST");
  const [password, setPassword] = useState("");
  const isAdmin = currentUser?.role === "ADMIN";

  const loadUsers = useCallback(async () => {
    const sequence = ++loadSequence.current;
    setRefreshing(true);
    setError(null);
    setCurrentUser(null);
    setUsers([]);
    try {
      const current = await fetchCurrentUser();
      if (sequence !== loadSequence.current) return;
      setCurrentUser(current);
      const response = await authFetch("/users");
      if (!response.ok) throw new Error(await userRequestError(response));
      const data = (await response.json()) as UsersResponse;
      if (sequence === loadSequence.current) setUsers(data.items);
    } catch (err) {
      if (sequence === loadSequence.current)
        setError(
          err instanceof TypeError || err instanceof SyntaxError
            ? "Account service unavailable. Please try again."
            : err instanceof Error
              ? err.message
              : "Unable to load accounts.",
        );
    } finally {
      if (sequence === loadSequence.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadUsers(), 0);
    return () => {
      window.clearTimeout(timer);
      loadSequence.current += 1;
    };
  }, [loadUsers]);

  async function mutateUser(path: string, method: string, body: unknown, successMessage: string) {
    if (mutationRunning.current) return false;
    mutationRunning.current = true;
    setMutating(true);
    setError(null);
    setMessage(null);
    try {
      const response = await authFetch(path, {
        method,
        ...(body === undefined
          ? {}
          : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
      });
      if (!response.ok) throw new Error(await userRequestError(response));
      setMessage(successMessage);
      await loadUsers();
      return true;
    } catch (err) {
      setError(
        err instanceof TypeError || err instanceof SyntaxError
          ? "Account service unavailable. Please try again."
          : err instanceof Error
            ? err.message
            : "Account operation failed.",
      );
      return false;
    } finally {
      mutationRunning.current = false;
      setMutating(false);
    }
  }

  async function createUser(event: FormEvent) {
    event.preventDefault();
    if (!isAdmin || !username.trim() || password.length < 8) return;
    if (
      await mutateUser(
        "/users",
        "POST",
        {
          username,
          display_name: displayName || null,
          role,
          password,
          is_active: true,
        },
        "User created.",
      )
    ) {
      setUsername("");
      setDisplayName("");
      setRole("ANALYST");
      setPassword("");
    }
  }

  async function updateUser(userId: number, patch: Partial<AuthUser>) {
    if (!isAdmin) return false;
    if (userId === currentUser.id && patch.is_active === false) {
      setError("You cannot disable your own active account.");
      return false;
    }
    return mutateUser(`/users/${userId}`, "PATCH", patch, "User updated.");
  }

  async function updateDisplayName(user: AuthUser) {
    if (!isAdmin || mutating) return;
    const value = window.prompt(`Display name for ${user.username}`, user.display_name ?? "");
    if (value !== null) await updateUser(user.id, { display_name: value.trim() || null });
  }

  function toggleUserActive(user: AuthUser) {
    if (!isAdmin || mutating || (user.id === currentUser.id && user.is_active)) return;
    setError(null);
    setConfirmation({ operation: "status", user });
  }

  async function confirmOperation() {
    if (!confirmation || !isAdmin) return;
    const { user, operation } = confirmation;
    if (user.id === currentUser.id) return;
    const success =
      operation === "delete"
        ? await mutateUser(`/users/${user.id}`, "DELETE", undefined, "User deleted.")
        : await updateUser(user.id, { is_active: !user.is_active });
    if (success) setConfirmation(null);
  }

  async function resetPassword(newPassword: string) {
    if (
      !passwordTarget ||
      !currentUser ||
      (!isAdmin && passwordTarget.id !== currentUser.id) ||
      newPassword.length < 8
    )
      return;
    if (
      await mutateUser(
        `/users/${passwordTarget.id}/password`,
        "POST",
        { password: newPassword },
        "Password updated.",
      )
    ) {
      setPasswordTarget(null);
    }
  }

  const confirmationTitle =
    confirmation?.operation === "delete"
      ? "Delete user"
      : confirmation?.user.is_active
        ? "Disable user"
        : "Enable user";

  return (
    <AppShell>
      <EnterprisePageHeader
        title={isAdmin ? "User Management" : currentUser ? "User Profile" : "Users"}
        eyebrow={isAdmin ? "Administration" : currentUser ? "Self-service" : "Governance"}
        density="compact"
        icon={<Users aria-hidden="true" className="h-3.5 w-3.5" />}
        breadcrumbs={
          <EnterpriseBreadcrumbs items={[{ label: "Dashboard", href: "/" }, { label: "Users" }]} />
        }
        metadata={
          <>
            <EnterpriseBadge tone="neutral">{currentUser?.role ?? "Checking access"}</EnterpriseBadge>
            <EnterpriseBadge tone="muted">Europe/Zurich</EnterpriseBadge>
          </>
        }
        secondaryActions={
          <EnterpriseButton
            onClick={loadUsers}
            disabled={refreshing || mutating}
            size="xs"
            icon={<RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />}
          >
            Refresh
          </EnterpriseButton>
        }
      />

      {error && (
        <div id="users-error">
          <EnterpriseErrorState
            className="mb-3"
            title="Account request failed"
            message={error}
            onRetry={!mutating && !confirmation && !passwordTarget ? loadUsers : undefined}
          />
        </div>
      )}
      {message && (
        <div
          role="status"
          className={`mb-3 rounded-sm border p-3 text-xs ${SOC_TONE_CLASSES.success.panel} ${SOC_TONE_CLASSES.success.text}`}
        >
          {message}
        </div>
      )}

      <div className="space-y-4">
        {isAdmin && (
          <EnterpriseSection title="Create user" className="!border-0 !bg-transparent !p-0 !shadow-none">
            <form onSubmit={createUser} aria-describedby={error ? "users-error" : undefined}>
              <fieldset
                disabled={mutating || refreshing}
                className="grid min-w-0 items-end gap-2 sm:grid-cols-2 2xl:grid-cols-[1fr_1fr_140px_1fr_120px]"
              >
                <Input label="Username" value={username} onChange={setUsername} required autoComplete="off" />
                <Input label="Display name" value={displayName} onChange={setDisplayName} />
                <EnterpriseSelect label="Role" value={role} onChange={setRole} options={ROLE_OPTIONS} />
                <Input
                  label="Password (minimum 8 characters)"
                  value={password}
                  onChange={setPassword}
                  type="password"
                  required
                  minLength={8}
                  autoComplete="new-password"
                />
                <EnterpriseButton
                  type="submit"
                  tone="primary"
                  size="xs"
                  disabled={mutating || !username.trim() || password.length < 8}
                  icon={<UserPlus className="h-3.5 w-3.5" />}
                >
                  {mutating ? "Working..." : "Create"}
                </EnterpriseButton>
              </fieldset>
            </form>
          </EnterpriseSection>
        )}

        <EnterpriseSection
          title={isAdmin ? "Users" : "Account"}
          actions={<EnterpriseBadge tone="neutral">{users.length}</EnterpriseBadge>}
          className="!border-0 !bg-transparent !p-0 !shadow-none"
        >
          {loading || refreshing ? (
            <EnterpriseSkeleton label="Loading users" rows={4} />
          ) : error && users.length === 0 ? null : users.length === 0 ? (
            <EnterpriseEmptyState title="No users available." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1080px] text-left text-xs">
                <thead className="border-b border-slate-800 text-[10px] uppercase text-slate-500">
                  <tr>
                    {["Username", "Display name", "Role", "Status", "Last login", "Actions"].map((label) => (
                      <th key={label} scope="col" className="px-2 py-2">
                        {label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {users.map((user) => {
                    const own = user.id === currentUser?.id;
                    const canReset = Boolean(currentUser && (isAdmin || own));
                    return (
                      <tr key={user.id} className="align-top hover:bg-slate-900">
                        <td className="px-2 py-2 font-medium text-slate-100">
                          <span className="break-all">{user.username}</span>
                          {own && (
                            <span className="ml-2">
                              <EnterpriseBadge tone="primary" size="compact">
                                You
                              </EnterpriseBadge>
                            </span>
                          )}
                        </td>
                        <td className="px-2 py-2 text-slate-300">{user.display_name ?? "-"}</td>
                        <td className="px-2 py-2">
                          {isAdmin ? (
                            <select
                              aria-label={`Role for ${user.username}`}
                              value={user.role}
                              disabled={mutating}
                              onChange={(event) => void updateUser(user.id, { role: event.target.value })}
                              className={`h-7 px-2 text-xs ${SOC_CONTROL_CLASSES.input} ${SOC_CONTROL_CLASSES.focus}`}
                            >
                              {ROLES.map((item) => (
                                <option key={item}>{item}</option>
                              ))}
                            </select>
                          ) : (
                            <EnterpriseBadge tone="neutral" size="compact">
                              {user.role}
                            </EnterpriseBadge>
                          )}
                        </td>
                        <td className="px-2 py-2">
                          {isAdmin ? (
                            <EnterpriseButton
                              size="xs"
                              tone={user.is_active ? "secondary" : "ghost"}
                              disabled={mutating || own}
                              title={own ? "You cannot disable your own account." : undefined}
                              ariaLabel={`Change account status for ${user.username}`}
                              onClick={() => toggleUserActive(user)}
                            >
                              {user.is_active ? "ACTIVE" : "DISABLED"}
                            </EnterpriseButton>
                          ) : (
                            <EnterpriseBadge tone={user.is_active ? "primary" : "neutral"} size="compact">
                              {user.is_active ? "ACTIVE" : "DISABLED"}
                            </EnterpriseBadge>
                          )}
                        </td>
                        <td
                          className="whitespace-nowrap px-2 py-2 text-slate-400"
                          title={user.last_login_at ?? undefined}
                        >
                          {formatZurichDateTime(user.last_login_at)}
                        </td>
                        <td className="px-2 py-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <EnterpriseButton
                              size="xs"
                              tone="primary"
                              disabled={!canReset || mutating}
                              icon={<KeyRound className="h-3.5 w-3.5" />}
                              onClick={() => {
                                if (canReset) {
                                  setError(null);
                                  setPasswordTarget(user);
                                }
                              }}
                            >
                              Reset password
                            </EnterpriseButton>
                            {isAdmin && (
                              <>
                                <EnterpriseButton
                                  size="xs"
                                  disabled={mutating}
                                  icon={<Pencil className="h-3.5 w-3.5" />}
                                  onClick={() => updateDisplayName(user)}
                                >
                                  Edit
                                </EnterpriseButton>
                                <EnterpriseButton
                                  size="xs"
                                  tone={user.is_active ? "warning" : "primary"}
                                  disabled={mutating || own}
                                  title={own ? "You cannot disable your own account." : undefined}
                                  icon={<Power className="h-3.5 w-3.5" />}
                                  onClick={() => toggleUserActive(user)}
                                >
                                  {user.is_active ? "Disable" : "Enable"}
                                </EnterpriseButton>
                                <span className="border-l border-slate-700 pl-2">
                                  <EnterpriseButton
                                    size="xs"
                                    tone="danger"
                                    disabled={mutating || own}
                                    title={own ? "You cannot delete your own account." : undefined}
                                    icon={<Trash2 className="h-3.5 w-3.5" />}
                                    onClick={() => {
                                      if (!own) {
                                        setError(null);
                                        setConfirmation({ operation: "delete", user });
                                      }
                                    }}
                                  >
                                    Delete
                                  </EnterpriseButton>
                                </span>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </EnterpriseSection>
      </div>

      <EnterpriseConfirmationDialog
        open={Boolean(confirmation)}
        title={confirmationTitle}
        description={
          confirmation
            ? `${confirmationTitle} ${confirmation.user.username}?${confirmation.operation === "delete" ? " This action cannot be undone." : ""}`
            : undefined
        }
        confirmLabel={confirmationTitle}
        confirmTone={
          confirmation?.operation === "delete"
            ? "danger"
            : confirmation?.user.is_active
              ? "warning"
              : "primary"
        }
        busy={mutating}
        onCancel={() => setConfirmation(null)}
        onConfirm={confirmOperation}
      >
        {error && <EnterpriseErrorState title="Account operation failed" message={error} />}
      </EnterpriseConfirmationDialog>
      <UserPasswordDialog
        user={passwordTarget}
        busy={mutating}
        error={error}
        onCancel={() => setPasswordTarget(null)}
        onSubmit={resetPassword}
      />
    </AppShell>
  );
}

function Input({
  label,
  value,
  onChange,
  ...props
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
} & Pick<InputHTMLAttributes<HTMLInputElement>, "type" | "autoComplete" | "required" | "minLength">) {
  return (
    <label className="block min-w-0">
      <span className="mb-1 block text-[10px] font-medium uppercase text-slate-500">{label}</span>
      <input
        {...props}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className={`h-8 w-full px-2 text-xs ${SOC_CONTROL_CLASSES.input} ${SOC_CONTROL_CLASSES.focus}`}
      />
    </label>
  );
}
