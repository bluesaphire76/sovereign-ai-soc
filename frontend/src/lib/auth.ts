export type AuthUser = {
  id: number;
  username: string;
  display_name: string | null;
  role: "ADMIN" | "ANALYST" | "VIEWER" | string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string | null;
  updated_at: string | null;
};

const TOKEN_KEY = "ai_soc_access_token";
const USER_KEY = "ai_soc_user";
const COOKIE_NAME = "ai_soc_access_token";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

export function getAuthToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function getStoredUser(): AuthUser | null {
  if (typeof window === "undefined") return null;

  const value = window.localStorage.getItem(USER_KEY);

  if (!value) return null;

  try {
    return JSON.parse(value) as AuthUser;
  } catch {
    return null;
  }
}

export async function setAuthSession(token: string, user: AuthUser) {
  window.localStorage.setItem(TOKEN_KEY, token);
  window.localStorage.setItem(USER_KEY, JSON.stringify(user));

  document.cookie = `${COOKIE_NAME}=${encodeURIComponent(
    token
  )}; path=/; max-age=28800; SameSite=Lax`;

  await fetch("/api/auth/session", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token }),
  });
}

export async function clearAuthSession() {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);

  document.cookie = `${COOKIE_NAME}=; path=/; max-age=0; SameSite=Lax`;

  await fetch("/api/auth/logout", {
    method: "POST",
  }).catch(() => {
    // ignore logout cookie cleanup errors
  });
}

export async function authFetch(path: string, init: RequestInit = {}) {
  const token = getAuthToken();

  const headers = new Headers(init.headers);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  return fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  });
}

export async function fetchCurrentUser(): Promise<AuthUser> {
  const response = await authFetch("/auth/me");

  if (!response.ok) {
    throw new Error(`Authentication failed: ${response.status}`);
  }

  return response.json();
}
