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
const EXPIRES_AT_KEY = "ai_soc_access_token_expires_at";
const COOKIE_NAME = "ai_soc_access_token";
const DEFAULT_SESSION_MAX_AGE_SECONDS = 60 * 60 * 8;
const EXPIRY_SKEW_SECONDS = 30;

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8008";

export function getAuthToken(): string | null {
  if (typeof window === "undefined") return null;

  if (isStoredSessionExpired()) {
    clearAuthSessionStorage();
    return null;
  }

  return window.localStorage.getItem(TOKEN_KEY);
}

export function getStoredUser(): AuthUser | null {
  if (typeof window === "undefined") return null;

  if (isStoredSessionExpired()) {
    clearAuthSessionStorage();
    return null;
  }

  const value = window.localStorage.getItem(USER_KEY);

  if (!value) return null;

  try {
    return JSON.parse(value) as AuthUser;
  } catch {
    return null;
  }
}

export function getStoredTokenExpiresAt(): number | null {
  if (typeof window === "undefined") return null;

  const rawValue = window.localStorage.getItem(EXPIRES_AT_KEY);

  if (!rawValue) return null;

  const value = Number(rawValue);

  if (!Number.isFinite(value) || value <= 0) {
    return null;
  }

  return value;
}

export function isStoredSessionExpired(skewSeconds = EXPIRY_SKEW_SECONDS) {
  if (typeof window === "undefined") return false;

  const expiresAt = getStoredTokenExpiresAt();

  if (!expiresAt) return false;

  const now = Math.floor(Date.now() / 1000);

  return expiresAt <= now + skewSeconds;
}

function sessionMaxAgeSeconds(expiresAt?: number | null) {
  if (!expiresAt) return DEFAULT_SESSION_MAX_AGE_SECONDS;

  const now = Math.floor(Date.now() / 1000);
  const remaining = expiresAt - now;

  if (!Number.isFinite(remaining) || remaining <= 0) {
    return 0;
  }

  return Math.min(remaining, DEFAULT_SESSION_MAX_AGE_SECONDS);
}

function clearAuthSessionStorage() {
  if (typeof window === "undefined") return;

  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
  window.localStorage.removeItem(EXPIRES_AT_KEY);

  document.cookie = `${COOKIE_NAME}=; path=/; max-age=0; SameSite=Lax`;
}

function redirectToLogin(reason = "expired") {
  if (typeof window === "undefined") return;

  if (window.location.pathname === "/login") return;

  const target = `/login?session=${encodeURIComponent(reason)}`;
  window.location.assign(target);
}

export async function setAuthSession(
  token: string,
  user: AuthUser,
  expiresAt?: number | null
) {
  const maxAgeSeconds = sessionMaxAgeSeconds(expiresAt);

  window.localStorage.setItem(TOKEN_KEY, token);
  window.localStorage.setItem(USER_KEY, JSON.stringify(user));

  if (expiresAt) {
    window.localStorage.setItem(EXPIRES_AT_KEY, String(expiresAt));
  } else {
    window.localStorage.removeItem(EXPIRES_AT_KEY);
  }

  document.cookie = `${COOKIE_NAME}=${encodeURIComponent(
    token
  )}; path=/; max-age=${maxAgeSeconds}; SameSite=Lax`;

  await fetch("/api/auth/session", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      token,
      max_age_seconds: maxAgeSeconds,
    }),
  });
}

export async function clearAuthSession() {
  clearAuthSessionStorage();

  await fetch("/api/auth/logout", {
    method: "POST",
  }).catch(() => {
    // ignore logout cookie cleanup errors
  });
}

export async function handleUnauthorizedSession(reason = "expired") {
  await clearAuthSession();
  redirectToLogin(reason);
}

export async function authFetch(path: string, init: RequestInit = {}) {
  if (isStoredSessionExpired()) {
    await handleUnauthorizedSession("expired");

    return new Response(
      JSON.stringify({
        detail: "Session expired.",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const token = getAuthToken();

  const headers = new Headers(init.headers);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  });

  if (response.status === 401) {
    await handleUnauthorizedSession("expired");
  }

  return response;
}

export async function fetchCurrentUser(): Promise<AuthUser> {
  const response = await authFetch("/auth/me");

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("Session expired. Please sign in again.");
    }

    throw new Error(`Authentication failed: ${response.status}`);
  }

  return response.json();
}
