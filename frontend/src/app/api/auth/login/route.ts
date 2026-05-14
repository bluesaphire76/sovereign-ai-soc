import { scryptSync } from "crypto";
import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";

function authEnabled() {
  return (process.env.LOCAL_AUTH_ENABLED ?? "true").toLowerCase() !== "false";
}

function cookieName() {
  return process.env.LOCAL_AUTH_COOKIE_NAME || "ai_soc_session";
}

function cookieSecure() {
  return (process.env.LOCAL_AUTH_COOKIE_SECURE ?? "false").toLowerCase() === "true";
}

function configuredUsername() {
  return process.env.LOCAL_AUTH_USERNAME || "admin";
}

function configuredPassword() {
  return process.env.LOCAL_AUTH_PASSWORD || "admin";
}

function configuredSecret() {
  return process.env.LOCAL_AUTH_SESSION_SECRET || "local-dev-secret";
}

function scryptHex(value: string) {
  const salt = `local-auth-session:${configuredSecret()}`;
  return scryptSync(value, salt, 32).toString("hex");
}

function expectedToken() {
  return scryptHex(
    `${configuredUsername()}:${configuredPassword()}:${configuredSecret()}`
  );
}

export async function POST(request: NextRequest) {
  if (!authEnabled()) {
    return NextResponse.json({ ok: true, auth_enabled: false });
  }

  const payload = await request.json().catch(() => null);

  const username = String(payload?.username ?? "");
  const password = String(payload?.password ?? "");

  if (username !== configuredUsername() || password !== configuredPassword()) {
    return NextResponse.json(
      {
        ok: false,
        error: "Invalid username or password",
      },
      {
        status: 401,
      }
    );
  }

  const response = NextResponse.json({
    ok: true,
  });

  response.cookies.set(cookieName(), expectedToken(), {
    httpOnly: true,
    sameSite: "lax",
    secure: cookieSecure(),
    path: "/",
    maxAge: 60 * 60 * 8,
  });

  return response;
}
