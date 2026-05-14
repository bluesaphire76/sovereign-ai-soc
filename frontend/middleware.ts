import { NextRequest, NextResponse } from "next/server";

function authEnabled() {
  return (process.env.LOCAL_AUTH_ENABLED ?? "true").toLowerCase() !== "false";
}

function cookieName() {
  return process.env.LOCAL_AUTH_COOKIE_NAME || "ai_soc_session";
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

async function sha256Hex(value: string) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function expectedToken() {
  return sha256Hex(
    `${configuredUsername()}:${configuredPassword()}:${configuredSecret()}`
  );
}

function isPublicPath(pathname: string) {
  return (
    pathname === "/login" ||
    pathname.startsWith("/api/auth") ||
    pathname.startsWith("/_next") ||
    pathname === "/favicon.ico"
  );
}

export async function middleware(request: NextRequest) {
  if (!authEnabled()) {
    return NextResponse.next();
  }

  const { pathname } = request.nextUrl;

  if (isPublicPath(pathname)) {
    return NextResponse.next();
  }

  const currentToken = request.cookies.get(cookieName())?.value;
  const validToken = await expectedToken();

  if (currentToken === validToken) {
    return NextResponse.next();
  }

  const loginUrl = request.nextUrl.clone();
  loginUrl.pathname = "/login";
  loginUrl.searchParams.set("next", pathname);

  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
