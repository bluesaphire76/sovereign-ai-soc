import { NextResponse } from "next/server";

export const runtime = "nodejs";

function cookieName() {
  return process.env.LOCAL_AUTH_COOKIE_NAME || "ai_soc_session";
}

function cookieSecure() {
  return (process.env.LOCAL_AUTH_COOKIE_SECURE ?? "false").toLowerCase() === "true";
}

export async function POST() {
  const response = NextResponse.json({
    ok: true,
  });

  response.cookies.set(cookieName(), "", {
    httpOnly: true,
    sameSite: "lax",
    secure: cookieSecure(),
    path: "/",
    maxAge: 0,
  });

  return response;
}
