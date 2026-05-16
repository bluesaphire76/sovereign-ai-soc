import { NextResponse } from "next/server";

const COOKIE_NAME = "ai_soc_access_token";

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  const token = body?.token;

  if (!token || typeof token !== "string") {
    return NextResponse.json({ detail: "Missing token." }, { status: 400 });
  }

  const response = NextResponse.json({ status: "ok" });

  response.cookies.set({
    name: COOKIE_NAME,
    value: token,
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 8,
  });

  return response;
}
