import { NextResponse } from "next/server";

const COOKIE_NAME = "ai_soc_access_token";

export async function POST() {
  const response = NextResponse.json({ status: "logged_out" });

  response.cookies.set({
    name: COOKIE_NAME,
    value: "",
    httpOnly: false,
    sameSite: "lax",
    secure: false,
    path: "/",
    maxAge: 0,
  });

  return response;
}
