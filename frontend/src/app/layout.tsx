import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Sovereign AI SOC",
  description: "Local-first AI-assisted SOC platform",
};

const demoMode = process.env.NEXT_PUBLIC_AI_SOC_DEMO_MODE === "true";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        {demoMode ? (
          <div className="border-b border-amber-500/60 bg-amber-950 px-3 py-1 text-center text-[11px] font-semibold tracking-[0.16em] text-amber-200">
            DEMO MODE — SYNTHETIC DATA
          </div>
        ) : null}
        {children}
      </body>
    </html>
  );
}
