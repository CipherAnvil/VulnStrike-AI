import type { Metadata } from "next";
import "./globals.css";
import { Sidebar, TopBar } from "@/components/Navigation";

export const metadata: Metadata = {
  title: "VulnStrike AI — Cybersecurity Assessment & Orchestration",
  description: "Authorized web security assessments, CVE intelligence, and evidence-backed attack-path reporting",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="bg-background text-zinc-100 flex min-h-screen">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <TopBar />
          <main className="flex-1 p-6 md:p-8 overflow-y-auto">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
