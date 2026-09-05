import type { Metadata } from "next";

import "./globals.css";
import { ModelGate } from "@/components/ModelGate";
import { Nav } from "@/components/Nav";

export const metadata: Metadata = {
  title: "Bishop",
  description:
    "An autonomous SOC analyst. Investigates and proposes; never contains alone.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <Nav />
        <ModelGate />
        <main className="mx-auto max-w-[1600px] px-6 py-6">{children}</main>
      </body>
    </html>
  );
}
