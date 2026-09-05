"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { Health } from "@/lib/types";

const LINKS = [
  { href: "/", label: "Alerts" },
  { href: "/triage", label: "Triage yours" },
  { href: "/coverage", label: "Coverage" },
  { href: "/detectors", label: "Detectors" },
  { href: "/scorecard", label: "Scorecard" },
];

export function Nav() {
  const pathname = usePathname();
  const [health, setHealth] = useState<Health | null>(null);
  const [down, setDown] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      try {
        const result = await api.health();
        if (!cancelled) {
          setHealth(result);
          setDown(false);
        }
      } catch {
        if (!cancelled) setDown(true);
      }
    };
    void check();
    const timer = setInterval(check, 15_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <header className="border-b" style={{ borderColor: "var(--edge)" }}>
      <div className="mx-auto flex max-w-[1600px] items-center gap-6 px-6 py-3">
        <Link href="/" className="flex items-baseline gap-2">
          <span className="text-lg font-semibold tracking-tight">Bishop</span>
          <span className="muted hidden text-xs sm:inline">
            investigates and proposes; never contains alone
          </span>
        </Link>

        <nav className="flex gap-1">
          {LINKS.map((link) => {
            const active = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className="rounded px-3 py-1 text-sm"
                style={{
                  background: active ? "var(--edge)" : "transparent",
                  color: active ? "var(--text)" : "var(--muted)",
                }}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto text-xs">
          {down ? (
            <span style={{ color: "var(--color-tp)" }}>
              API unreachable — start it with <code>just api</code>
            </span>
          ) : health ? (
            <span className="muted">
              {health.offline ? "offline · mock model" : `live · ${health.model}`} · v
              {health.version}
            </span>
          ) : (
            <span className="muted">checking…</span>
          )}
        </div>
      </div>
    </header>
  );
}
