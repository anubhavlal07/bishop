"use client";

import type { VerdictLabel } from "@/lib/types";

export const VERDICT_COLOUR: Record<string, string> = {
  true_positive: "var(--color-tp)",
  false_positive: "var(--color-fp)",
  benign_true_positive: "var(--color-btp)",
  escalate: "var(--color-escalate)",
};

export const VERDICT_LABEL: Record<string, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  benign_true_positive: "Benign true positive",
  escalate: "Escalated to a human",
};

export function VerdictPill({
  label,
  confidence,
}: {
  label: VerdictLabel | string | null;
  confidence?: number | null;
}) {
  if (!label) return <span className="muted text-xs">no verdict yet</span>;
  const colour = VERDICT_COLOUR[label] ?? "var(--muted)";
  return (
    <span
      className="inline-flex items-center gap-2 rounded px-2 py-0.5 text-xs font-medium"
      style={{ color: colour, border: `1px solid ${colour}`, background: `${colour}14` }}
    >
      {VERDICT_LABEL[label] ?? label}
      {typeof confidence === "number" && (
        <span className="mono opacity-80">{confidence.toFixed(2)}</span>
      )}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: string }) {
  const colour =
    { critical: "#f2555a", high: "#ff8a4c", medium: "#e3b341", low: "#58a6ff" }[severity] ??
    "var(--muted)";
  return (
    <span
      title={severity}
      className="inline-block h-2 w-2 shrink-0 rounded-full"
      style={{ background: colour }}
    />
  );
}

export function Panel({
  title,
  subtitle,
  right,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || right) && (
        <header
          className="flex items-baseline gap-3 border-b px-4 py-2.5"
          style={{ borderColor: "var(--edge)" }}
        >
          {title && <h2 className="text-sm font-semibold">{title}</h2>}
          {subtitle && <span className="muted text-xs">{subtitle}</span>}
          <div className="ml-auto">{right}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

/** Shown instead of an empty state when the API is the problem. */
export function ApiDown({ message }: { message: string }) {
  return (
    <div
      className="panel p-6"
      style={{ borderColor: "var(--color-tp)", color: "var(--color-tp)" }}
    >
      <p className="font-medium">Bishop&apos;s API did not answer.</p>
      <p className="muted mt-2 text-xs">{message}</p>
      <p className="muted mt-3 text-xs">
        This is not an empty result — the console could not reach the backend, so it does not
        know what there is.
      </p>
    </div>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="muted py-6 text-center text-xs">{children}</p>;
}
