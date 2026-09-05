"use client";

/**
 * Opens the setup dialog on a first visit, and gives the nav a way to reopen it.
 *
 * The dialog is *not* dismissable on a first visit and is dismissable
 * afterwards. That is the one bit of friction worth having: choosing the
 * deterministic model is a legitimate answer, but it should be a choice
 * somebody made rather than a default they never saw. "Deterministic" is
 * offered as the first-class option in the dialog precisely so declining to
 * paste a key is a one-click path, not a dead end.
 */

import { useCallback, useEffect, useState } from "react";

import { ProviderSetup } from "@/components/ProviderSetup";
import { hasChosen, loadCredentials } from "@/lib/credentials";

export function ModelGate() {
  const [open, setOpen] = useState(false);
  const [firstRun, setFirstRun] = useState(false);

  useEffect(() => {
    // Read after mount, never during render: `localStorage` does not exist on
    // the server, and touching it during render breaks hydration.
    if (!hasChosen()) {
      setFirstRun(true);
      setOpen(true);
    }
    const reopen = () => setOpen(true);
    window.addEventListener("bishop:open-model-setup", reopen);
    return () => window.removeEventListener("bishop:open-model-setup", reopen);
  }, []);

  const close = useCallback(() => {
    setOpen(false);
    setFirstRun(false);
    // Something may have changed; let the nav badge re-read.
    window.dispatchEvent(new Event("bishop:credentials"));
  }, []);

  return (
    <ProviderSetup
      open={open}
      onClose={close}
      dismissable={!firstRun || Boolean(loadCredentials())}
    />
  );
}
