"use client";

import { useCallback, useEffect, useState } from "react";

import { ProviderSetup } from "@/components/ProviderSetup";
import { hasChosen, loadCredentials } from "@/lib/credentials";

export function ModelGate() {
  const [open, setOpen] = useState(false);
  const [firstRun, setFirstRun] = useState(false);

  useEffect(() => {
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
