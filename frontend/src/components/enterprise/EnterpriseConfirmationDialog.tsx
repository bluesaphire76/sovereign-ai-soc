"use client";

import type { ReactNode } from "react";
import EnterpriseButton, { type EnterpriseButtonTone } from "./EnterpriseButton";
import EnterpriseModal from "./EnterpriseModal";

type EnterpriseConfirmationDialogProps = {
  open: boolean;
  title: string;
  description?: string;
  children?: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  confirmTone?: Extract<EnterpriseButtonTone, "danger" | "warning" | "primary">;
  busy?: boolean;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
};

export default function EnterpriseConfirmationDialog({
  open,
  title,
  description,
  children,
  confirmLabel,
  cancelLabel = "Cancel",
  confirmTone = "danger",
  busy = false,
  onConfirm,
  onCancel,
}: EnterpriseConfirmationDialogProps) {
  return (
    <EnterpriseModal
      open={open}
      title={title}
      description={description}
      onClose={onCancel}
      closeDisabled={busy}
      actions={
        <>
          <EnterpriseButton onClick={onCancel} disabled={busy} tone="secondary" autoFocus>
            {cancelLabel}
          </EnterpriseButton>
          <EnterpriseButton onClick={onConfirm} disabled={busy} tone={confirmTone}>
            {busy ? "Working..." : confirmLabel}
          </EnterpriseButton>
        </>
      }
    >
      {children}
    </EnterpriseModal>
  );
}
