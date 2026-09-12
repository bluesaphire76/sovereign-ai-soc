"use client";

import { useLayoutEffect, useId, useRef, type MouseEvent, type ReactNode } from "react";
import { X } from "lucide-react";
import { cx } from "@/lib/semantic-styles";
import EnterpriseIconButton from "./EnterpriseIconButton";

type EnterpriseModalProps = {
  open: boolean;
  title: string;
  description?: string;
  children?: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  closeDisabled?: boolean;
  className?: string;
};

export default function EnterpriseModal({
  open,
  title,
  description,
  children,
  actions,
  onClose,
  closeDisabled = false,
  className,
}: EnterpriseModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useLayoutEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();

    // Close before removal so native dialog focus restoration also works on unmount.
    return () => {
      if (dialog.open) dialog.close();
    };
  }, [open]);

  function handleBackdropClick(event: MouseEvent<HTMLDialogElement>) {
    if (event.target === event.currentTarget && !closeDisabled) onClose();
  }

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      aria-busy={closeDisabled}
      onCancel={(event) => {
        event.preventDefault();
        if (!closeDisabled) onClose();
      }}
      onClick={handleBackdropClick}
      className={cx(
        "m-auto max-h-[calc(100dvh-2rem)] w-[min(32rem,calc(100vw-2rem))] overflow-y-auto rounded-sm border border-slate-700 bg-slate-900 p-0 text-slate-100 shadow-2xl backdrop:bg-slate-950/80",
        className
      )}
    >
      <div className="flex items-start justify-between gap-4 border-b border-slate-800 px-4 py-3">
        <div className="min-w-0">
          <h2 id={titleId} className="break-words text-sm font-semibold text-slate-100">
            {title}
          </h2>
          {description && (
            <p id={descriptionId} className="mt-1 text-xs leading-5 text-slate-500">
              {description}
            </p>
          )}
        </div>
        <EnterpriseIconButton
          icon={<X className="h-4 w-4" />}
          label="Close dialog"
          onClick={onClose}
          disabled={closeDisabled}
          tone="ghost"
          size="xs"
        />
      </div>
      {children && <div className="px-4 py-3 text-sm text-slate-300">{children}</div>}
      {actions && (
        <div className="flex flex-wrap justify-end gap-2 border-t border-slate-800 px-4 py-3">
          {actions}
        </div>
      )}
    </dialog>
  );
}
