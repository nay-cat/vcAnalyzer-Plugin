/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { openModal, Modal, React, Select, TextInput, useState, UserStore } from "@webpack/common";

import { reportUserToUbfb, UBFB_REASONS } from "../../analyzers/UBFB";

function UbfbReportModal({ modalProps, userId, userName, defaultProofs }: {
    modalProps: any;
    userId: string;
    userName: string;
    defaultProofs: string[];
}) {
    const [reason, setReason] = useState<string>(UBFB_REASONS[0]);
    const [proofs, setProofs] = useState(defaultProofs.join("\n"));
    const [submitting, setSubmitting] = useState(false);

    const proofList = proofs.split("\n").map(p => p.trim()).filter(Boolean);
    const canSubmit = proofList.length > 0 && !submitting;

    async function submit() {
        if (!canSubmit) return;
        setSubmitting(true);

        const self = UserStore.getCurrentUser();
        const ok = await reportUserToUbfb(
            userId,
            reason,
            proofList,
            self?.id ?? "0",
            self?.username ?? "unknown"
        );

        setSubmitting(false);
        if (ok) modalProps.onClose();
    }

    return (
        <Modal
            {...modalProps}
            size="sm"
            title="Report user to UBFB"
            actions={[
                { text: submitting ? "Submitting..." : "Submit report", variant: "dangerPrimary", onClick: submit, disabled: !canSubmit },
                { text: "Cancel", variant: "secondary", onClick: modalProps.onClose },
            ]}
        >
            <p style={{ marginBottom: "10px", fontSize: "13px" }}>
                Reporting <strong>{userName}</strong> ({userId})
            </p>

            <p style={{ marginBottom: "6px", color: "var(--text-muted)", fontSize: "12px" }}>Reason</p>
            <Select
                options={UBFB_REASONS.map(r => ({ label: r, value: r }))}
                placeholder="Select a reason"
                maxVisibleItems={6}
                closeOnSelect={true}
                select={(v: string) => setReason(v)}
                isSelected={(v: string) => v === reason}
                serialize={(v: string) => String(v)}
            />

            <p style={{ margin: "12px 0 6px", color: "var(--text-muted)", fontSize: "12px" }}>
                Proof URLs (required)
            </p>
            <TextInput
                placeholder="https://cdn.discordapp.com/attachments/.../proof.png"
                value={proofs}
                onChange={setProofs}
            />

            <div style={{ marginTop: "14px", padding: "10px", borderRadius: "4px", background: "var(--background-secondary-alt)" }}>
                <p style={{ margin: 0, fontSize: "12px", color: "var(--text-danger)" }}>
                    This submits a public accusation that cannot be withdrawn from here. Your Discord ID and username are attached to it, and the pending queue is readable by anyone. Only report with genuine evidence.
                </p>
            </div>
        </Modal>
    );
}

export function openUbfbReportModal(userId: string, userName: string, defaultProofs: string[] = []) {
    openModal(modalProps => (
        <UbfbReportModal
            modalProps={modalProps}
            userId={userId}
            userName={userName}
            defaultProofs={defaultProofs}
        />
    ));
}
