/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Modal, openModal, React, TextInput, useState } from "@webpack/common";

import { analyzeUserWithCordCat } from "../../analyzers/CordCat";

function FindUserByIdModal({ modalProps }: { modalProps: any; }) {
    const [userId, setUserId] = useState("");

    function submit() {
        const id = userId.trim();
        if (!id) return;
        modalProps.onClose();
        analyzeUserWithCordCat(id, id);
    }

    return (
        <Modal
            {...modalProps}
            size="sm"
            title="Find User by ID - CordCat"
            actions={[
                { text: "Look Up", variant: "primary", onClick: submit, disabled: !userId.trim() },
                { text: "Cancel", variant: "secondary", onClick: modalProps.onClose },
            ]}
        >
            <p style={{ marginBottom: "10px", color: "var(--text-warning)", fontSize: "12px" }}>
                Deprecated: Vencord ships a built-in plugin called ValidUser that resolves unknown users
                directly in chat. Enable that instead of using this lookup.
            </p>
            <p style={{ marginBottom: "10px", color: "var(--text-muted)", fontSize: "13px" }}>
                Enter a Discord User ID to query CordCat:
            </p>
            <TextInput
                autoFocus
                placeholder="447812212241989632"
                value={userId}
                onChange={setUserId}
                onKeyDown={(e: React.KeyboardEvent) => { if (e.key === "Enter") submit(); }}
            />
        </Modal>
    );
}

export function openFindUserByIdModal() {
    openModal(modalProps => <FindUserByIdModal modalProps={modalProps} />);
}
