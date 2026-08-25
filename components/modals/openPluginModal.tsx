/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { ModalAction, ModalSize } from "@vencord/discord-types";
import { Modal, openModal, React } from "@webpack/common";

export interface PluginModalOptions {
    title: string;
    size?: ModalSize;
    actions?: (onClose: () => void) => ModalAction[];
    dismissText?: string;
}

export function openPluginModal(
    render: (modalProps: any) => React.ReactNode,
    { title, size = "sm", actions, dismissText = "Close" }: PluginModalOptions
) {
    openModal(modalProps => (
        <Modal
            {...modalProps}
            size={size}
            title={title}
            actions={[
                ...(actions?.(modalProps.onClose) ?? []),
                { text: dismissText, variant: "secondary", onClick: modalProps.onClose }
            ]}
        >
            {render(modalProps)}
        </Modal>
    ));
}
