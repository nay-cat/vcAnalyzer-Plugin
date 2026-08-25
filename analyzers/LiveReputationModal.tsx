/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { React, useState } from "@webpack/common";

import { openPluginModal } from "../components/modals/openPluginModal";
import { ReputationModal, ReputationSection } from "./ReputationModal";

/**
 * Renders the modal immediately and fills each service in as it answers, so a
 * slow or unreachable service never holds up the ones that already replied.
 */
function LiveReputationModal({ userName, userId, services, subscribe }: {
    userName: string;
    userId: string;
    services: string[];
    subscribe: (onResult: (section: ReputationSection) => void) => Promise<void>;
}) {
    const [sections, setSections] = useState<ReputationSection[]>([]);

    React.useEffect(() => {
        let active = true;

        subscribe(section => {
            if (active) setSections(prev => [...prev, section]);
        });

        return () => { active = false; };
    }, []);

    const answered = new Set(sections.map(s => s.service));
    const pending = services.filter(label => !answered.has(label));

    return (
        <ReputationModal
            userName={userName}
            userId={userId}
            sections={sections}
            pending={pending}
        />
    );
}

export function openReputationModal(
    userName: string,
    userId: string,
    title: string,
    services: string[],
    subscribe: (onResult: (section: ReputationSection) => void) => Promise<void>
) {
    openPluginModal(
        () => (
            <LiveReputationModal
                userName={userName}
                userId={userId}
                services={services}
                subscribe={subscribe}
            />
        ),
        { title }
    );
}
