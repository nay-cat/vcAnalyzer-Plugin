/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { handleAnalysis } from "../AnalysisAccesory";
import { openReputationModal } from "./LiveReputationModal";
import { getEnabledReputationServices, streamUserReputation, type UserReputationService } from "./userReputation";

/**
 * From a message the result is merged into the inline accessory; from a profile
 * there is no message to attach to, so the structured modal is shown instead.
 */
export async function analyzeUserReputationEntry(
    messageId: string | undefined,
    userId: string,
    userName: string,
    run: (userId: string, userName: string, silent: boolean) => Promise<any>,
    title: string,
    stream?: boolean,
    only?: UserReputationService
) {
    if (!messageId && stream) {
        // a single-service entry must only query that one service
        if (only) {
            openReputationModal(userName, userId, title, [only.label], async onResult => {
                try {
                    onResult(await only.describe(userId, userName));
                } catch (e) {
                    onResult({ service: only.label, verdict: "error", summary: "Lookup failed", error: String(e) });
                }
            });
            return;
        }

        const services = getEnabledReputationServices();
        if (!services.length) return;

        openReputationModal(
            userName,
            userId,
            title,
            services.map(s => s.label),
            onResult => streamUserReputation(userId, userName, onResult).done
        );
        return;
    }

    const result = await run(userId, userName, false);
    if (!result) return;

    if (messageId) {
        handleAnalysis(messageId, result);
    }
}
