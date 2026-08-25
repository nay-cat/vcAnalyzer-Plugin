/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { settings } from "../settings";
import { AnalysisValue, analyzerLimiter } from "../utils";
import { analyzeUserWithCordCatReputation, describeCordCat } from "./CordCat";
import { analyzeUserWithDangercord, describeDangercord } from "./Dangercord";
import { ReputationSection } from "./ReputationModal";
import { analyzeUserWithUbfb, describeUbfb } from "./UBFB";
import { analyzeUserWithXnProtect, describeXnProtect } from "./XNProtect";

export interface UserReputationService {
    id: string;
    label: string;
    settingKey: string;
    run: (userId: string, userName: string, silent: boolean) => Promise<AnalysisValue | null>;
    describe: (userId: string, userName: string) => Promise<ReputationSection>;
}

/**
 * CONTRIBUTORS!!!
 * Community blacklists that answer "is this user reported?" for a Discord ID.
 * Adding a service here is enough for it to appear in the unified scan, in the
 * per-service menu and in settings, with no menu or call-site changes needed.
 */
export const USER_REPUTATION_SERVICES: UserReputationService[] = [
    {
        id: "cordcat",
        label: "CordCat",
        settingKey: "enableCordCat",
        run: analyzeUserWithCordCatReputation,
        describe: describeCordCat
    },
    {
        id: "dangercord",
        label: "Dangercord",
        settingKey: "enableDangercord",
        run: analyzeUserWithDangercord,
        describe: describeDangercord
    },
    {
        id: "ubfb",
        label: "UBFB",
        settingKey: "enableUbfb",
        run: analyzeUserWithUbfb,
        describe: describeUbfb
    },
    {
        id: "xnprotect",
        label: "XN Protect",
        settingKey: "enableXnProtect",
        run: analyzeUserWithXnProtect,
        describe: describeXnProtect
    }
];

export function getEnabledReputationServices(): UserReputationService[] {
    return USER_REPUTATION_SERVICES.filter(s => (settings.store as any)[s.settingKey]);
}

export function isUnifiedMode(): boolean {
    return settings.store.unifyUserReputationChecks;
}

/**
 * CONTRIBUTORS!!!
 * Runs every enabled service and merges their findings into a single result.
 * Services are independent, so one failing or being down never blocks the rest.
 */
export async function analyzeUserReputation(userId: string, userName: string, silent = false): Promise<AnalysisValue | null> {
    const services = getEnabledReputationServices();
    if (!services.length) return null;

    const results = await Promise.all(services.map(service =>
        analyzerLimiter.run(async () => {
            try {
                return await service.run(userId, userName, true);
            } catch {
                return null;
            }
        })
    ));

    const details: AnalysisValue["details"] = [];
    let failed = 0;

    for (let i = 0; i < results.length; i++) {
        const result = results[i];
        if (result) {
            details.push(...result.details);
        } else {
            failed++;
            details.push({
                message: `[${services[i].label}] Lookup failed or unavailable`,
                type: "error"
            });
        }
    }

    // nothing came back at all, so treat as a failed scan rather than a clean one
    if (failed === services.length) return null;

    return { details, timestamp: Date.now() };
}

export function streamUserReputation(
    userId: string,
    userName: string,
    onResult: (section: ReputationSection) => void
): { services: UserReputationService[]; done: Promise<void>; } {
    const services = getEnabledReputationServices();

    const done = Promise.all(services.map(service =>
        analyzerLimiter.run(async () => {
            try {
                onResult(await service.describe(userId, userName));
            } catch (e) {
                onResult({
                    service: service.label,
                    verdict: "error",
                    summary: "Lookup failed",
                    error: String(e)
                });
            }
        })
    )).then(() => undefined);

    return { services, done };
}
