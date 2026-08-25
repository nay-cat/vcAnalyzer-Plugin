/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { IpcMainInvokeEvent } from "electron";

import { UBFB_REASONS } from "./reasons";

const BASE_URL = "https://ubfb-api.theindiebrand.es";

export interface UbfbEntry {
    id: string;
    reason?: string;
    status?: string;
    punishmentDays?: number;
    authorId?: string;
    authorUsername?: string;
    intermediaryId?: string;
    intermediaryUsername?: string;
    proofs?: string[];
    createdAt?: string;
    updatedAt?: string;
}

export async function queryUbfb(_: IpcMainInvokeEvent, userId: string): Promise<{ blacklisted?: boolean; entry?: UbfbEntry; error?: string; }> {
    if (!/^\d{17,20}$/.test(userId)) {
        return { error: "Invalid Discord user ID" };
    }

    try {
        const res = await fetch(`${BASE_URL}/blacklist/${userId}`, {
            headers: {
                "accept": "application/json",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
            }
        });

        // 300/min per IP
        if (res.status === 429) return { error: "Rate limited by UBFB, try again in a minute" };

        let data: any;
        try {
            data = await res.json();
        } catch {
            return { error: `Invalid response from UBFB (HTTP ${res.status})` };
        }

        if (res.status === 404) return { blacklisted: false };

        if (!res.ok) return { error: data?.error ?? `UBFB returned HTTP ${res.status}` };

        return { blacklisted: !!data?.blacklisted, entry: data?.entry };
    } catch (e) {
        return { error: String(e) };
    }
}


export interface UbfbReportInput {
    userId: string;
    reason: string;
    authorId: string;
    authorUsername: string;
    proofs: string[];
}

export async function submitUbfbReport(_: IpcMainInvokeEvent, report: UbfbReportInput): Promise<{ ok?: boolean; error?: string; }> {
    if (!/^\d{17,20}$/.test(report.userId)) return { error: "Invalid Discord user ID" };
    if (!/^\d{17,20}$/.test(report.authorId)) return { error: "Could not resolve your Discord account" };
    if (!UBFB_REASONS.includes(report.reason as any)) return { error: "Invalid reason" };
    if (!Array.isArray(report.proofs) || report.proofs.length === 0) return { error: "At least one proof URL is required" };

    try {
        const res = await fetch(`${BASE_URL}/reports`, {
            method: "POST",
            headers: {
                "accept": "application/json",
                "content-type": "application/json"
            },
            body: JSON.stringify({
                userId: report.userId,
                reason: report.reason,
                authorId: report.authorId,
                authorUsername: `vAnalyzer (${report.authorUsername})`,
                intermediaryId: report.authorId,
                intermediaryUsername: `vAnalyzer (${report.authorUsername})`,
                proofs: report.proofs
            })
        });

        if (res.status === 429) return { error: "Rate limited by UBFB (20 reports/min), try again shortly" };

        let data: any;
        try {
            data = await res.json();
        } catch {
            return { error: `Invalid response from UBFB (HTTP ${res.status})` };
        }

        if (res.status === 409) return { error: "This user already has a pending report" };

        if (!res.ok) {
            if (data?.error) return { error: data.error };
            if (Array.isArray(data?.errors) && data.errors.length > 0) return { error: data.errors.join("; ") };
            return { error: `UBFB returned HTTP ${res.status}` };
        }

        return { ok: true };
    } catch (e) {
        return { error: String(e) };
    }
}
