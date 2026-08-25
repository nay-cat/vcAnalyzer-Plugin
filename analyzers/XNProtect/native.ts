/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { IpcMainInvokeEvent } from "electron";

const BASE_URL = "https://apis.ebixcloud.com/apis/xnprotect";

export interface XnProtectBan {
    banglobal: boolean;
    reason?: string;
    proof?: string;
    dates?: {
        since?: string | number;
        expires?: string | number;
    };
}

export async function queryXnProtect(_: IpcMainInvokeEvent, userId: string): Promise<{ ban?: XnProtectBan; error?: string; }> {
    if (!/^\d{17,20}$/.test(userId)) return { error: "Invalid Discord user ID" };

    try {
        const res = await fetch(`${BASE_URL}/banglobal?id=${encodeURIComponent(userId)}`, {
            headers: {
                "accept": "application/json",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
            }
        });

        if (res.status === 429) return { error: "Rate limited by XN Protect, try again shortly" };

        let data: any;
        try {
            data = await res.json();
        } catch {
            return { error: `Invalid response from XN Protect (HTTP ${res.status})` };
        }

        if (data?.success === false || !res.ok) {
            const msg = Array.isArray(data?.errors)
                ? data.errors.map((e: any) => e?.message).filter(Boolean).join("; ")
                : null;
            return { error: msg || `XN Protect returned HTTP ${res.status}` };
        }

        const response = data?.response;
        if (!response || typeof response.banglobal !== "boolean") {
            return { error: "Unexpected response shape from XN Protect" };
        }

        return { ban: response };
    } catch (e) {
        return { error: String(e) };
    }
}
