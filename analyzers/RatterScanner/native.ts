/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { createHash } from "crypto";
import { IpcMainInvokeEvent } from "electron";

export interface RatterScannerResult {
    hash: string;
    safe: boolean;
    automated_safe: boolean;
    malicious: boolean;
    fileName?: string;
    githubInfo?: {
        name?: string;
        owner?: string;
        projectName?: string;
        repoUrl?: string;
        downloadUrl?: string;
    };
}

const MAX_FILE_SIZE = 100 * 1024 * 1024;

export async function queryRatterScanner(_: IpcMainInvokeEvent, fileUrl: string): Promise<{ result?: RatterScannerResult; hash?: string; error?: string; }> {
    try {
        const fileResponse = await fetch(fileUrl);
        if (!fileResponse.ok) return { error: `Failed to fetch file: HTTP ${fileResponse.status}` };

        const contentLength = Number(fileResponse.headers.get("content-length"));
        if (contentLength && contentLength > MAX_FILE_SIZE) {
            return { error: "File is too large to hash" };
        }

        const buffer = Buffer.from(await fileResponse.arrayBuffer());
        const sha256 = createHash("sha256").update(buffer).digest("hex");

        const res = await fetch(`https://api.ratterscanner.com/hash/${sha256}`, {
            headers: {
                "accept": "application/json",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
            }
        });

        let data: any;
        try {
            data = await res.json();
        } catch {
            return { hash: sha256, error: `Invalid response from Ratter Scanner (HTTP ${res.status})` };
        }

        if (data?.error) return { hash: sha256, error: String(data.error) };
        if (!res.ok) return { hash: sha256, error: `Ratter Scanner returned HTTP ${res.status}` };

        const result = data?.results?.find((r: RatterScannerResult) => r?.hash?.toLowerCase() === sha256) ?? data?.results?.[0];
        if (!result) return { hash: sha256, error: "Ratter Scanner returned no results" };

        return { result, hash: sha256 };
    } catch (e) {
        return { error: String(e) };
    }
}
