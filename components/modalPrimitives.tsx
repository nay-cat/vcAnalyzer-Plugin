/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Link } from "@components/Link";
import { React, useState } from "@webpack/common";

export const TEXT_NORMAL = "var(--text-normal, var(--header-primary, #dcddde))";
export const TEXT_MUTED = "var(--text-muted, var(--header-secondary, #b5bac1))";

/** Small coloured pill used for statuses and counters. */
export function Tag({ children, color }: { children: React.ReactNode; color: string; }) {
    return (
        <span style={{
            background: color,
            color: "#fff",
            borderRadius: 3,
            padding: "1px 6px",
            fontSize: 11,
            fontWeight: 700,
            textTransform: "uppercase" as const
        }}>
            {children}
        </span>
    );
}

export interface FieldProps {
    label: string;
    value: string;
    /** render the value as a clickable link */
    link?: boolean;
    /** width reserved for the label when laid out inline */
    labelWidth?: number;
}

/**
 * Label/value row. Long values stack under their label instead of being
 * squeezed into a narrow column beside it.
 */
export function Field({ label, value, link, labelWidth = 96 }: FieldProps) {
    const stacked = !link && value.length > 60;

    return (
        <div style={{
            display: "flex",
            flexDirection: stacked ? "column" : "row",
            gap: stacked ? 1 : 8,
            fontSize: 13,
            marginBottom: 4
        }}>
            <span style={{ color: TEXT_MUTED, minWidth: stacked ? undefined : labelWidth, flexShrink: 0 }}>{label}</span>
            {link
                ? <span style={{ minWidth: 0, overflowWrap: "anywhere" as const }}><Link href={value}>{value}</Link></span>
                : <span style={{ color: TEXT_NORMAL, overflowWrap: "anywhere" as const }}>{value}</span>}
        </div>
    );
}

/** Uppercase heading with a rule under it, used to open a group of fields. */
export function SectionTitle({ children, color = TEXT_MUTED }: { children: React.ReactNode; color?: string; }) {
    return (
        <div style={{
            fontSize: 11,
            fontWeight: 700,
            textTransform: "uppercase" as const,
            letterSpacing: "0.06em",
            color,
            borderBottom: "1px solid var(--background-modifier-accent)",
            paddingBottom: 3,
            marginBottom: 8,
            marginTop: 4
        }}>
            {children}
        </div>
    );
}

/**
 * Discord avatar for a user id, falling back to the default avatar derived
 * from the id when the user is not cached.
 */
export function discordAvatarUrl(userId: string, avatarHash?: string | null, size = 80): string {
    if (avatarHash) {
        const ext = avatarHash.startsWith("a_") ? "gif" : "png";
        return `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.${ext}?size=${size}`;
    }

    let index = 0;
    try {
        index = Number((BigInt(userId) >> 22n) % 6n);
    } catch {
        // not a snowflake, keep the first default avatar
    }
    return `https://cdn.discordapp.com/embed/avatars/${index}.png`;
}

/** Formats an ISO string or a unix timestamp (seconds or ms) for display. */
export function formatTimestamp(value?: string | number | null): string | null {
    if (value === undefined || value === null || value === "") return null;

    const numeric = typeof value === "string" ? Number(value) : value;
    const ms = Number.isFinite(numeric)
        ? (Math.abs(numeric as number) < 1e12 ? (numeric as number) * 1000 : numeric as number)
        : Date.parse(String(value));

    if (!Number.isFinite(ms)) return null;

    const date = new Date(ms as number);
    if (Number.isNaN(date.getTime())) return null;

    return date.toLocaleString();
}

const IMAGE_EXT = /\.(png|jpe?g|gif|webp|bmp|avif)(\?|#|$)/i;

/** True when a URL is worth rendering as an inline image preview. */
export function isImageUrl(url: string): boolean {
    return /^https?:\/\//i.test(url) && IMAGE_EXT.test(url);
}

/**
 * Inline proof image. Starts collapsed behind a click so opening a report does
 * not silently pull remote images, and hides itself if the URL fails to load.
 */
export function ProofImage({ url, revealed = false }: { url: string; revealed?: boolean; }) {
    const [shown, setShown] = useState(revealed);
    const [failed, setFailed] = useState(false);

    if (failed) {
        return (
            <div style={{ fontSize: 12, color: TEXT_MUTED, marginBottom: 6 }}>
                Preview unavailable, <Link href={url}>open in browser</Link>
            </div>
        );
    }

    if (!shown) {
        return (
            <div
                onClick={() => setShown(true)}
                style={{
                    fontSize: 12,
                    color: "var(--text-link)",
                    cursor: "pointer",
                    marginBottom: 6,
                    userSelect: "none" as const
                }}
            >
                Show proof image
            </div>
        );
    }

    return (
        <div style={{ marginBottom: 8 }}>
            <img
                src={url}
                alt="proof"
                onError={() => setFailed(true)}
                style={{
                    maxWidth: "100%",
                    maxHeight: 220,
                    borderRadius: 4,
                    border: "1px solid var(--background-modifier-accent)",
                    display: "block",
                    objectFit: "contain" as const
                }}
            />
            <Link href={url}>Open full size</Link>
        </div>
    );
}
