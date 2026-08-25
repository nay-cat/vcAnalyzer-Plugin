/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { React, UserStore } from "@webpack/common";

import { discordAvatarUrl, Field, type FieldProps, isImageUrl, ProofImage, Tag, TEXT_MUTED, TEXT_NORMAL } from "../components/modalPrimitives";

const VERDICT_COLORS = {
    malicious: "var(--status-danger, #f23f43)",
    suspicious: "var(--text-warning, #f0b232)",
    safe: "var(--status-positive, #23a55a)",
    neutral: TEXT_MUTED,
    error: TEXT_MUTED
} as const;

const VERDICT_TAGS: Record<ReputationVerdict, string> = {
    malicious: "Listed",
    suspicious: "Flagged",
    safe: "Clean",
    neutral: "Unknown",
    error: "Failed"
};

export type ReputationVerdict = keyof typeof VERDICT_COLORS;

export type ReputationField = FieldProps;

export interface ReputationSection {
    service: string;
    verdict: ReputationVerdict;
    summary: string;
    fields?: ReputationField[];
    error?: string;
}

function SectionCard({ section }: { section: ReputationSection; }) {
    const color = VERDICT_COLORS[section.verdict];

    return (
        <div style={{
            background: "var(--background-secondary)",
            borderRadius: 4,
            borderLeft: `3px solid ${color}`,
            padding: "10px 12px",
            marginBottom: 10
        }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span style={{
                    fontSize: 12,
                    fontWeight: 700,
                    textTransform: "uppercase" as const,
                    letterSpacing: "0.04em",
                    color: TEXT_NORMAL
                }}>
                    {section.service}
                </span>
                <Tag color={color}>{VERDICT_TAGS[section.verdict]}</Tag>
            </div>

            <div style={{ color, fontSize: 13, fontWeight: 500, marginBottom: section.fields?.length || section.error ? 8 : 0 }}>
                {section.summary}
            </div>

            {section.error
                ? <div style={{ color: TEXT_MUTED, fontSize: 12 }}>{section.error}</div>
                : section.fields?.map(field => (
                    field.link && isImageUrl(field.value)
                        ? <ProofImage key={field.label + field.value} url={field.value} />
                        : <Field key={field.label + field.value} {...field} />
                ))}
        </div>
    );
}

/** service is still being queried. */
function PendingCard({ service }: { service: string; }) {
    return (
        <div style={{
            background: "var(--background-secondary)",
            borderRadius: 4,
            borderLeft: `3px solid ${TEXT_MUTED}`,
            padding: "10px 12px",
            marginBottom: 10,
            opacity: 0.65
        }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{
                    fontSize: 12,
                    fontWeight: 700,
                    textTransform: "uppercase" as const,
                    letterSpacing: "0.04em",
                    color: TEXT_NORMAL
                }}>
                    {service}
                </span>
                <span style={{ fontSize: 12, color: TEXT_MUTED }}>Checking...</span>
            </div>
        </div>
    );
}

export function ReputationModal({ userName, userId, sections, pending = [] }: {
    userName: string;
    userId: string;
    sections: ReputationSection[];
    /** service labels still being queried */
    pending?: string[];
}) {
    const user: any = UserStore.getUser(userId);
    const displayName = user?.globalName || user?.username || userName;
    const handle = user?.username && user.username !== displayName ? `@${user.username}` : null;

    const listed = sections.filter(s => s.verdict === "malicious" || s.verdict === "suspicious").length;
    const failed = sections.filter(s => s.verdict === "error").length;
    const checked = sections.length - failed;

    let overallColor: string;
    let overallLabel: string;
    if (listed > 0) {
        overallColor = VERDICT_COLORS.malicious;
        overallLabel = `Listed on ${listed} of ${checked}`;
    } else if (pending.length > 0) {
        overallColor = VERDICT_COLORS.neutral;
        overallLabel = `Checking ${pending.length} more`;
    } else if (checked === 0) {
        overallColor = VERDICT_COLORS.neutral;
        overallLabel = "No results";
    } else {
        overallColor = VERDICT_COLORS.safe;
        overallLabel = `Clean on ${checked}`;
    }

    return (
        <div style={{ padding: "4px 2px", color: TEXT_NORMAL }}>
            <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
                <img
                    src={discordAvatarUrl(userId, user?.avatar)}
                    alt=""
                    style={{ width: 48, height: 48, borderRadius: "50%", border: "3px solid var(--background-tertiary)", flexShrink: 0 }}
                />
                <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 800, fontSize: 16, color: "var(--white-500, #fff)" }}>{displayName}</div>
                    {handle && <div style={{ color: TEXT_MUTED, fontSize: 13 }}>{handle}</div>}
                    <div style={{ color: TEXT_MUTED, fontSize: 11, fontFamily: "var(--font-code)" }}>{userId}</div>
                </div>
            </div>

            <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginBottom: 14 }}>
                <Tag color={overallColor}>{overallLabel}</Tag>
                {failed > 0 && <Tag color={VERDICT_COLORS.neutral}>{failed} unavailable</Tag>}
            </div>

            {sections.map(section => <SectionCard key={section.service} section={section} />)}
            {pending.map(service => <PendingCard key={service} service={service} />)}
        </div>
    );
}
