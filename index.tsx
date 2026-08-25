/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import "./style/styles.css";

import { findGroupChildrenByChildId, NavContextMenuPatchCallback } from "@api/ContextMenu";
import definePlugin from "@utils/types";
import { Message } from "@vencord/discord-types";
import { Alerts, Menu, React } from "@webpack/common";

import { LinkIcon, OpenExternalIcon, SafetyIcon } from "@components/Icons";

import { AnalysisAccessory, handleAnalysis } from "./AnalysisAccesory";
import { getThreat } from "./threatStore";
import { analyzeUserWithCordCat } from "./analyzers/CordCat";
import { analyzeDiscordInvite, isDiscordInvite } from "./analyzers/DiscordInvite";
import { analyzeFileWithHybridAnalysis, analyzeUrlWithHybridAnalysis } from "./analyzers/HybridAnalysis";
import { analyzeWithCertPL } from "./analyzers/CertPL";
import { analyzeWithCrtSh } from "./analyzers/CrtSh";
import { analyzeWithFishFish } from "./analyzers/FishFish";
import { analyzeWithSucuri } from "./analyzers/Sucuri";
import { analyzeFileWithRatterScanner, isJarFile } from "./analyzers/RatterScanner";
import { analyzeUserReputation, getEnabledReputationServices, isUnifiedMode } from "./analyzers/userReputation";
import { analyzeUserReputationEntry } from "./analyzers/reputationEntry";
import { openFindUserByIdModal } from "./components/modals/FindUserByIdModal";
import { openUbfbReportModal } from "./components/modals/UbfbReportModal";
import { analyzeWithVirusTotal } from "./analyzers/VirusTotal";
import { analyzeWithWhereGoes } from "./analyzers/WhereGoes";
import { runModularScan } from "./analyzers/ModularScan";
import { autoAnalyzeMessage, extractUrlsFromMessage, manualAnalyzeUrls } from "./autoAnalyze";
import { settings } from "./settings";
import { getModulesSync } from "./modularScanStore";
import { initFilters, setCustomWhitelist, setCustomBlocklist } from "./urlFilter";
import { extractCdnFileUrls, truncateUrl } from "./utils";

async function genericAnalyze(messageId: string, url: string, analyzer: (url: string, silent: boolean) => Promise<any>, silent = false) {
    const result = await analyzer(url, silent);
    if (result) {
        handleAnalysis(messageId, result, url);
    }
}

async function genericAnalyzeFile(messageId: string, fileUrl: string, fileName: string, analyzer: (url: string, name: string, silent: boolean) => Promise<any>, silent = false) {
    const result = await analyzer(fileUrl, fileName, silent);
    if (result) {
        handleAnalysis(messageId, result, fileUrl);
    }
}

/** Builds the reputation menu entries one combined, or one per enabled service. */
function buildReputationMenuItems(messageId: string | undefined, userId: string, userName: string, prefix: string) {
    const services = getEnabledReputationServices();
    if (!services.length) return [];

    if (isUnifiedMode()) {
        return [(
            <Menu.MenuItem
                id={`${prefix}-reputation`}
                key="reputation"
                label="Scan user reputation"
                icon={SafetyIcon}
                action={() => analyzeUserReputationEntry(messageId, userId, userName, analyzeUserReputation, "User Reputation", true)}
            />
        )];
    }

    return services.map(service => (
        <Menu.MenuItem
            id={`${prefix}-reputation-${service.id}`}
            key={service.id}
            label={`Scan user with ${service.label}`}
            icon={SafetyIcon}
            action={() => analyzeUserReputationEntry(messageId, userId, userName, service.run, `${service.label} Analysis`, true, service)}
        />
    ));
}

function openExternal(url: string) {
    VencordNative.native.openExternal(url);
}

function extractUserIdFromContext(context: any): string | undefined {
    if (!context || typeof context !== "object") return undefined;

    const id = context.id ?? context.userId ?? context.targetUserId ?? context.user?.id;
    if (typeof id === "string" && /^\d{17,20}$/.test(id)) return id;
    if ((typeof id === "number" || typeof id === "bigint") && /^\d{17,20}$/.test(String(id))) return String(id);

    return undefined;
}

function getUserSearchLinks(userId: string) {
    const encodedId = encodeURIComponent(userId);
    return [
        { id: "top-gg", label: "top.gg", url: `https://top.gg/user/${encodedId}` },
        { id: "discordhub", label: "DiscordHub", url: `https://discordhub.com/profile/${encodedId}` },
        { id: "cordcat", label: "CordCat", url: `https://cord.cat/${encodedId}` }

    ];
}

function getServerSearchLinks(guildId: string) {
    const encodedId = encodeURIComponent(guildId);
    return [
        { id: "disboard", label: "Disboard", url: `https://disboard.org/es/server/${encodedId}` },
        { id: "discordservers", label: "DiscordServers", url: `https://discordservers.com/server/${encodedId}` },
        { id: "discordplace", label: "DiscordPlace", url: `https://discordplace.com/servers/${encodedId}` },
        { id: "discords", label: "Discords", url: `https://discords.com/servers/${encodedId}` }
    ];
}

const urlAnalyzers = [
    { id: "auto-url-checks", label: "Run all automatic checks", fn: null as null },
    { id: "wg", label: "Trace URL with WhereGoes", fn: analyzeWithWhereGoes },
    { id: "crtsh", label: "Check certificates (crt.sh)", fn: analyzeWithCrtSh },
    { id: "certpl", label: "Check blocklist (CERT.PL)", fn: analyzeWithCertPL },
    { id: "fishfish", label: "Check phishing (FishFish)", fn: analyzeWithFishFish },
    { id: "sucuri", label: "Check reputation (Sucuri)", fn: analyzeWithSucuri },
    { id: "ha-url", label: "Scan URL (Hybrid Analysis)", fn: analyzeUrlWithHybridAnalysis },
];

const fileAnalyzers = [
    { id: "vt", label: "Scan file with VirusTotal", fn: (msgId: string, url: string, _name: string) => genericAnalyze(msgId, url, (u, s) => analyzeWithVirusTotal(msgId, u, s)) },
    { id: "ha-file", label: "Scan file with Hybrid Analysis", fn: (msgId: string, url: string, name: string) => genericAnalyzeFile(msgId, url, name, analyzeFileWithHybridAnalysis) },
    { id: "ratterscanner", label: "Scan file with Ratter Scanner", fn: (msgId: string, url: string, name: string) => genericAnalyzeFile(msgId, url, name, analyzeFileWithRatterScanner), enabled: () => settings.store.autoScanFilesRatterScanner, accepts: isJarFile },
];

function getFileAnalyzers(fileNames: string[]) {
    return fileAnalyzers.filter(a =>
        (a.enabled?.() ?? true) && (!a.accepts || fileNames.some(a.accepts))
    );
}

const messageCtxPatch: NavContextMenuPatchCallback = (children, { message }: { message: Message; }) => {
    const hasAttachments = !!message.attachments?.length;
    const urls = extractUrlsFromMessage(message);
    const inviteUrls = urls.filter(isDiscordInvite);
    const normalUrls = urls.filter(u => !isDiscordInvite(u));
    const cdnFiles = extractCdnFileUrls(normalUrls);
    const hasUrls = normalUrls.length > 0;
    const hasCdnFiles = cdnFiles.length > 0;
    const hasInvites = inviteUrls.length > 0;

    const group = findGroupChildrenByChildId("copy-text", children)
        ?? findGroupChildrenByChildId("copy-link", children)
        ?? children;

    if (settings.store.enableCordCat) {
        const authorName = message.author.username || message.author.id;
        group.push(
            <Menu.MenuItem
                id="vc-analyze-author-cordcat"
                label="Scan author with CordCat"
                icon={SafetyIcon}
                action={() => analyzeUserWithCordCat(message.author.id, authorName)}
            />
        );
    }

    {
        const authorName = message.author.username || message.author.id;
        group.push(...buildReputationMenuItems(message.id, message.author.id, authorName, "vc-analyze-author"));

        if (settings.store.enableUbfb && settings.store.enableUbfbReporting) {
            const imageProofs = (message.attachments ?? [])
                .filter(a => a.content_type?.toLowerCase().startsWith("image/"))
                .map(a => a.url);

            group.push(
                <Menu.MenuItem
                    id="vc-analyze-author-ubfb-report"
                    label="Report author to UBFB..."
                    icon={SafetyIcon}
                    color="danger"
                    action={() => openUbfbReportModal(message.author.id, authorName, imageProofs)}
                />
            );
        }
    }

    if (settings.store.enableFindUserById) {
        group.push(
            <Menu.MenuItem
                id="vc-analyze-find-user-by-id"
                label="Find User by ID (deprecated)"
                icon={SafetyIcon}
                action={openFindUserByIdModal}
            />
        );
    }

    if (!hasAttachments && !hasUrls && !hasInvites && !hasCdnFiles) return;

    if (hasAttachments) {
        for (const analyzer of getFileAnalyzers(message.attachments.map(a => a.filename))) {
            const attachments = analyzer.accepts
                ? message.attachments.filter(a => analyzer.accepts!(a.filename))
                : message.attachments;

            if (attachments.length === 1) {
                group.push(
                    <Menu.MenuItem
                        id={`vc-analyze-${analyzer.id}`}
                        label={analyzer.label}
                        icon={SafetyIcon}
                        action={() => analyzer.fn(message.id, attachments[0].url, attachments[0].filename)}
                    />
                );
            } else {
                group.push(
                    <Menu.MenuItem
                        id={`vc-analyze-${analyzer.id}`}
                        label={analyzer.label}
                        icon={SafetyIcon}
                    >
                        {attachments.map((attachment, i) => (
                            <Menu.MenuItem
                                id={`vc-analyze-${analyzer.id}-${i}`}
                                key={attachment.id}
                                label={attachment.filename}
                                action={() => analyzer.fn(message.id, attachment.url, attachment.filename)}
                            />
                        ))}
                    </Menu.MenuItem>
                );
            }
        }
    }

    if (hasCdnFiles) {
        for (const analyzer of getFileAnalyzers(cdnFiles.map(f => f.fileName))) {
            const files = analyzer.accepts
                ? cdnFiles.filter(f => analyzer.accepts!(f.fileName))
                : cdnFiles;

            if (files.length === 1) {
                group.push(
                    <Menu.MenuItem
                        id={`vc-analyze-cdn-${analyzer.id}`}
                        label={`${analyzer.label} (${files[0].fileName})`}
                        icon={SafetyIcon}
                        action={() => analyzer.fn(message.id, files[0].url, files[0].fileName)}
                    />
                );
            } else {
                group.push(
                    <Menu.MenuItem
                        id={`vc-analyze-cdn-${analyzer.id}`}
                        label={analyzer.label}
                        icon={SafetyIcon}
                    >
                        {files.map((file, i) => (
                            <Menu.MenuItem
                                id={`vc-analyze-cdn-${analyzer.id}-${i}`}
                                key={file.url}
                                label={file.fileName}
                                action={() => analyzer.fn(message.id, file.url, file.fileName)}
                            />
                        ))}
                    </Menu.MenuItem>
                );
            }
        }
    }

    if (hasUrls) {
        const primaryUrl = normalUrls[0];
        group.push(
            <Menu.MenuItem
                id="vc-analyze-url-group"
                label="Analyze URL"
                icon={LinkIcon}
            >
                {urlAnalyzers.map(analyzer => {
                    let action: (url: string) => void;
                    if (analyzer.fn) {
                        action = (url: string) => genericAnalyze(message.id, url, analyzer.fn!);
                    } else {
                        action = (url: string) => manualAnalyzeUrls(message, [url]);
                    }

                    return (
                        <Menu.MenuItem
                            id={`vc-analyze-${analyzer.id}`}
                            key={analyzer.id}
                            label={analyzer.label}
                            action={() => action(primaryUrl)}
                        >
                            {normalUrls.length > 1 && normalUrls.map((url, i) => (
                                <Menu.MenuItem
                                    id={`vc-analyze-${analyzer.id}-${i}`}
                                    key={url}
                                    label={truncateUrl(url)}
                                    action={() => action(url)}
                                />
                            ))}
                        </Menu.MenuItem>
                    );
                })}
            </Menu.MenuItem>
        );
    }

    if (hasInvites) {
        const analyzeInvite = async (url: string) => {
            const result = await analyzeDiscordInvite(url);
            if (result) handleAnalysis(message.id, result);
        };

        if (inviteUrls.length === 1) {
            group.push(
                <Menu.MenuItem
                    id="vc-analyze-invite"
                    label="Analyze Discord invite"
                    icon={OpenExternalIcon}
                    action={() => analyzeInvite(inviteUrls[0])}
                />
            );
        } else {
            group.push(
                <Menu.MenuItem
                    id="vc-analyze-invite"
                    label="Analyze Discord invite"
                    icon={OpenExternalIcon}
                >
                    {inviteUrls.map((url, i) => (
                        <Menu.MenuItem
                            id={`vc-analyze-invite-${i}`}
                            key={url}
                            label={truncateUrl(url)}
                            action={() => analyzeInvite(url)}
                        />
                    ))}
                </Menu.MenuItem>
            );
        }
    }

    const modularModules = getModulesSync();
    if (modularModules.length > 0) {
        const analyzeModular = async (module: any, fileUrl: string, fileName: string) => {
            const result = await runModularScan(module, fileUrl, fileName);
            if (result) handleAnalysis(message.id, result, fileUrl);
        };

        group.push(
            <Menu.MenuItem
                id="vc-analyze-modular-group"
                label="Modular Scan"
                icon={SafetyIcon}
            >
                {modularModules.map(module => {
                    const isUrlMatch = module.type === "url" && hasUrls;
                    const isFileMatch = module.type === "file" && hasAttachments;

                    if (!isUrlMatch && !isFileMatch) return null;

                    return (
                        <Menu.MenuItem
                            id={`vc-analyze-modular-${module.id}`}
                            key={module.id}
                            label={module.name}
                            action={() => {
                                if (isUrlMatch) {
                                    analyzeModular(module, urls[0], "");
                                } else {
                                    analyzeModular(module, message.attachments[0].url, message.attachments[0].filename);
                                }
                            }}
                        >
                            {isUrlMatch && urls.length > 1 && urls.map((url, i) => (
                                <Menu.MenuItem
                                    id={`vc-analyze-modular-${module.id}-${i}`}
                                    key={url}
                                    label={truncateUrl(url)}
                                    action={() => analyzeModular(module, url, "")}
                                />
                            ))}
                            {isFileMatch && message.attachments.length > 1 && message.attachments.map((attachment, i) => (
                                <Menu.MenuItem
                                    id={`vc-analyze-modular-${module.id}-${i}`}
                                    key={attachment.id}
                                    label={attachment.filename}
                                    action={() => analyzeModular(module, attachment.url, attachment.filename)}
                                />
                            ))}
                        </Menu.MenuItem>
                    );
                })}
            </Menu.MenuItem>
        );
    }
};

const userContextPatch: NavContextMenuPatchCallback = (children, { user, id }: { user?: any; id?: string; }) => {
    const userId: string | undefined = user?.id ?? id;
    if (!user && !userId) return;

    if (user && settings.store.enableOsintSearchShortcuts) {
        const links = getUserSearchLinks(user.id);
        children.push(
            <Menu.MenuItem
                id="vc-analyze-search-user"
                label="Search User"
                icon={OpenExternalIcon}
            >
                {links.map(link => (
                    <Menu.MenuItem
                        id={`vc-analyze-search-user-${link.id}`}
                        key={link.id}
                        label={link.label}
                        action={() => openExternal(link.url)}
                    />
                ))}
            </Menu.MenuItem>
        );
    }

    if (settings.store.enableCordCat && userId) {
        const username = user?.username || userId;
        children.push(
            <Menu.MenuItem
                id="vc-analyze-user-cordcat"
                label="Analyze User with CordCat"
                icon={SafetyIcon}
                action={() => analyzeUserWithCordCat(userId, username)}
            />
        );
    }

    if (userId) {
        const username = user?.username || userId;
        children.push(...buildReputationMenuItems(undefined, userId, username, "vc-analyze-user"));

        if (settings.store.enableUbfb && settings.store.enableUbfbReporting) {
            children.push(
                <Menu.MenuItem
                    id="vc-analyze-user-ubfb-report"
                    label="Report User to UBFB..."
                    icon={SafetyIcon}
                    color="danger"
                    action={() => openUbfbReportModal(userId, username)}
                />
            );
        }
    }
};

const devContextPatch: NavContextMenuPatchCallback = (children, context: any) => {
    const userId = extractUserIdFromContext(context);

    if (settings.store.enableCordCat) {
        if (userId) {
            children.push(
                <Menu.MenuItem
                    id="vc-analyze-dev-context-cordcat"
                    label="Analyze User with CordCat"
                    icon={SafetyIcon}
                    action={() => analyzeUserWithCordCat(userId, userId)}
                />
            );
        } else {
            children.push(
                <Menu.MenuItem
                    id="vc-analyze-dev-context-cordcat"
                    label="Find User by ID (deprecated)"
                    icon={SafetyIcon}
                    action={openFindUserByIdModal}
                />
            );
        }
    }

    // an unknown user still has a usable ID, so the reputation lookups apply
    if (userId) {
        children.push(...buildReputationMenuItems(undefined, userId, userId, "vc-analyze-dev-context"));

        if (settings.store.enableUbfb && settings.store.enableUbfbReporting) {
            children.push(
                <Menu.MenuItem
                    id="vc-analyze-dev-context-ubfb-report"
                    label="Report User to UBFB..."
                    icon={SafetyIcon}
                    color="danger"
                    action={() => openUbfbReportModal(userId, userId)}
                />
            );
        }
    }
};

const guildContextPatch: NavContextMenuPatchCallback = (children, { guild }: { guild: { id: string; }; }) => {
    if (!guild || !settings.store.enableOsintSearchShortcuts) return;

    const group = findGroupChildrenByChildId("privacy", children) ?? children;
    const links = getServerSearchLinks(guild.id);
    group.push(
        <Menu.MenuItem
            id="vc-analyze-search-server"
            label="Search Server"
            icon={OpenExternalIcon}
        >
            {links.map(link => (
                <Menu.MenuItem
                    id={`vc-analyze-search-server-${link.id}`}
                    key={link.id}
                    label={link.label}
                    action={() => openExternal(link.url)}
                />
            ))}
        </Menu.MenuItem>
    );
};

export default definePlugin({
    name: "vAnalyzer",
    description: "Analyze message attachments, trace URLs, check certificates, avoid scams and more.",
    authors: [{ name: "nay-cat", id: 1159977353661919363n }],
    settings,

    async start() {
        await initFilters();

        const wl = settings.store.customWhitelist;
        if (wl) setCustomWhitelist(wl.split(",").map(s => s.trim()).filter(Boolean));

        const bl = settings.store.customBlocklist;
        if (bl) setCustomBlocklist(bl.split(",").map(s => s.trim()).filter(Boolean));
    },

    handleLinkClick(data: { href: string; }) {
        if (!data?.href || !settings.store.warnOnLinkClick) return false;

        const threat = getThreat(data.href);
        if (!threat) return false;

        return new Promise<boolean>(resolve => {
            let resolved = false;
            const done = (block: boolean) => {
                if (resolved) return;
                resolved = true;
                resolve(block);
            };

            let title: string;
            let confirmColor: string;
            if (threat.level === "malicious") {
                title = "Malicious Link Detected";
                confirmColor = "var(--button-danger-background)";
            } else {
                title = "Suspicious Link Detected";
                confirmColor = "var(--button-outline-danger-text)";
            }

            Alerts.show({
                title,
                body: (
                    <div>
                        <p style={{ marginBottom: "8px" }}>
                            This link has been flagged as <strong>{threat.level}</strong> by vAnalyzer:
                        </p>
                        <div style={{ padding: "8px", background: "var(--background-secondary)", borderRadius: "4px", marginBottom: "8px" }}>
                            <code>{data.href}</code>
                        </div>
                        <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                            {threat.reasons.map((r, i) => (
                                <div key={i}>• {r}</div>
                            ))}
                        </div>
                    </div>
                ),
                confirmText: "Open Anyway",
                cancelText: "Cancel",
                confirmColor,
                onConfirm: () => done(false),
                onCancel: () => done(true),
                onCloseCallback: () => done(true)
            });
        });
    },

    handleFileDownload(url: string) {
        if (!url || !settings.store.warnOnFileDownload) return false;

        const threat = getThreat(url);
        if (!threat) return false;

        return true;
    },

    flux: {
        MESSAGE_CREATE({ message, optimistic }: { message: Message; optimistic: boolean; }) {
            if (optimistic) return;
            autoAnalyzeMessage(message);
        }
    },

    contextMenus: {
        "message": messageCtxPatch,
        "user-context": userContextPatch,
        "user-profile-actions": userContextPatch,
        "user-profile-overflow-menu": userContextPatch,
        "unknown-user-context": devContextPatch,
        "dev-context": devContextPatch,
        "guild-context": guildContextPatch,
        "guild-header-popout": guildContextPatch
    },

    renderMessageAccessory: props => {
        autoAnalyzeMessage(props.message);
        return <AnalysisAccessory message={props.message} />;
    },
});
