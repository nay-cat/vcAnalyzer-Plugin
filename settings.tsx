/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { definePluginSettings } from "@api/Settings";
import { Link } from "@components/Link";
import { Paragraph } from "@components/Paragraph";
import { OptionType } from "@utils/types";
import { Alerts, React } from "@webpack/common";

import ModularScanSettings from "./components/ModularScanSettings";
import SeparatorSettings from "./components/SeparatorSettings";

function AboutVAnalyzer() {
    return (
        <Paragraph>
            vAnalyzer, developed by nay-cat: source code, issues and contributions: <Link href="https://github.com/nay-cat/vAnalyzer/">github.com/nay-cat/vAnalyzer</Link>
        </Paragraph>
    );
}

function CordCatRegisterLink() {
    return (
        <Paragraph>
            Get a free CordCat API key at <Link href="https://cord.cat/register">cord.cat/register</Link>
        </Paragraph>
    );
}

function ThirdPartyNotice() {
    return (
        <Paragraph
            size="xs"
            style={{ color: "var(--text-muted)", marginTop: "4px", lineHeight: "1.4" }}
        >
            Community-run scanners and analyzers, each focused on a specific field such as Minecraft
            files or Discord user reputation. Every check sends a request to their servers with what you
            look up (file hashes, Discord user IDs, anything you submit), with everything that involves:
            they may log those requests, rate-limit you or be down entirely.
        </Paragraph>
    );
}

function ThirdPartyLinks() {
    return (
        <Paragraph size="xs" style={{ color: "var(--text-muted)", marginTop: "4px" }}>
            Learn more: <Link href="https://cord.cat/">CordCat</Link>
            {" · "}
            <Link href="https://status.dangercord.com/">Dangercord</Link>
            {" · "}
            <Link href="https://discord.gg/wEDbPRHyeB">Ratter Scanner</Link>
            {" · "}
            <Link href="https://ubfb.theindiebrand.es">UBFB</Link>
            {" · "}
            <Link href="https://xnprotect.com/">XN Protect</Link>
        </Paragraph>
    );
}

type ThirdPartyKey = "autoScanFilesRatterScanner" | "enableCordCat" | "enableDangercord" | "enableUbfb" | "enableXnProtect";

// show once
function warnThirdParty(key: ThirdPartyKey, enabled: boolean) {
    if (!enabled || settings.store.thirdPartyNoticeAcknowledged) return;

    Alerts.show({
        title: "Community Scanner",
        body: "This is a community-run scanner focused on a specific field, not a general antivirus. Every check sends a request to their servers with what you look up (file hashes, Discord user IDs, anything you submit), with everything that involves: they may log those requests under their own privacy and retention rules, rate-limit you, or be unavailable at any time.",
        confirmText: "I understand",
        cancelText: "Cancel",
        onConfirm: () => { settings.store.thirdPartyNoticeAcknowledged = true; },
        onCancel: () => { settings.store[key] = false; }
    });
}

function warnAutoScan(key: "autoScanUrls" | "autoScanFiles", enabled: boolean) {
    if (!enabled) return;

    let body: string;
    if (key === "autoScanUrls") {
        body = "Enabling auto-scan will send URLs from messages to third-party services for analysis. This may cause rate limiting and exposes the URLs you receive to external APIs. Use with discretion.";
    } else {
        body = "Enabling auto-scan will upload file attachments from messages to VirusTotal for analysis. Files may contain private or sensitive content. Use with discretion.";
    }

    Alerts.show({
        title: "Auto-Scan Warning",
        body,
        confirmText: "I understand",
        cancelText: "Cancel",
        onCancel: () => { settings.store[key] = false; }
    });
}

function warnUbfbReporting(enabled: boolean) {
    if (!enabled) return;

    Alerts.show({
        title: "UBFB Reporting Warning",
        body: "Reports submitted to UBFB are public accusations against real people. Your Discord ID and username are attached, the pending queue is readable by anyone, and reports cannot be withdrawn from this plugin. Only report with genuine evidence.",
        confirmText: "I understand",
        cancelText: "Cancel",
        onCancel: () => { settings.store.enableUbfbReporting = false; }
    });
}

export const settings = definePluginSettings(
    {
        aboutHeader: {
            type: OptionType.COMPONENT,
            component: AboutVAnalyzer
        },
        apiHeader: {
            type: OptionType.COMPONENT,
            component: () => <SeparatorSettings label="Services & API Keys" />
        },
        virusTotalApiKey: {
            type: OptionType.STRING,
            description: "VirusTotal API Key",
            default: "",
            placeholder: "Enter your VirusTotal API key..."
        },
        dangecordApiKey: {
            type: OptionType.STRING,
            description: "DangeCord API Key",
            default: "",
            placeholder: "Enter your DangeCord API key..."
        },
        hybridAnalysisApiKey: {
            type: OptionType.STRING,
            description: "Hybrid Analysis API Key",
            default: "",
            placeholder: "Enter your Hybrid Analysis API key..."
        },
        cordCatApiKey: {
            type: OptionType.STRING,
            description: "CordCat API Key (required for \"Analyze User with CordCat\")",
            default: "",
            placeholder: "Enter your CordCat API key..."
        },
        cordCatRegisterLink: {
            type: OptionType.COMPONENT,
            component: CordCatRegisterLink
        },

        generalHeader: {
            type: OptionType.COMPONENT,
            component: () => <SeparatorSettings label="General Protection" />
        },
        warnOnLinkClick: {
            type: OptionType.BOOLEAN,
            description: "Show a warning when clicking a link flagged as malicious or suspicious",
            default: true
        },
        warnOnFileDownload: {
            type: OptionType.BOOLEAN,
            description: "Show a warning when downloading a file flagged as malicious or suspicious",
            default: true
        },
        analyzeBotsProfile: {
            type: OptionType.BOOLEAN,
            description: "Analyze Bots Profile automatically when a bot sends a message",
            default: false
        },
        enableOsintSearchShortcuts: {
            type: OptionType.BOOLEAN,
            description: "Show Search User / Search Server shortcuts in context menus",
            default: true
        },
        enableFindUserById: {
            type: OptionType.BOOLEAN,
            displayName: "Find User by ID (deprecated)",
            description: "Deprecated: use Vencord's built-in ValidUser plugin instead, which resolves unknown users directly in chat. Shows \"Find User by ID\" in message context menus",
            default: false
        },

        scopeHeader: {
            type: OptionType.COMPONENT,
            component: () => <SeparatorSettings label="Scan Scope & Direct Messages" />
        },
        skipFriends: {
            type: OptionType.BOOLEAN,
            description: "Skip auto-scan for messages from friends",
            default: true
        },
        autoScanInvitesDirectMessageOnly: {
            type: OptionType.BOOLEAN,
            description: "Only auto-analyze invites in Direct Messages",
            default: false,
            disabled: () => !settings.store.autoScanInvites
        },
        autoScanUrlsDirectMessageOnly: {
            type: OptionType.BOOLEAN,
            description: "Only auto-scan URLs in Direct Messages",
            default: false,
            disabled: () => !settings.store.autoScanUrls
        },
        autoScanFilesDirectMessageOnly: {
            type: OptionType.BOOLEAN,
            description: "Only auto-scan files in Direct Messages",
            default: false,
            disabled: () => !settings.store.autoScanFiles
        },
        messageAgeFilter: {
            type: OptionType.SLIDER,
            description: "Only analyze messages from the last X days (0 = disabled)",
            default: 3,
            markers: [0, 1, 3, 7, 14, 30],
            stickToMarkers: true
        },

        autoScanHeader: {
            type: OptionType.COMPONENT,
            component: () => <SeparatorSettings label="URL & Invite Analysis" />
        },
        autoScanInvites: {
            type: OptionType.BOOLEAN,
            description: "Automatically analyze Discord invites in messages",
            default: true
        },
        checkEmbeds: {
            type: OptionType.BOOLEAN,
            description: "Include URLs found in embeds during URL extraction",
            default: false
        },
        autoScanUrls: {
            type: OptionType.BOOLEAN,
            description: "Automatically scan URLs found in messages",
            default: false,
            onChange: (v: boolean) => warnAutoScan("autoScanUrls", v)
        },
        autoScanUrlsCertPL: {
            type: OptionType.BOOLEAN,
            description: "Check domains on the CERT.PL blocklist",
            default: true,
            disabled: () => !settings.store.autoScanUrls
        },
        autoScanUrlsFishFish: {
            type: OptionType.BOOLEAN,
            description: "Check domains against FishFish phishing database",
            default: true,
            disabled: () => !settings.store.autoScanUrls
        },
        autoScanUrlsWhereGoes: {
            type: OptionType.BOOLEAN,
            description: "Trace URL redirects with WhereGoes",
            default: true,
            disabled: () => !settings.store.autoScanUrls
        },
        autoScanUrlsSucuri: {
            type: OptionType.BOOLEAN,
            description: "Check site reputation with Sucuri",
            default: true,
            disabled: () => !settings.store.autoScanUrls
        },
        autoScanUrlsHybridAnalysis: {
            type: OptionType.BOOLEAN,
            description: "Scan URLs with Hybrid Analysis (requires API Key)",
            default: false,
            disabled: () => !settings.store.autoScanUrls
        },

        fileScanHeader: {
            type: OptionType.COMPONENT,
            component: () => <SeparatorSettings label="Automatic File Analysis" />
        },
        autoScanFiles: {
            type: OptionType.BOOLEAN,
            description: "Automatically scan file attachments in messages",
            default: false,
            onChange: (v: boolean) => warnAutoScan("autoScanFiles", v)
        },
        ignoreMediaFiles: {
            type: OptionType.BOOLEAN,
            description: "Ignore media files (images, GIFs, videos, audio) during automatic file scanning",
            default: true,
            disabled: () => !settings.store.autoScanFiles
        },
        autoScanFilesVirusTotal: {
            type: OptionType.BOOLEAN,
            description: "Scan files with VirusTotal (requires API Key)",
            default: true,
            disabled: () => !settings.store.autoScanFiles
        },
        virusTotalLookupBeforeUpload: {
            type: OptionType.BOOLEAN,
            description: "VirusTotal: look up hash first before uploading (no API key needed)",
            default: true,
            disabled: () => !settings.store.virusTotalApiKey?.trim().length
        },
        autoScanFilesHybridAnalysis: {
            type: OptionType.BOOLEAN,
            description: "Scan files with Hybrid Analysis (requires API Key)",
            default: true,
            disabled: () => !settings.store.autoScanFiles
        },

        thirdPartyHeader: {
            type: OptionType.COMPONENT,
            component: () => <SeparatorSettings label="Community Scanners & Analyzers" />
        },
        thirdPartyNotice: {
            type: OptionType.COMPONENT,
            component: ThirdPartyNotice
        },
        thirdPartyNoticeAcknowledged: {
            type: OptionType.BOOLEAN,
            description: "Internal: whether the third-party notice has been acknowledged",
            default: false,
            hidden: true
        },
        enableCordCat: {
            type: OptionType.BOOLEAN,
            displayName: "CordCat",
            description: "Check users for Discord sanctions, data breaches and risk scoring (requires API key)",
            default: true,
            onChange: (v: boolean) => warnThirdParty("enableCordCat", v)
        },
        enableDangercord: {
            type: OptionType.BOOLEAN,
            displayName: "Dangercord",
            description: "Check users against the Dangercord blacklist and report counts",
            default: false,
            onChange: (v: boolean) => warnThirdParty("enableDangercord", v)
        },
        autoScanFilesRatterScanner: {
            type: OptionType.BOOLEAN,
            displayName: "Ratter Scanner",
            description: "Look up .jar attachments in the Ratter Scanner database of known malicious and known safe Minecraft files",
            default: false,
            onChange: (v: boolean) => warnThirdParty("autoScanFilesRatterScanner", v)
        },
        enableUbfb: {
            type: OptionType.BOOLEAN,
            displayName: "UBFB",
            description: "Check users against a community-run shared blacklist of scam, raid and dox reports",
            default: false,
            onChange: (v: boolean) => warnThirdParty("enableUbfb", v)
        },
        enableUbfbReporting: {
            type: OptionType.BOOLEAN,
            displayName: "UBFB reporting",
            description: "Submit reports to UBFB from the context menu. Public, permanent and tied to your account",
            default: false,
            disabled: () => !settings.store.enableUbfb,
            onChange: (v: boolean) => warnUbfbReporting(v)
        },
        enableXnProtect: {
            type: OptionType.BOOLEAN,
            displayName: "XN Protect",
            description: "Check users against a community global-ban list for Discord",
            default: false,
            onChange: (v: boolean) => warnThirdParty("enableXnProtect", v)
        },
        unifyUserReputationChecks: {
            type: OptionType.BOOLEAN,
            displayName: "Combine user checks",
            description: "Show one \"Scan user reputation\" entry instead of one per service",
            default: true
        },
        thirdPartyLinks: {
            type: OptionType.COMPONENT,
            component: ThirdPartyLinks
        },

        filterHeader: {
            type: OptionType.COMPONENT,
            component: () => <SeparatorSettings label="Filters & Blocklists" />
        },
        useBuiltinWhitelist: {
            type: OptionType.BOOLEAN,
            description: "Use built-in whitelist (Discord, YouTube, GitHub, etc. are skipped from scanning)",
            default: true
        },
        enableBlocklists: {
            type: OptionType.BOOLEAN,
            description: "Enable URL blocklist checking (flags URLs on known malicious lists)",
            default: true
        },
        enableFmhyBlocklist: {
            type: OptionType.BOOLEAN,
            description: "Use FMHY Unsafe Sites Filterlist (auto-updated every 4 days)",
            default: true,
            disabled: () => !settings.store.enableBlocklists
        },
        customWhitelist: {
            type: OptionType.STRING,
            description: "Custom whitelisted domains (comma-separated, e.g. example.com,mysite.org)",
            default: "",
            placeholder: "example.com, mysite.org"
        },
        customBlocklist: {
            type: OptionType.STRING,
            description: "Custom blocklisted domains (comma-separated, e.g. bad-site.com,scam.xyz)",
            default: "",
            placeholder: "bad-site.com, scam.xyz"
        },

        advancedHeader: {
            type: OptionType.COMPONENT,
            component: () => <SeparatorSettings label="Advanced Scanning" />
        },
        modularScanSettings: {
            type: OptionType.COMPONENT,
            component: ModularScanSettings
        }
    });
