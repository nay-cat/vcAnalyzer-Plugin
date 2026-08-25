/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

// Enum accepted by POST /reports anything else is rejected with HTTP 400 (thanks to ether)
export const UBFB_REASONS = [
    "Raider",
    "Miembro de una squad",
    "Dox",
    "Bot raider",
    "Spam al md",
    "Flood",
    "Suplantar identidad",
    "Nsfw",
    "Toxicidad",
    "Amenaza",
    "Estafa",
    "Infectar usuarios",
    "Multicuenta maliciosa",
    "Infiltración",
    "Plagio",
    "Generadores unchecked",
    "Uso de tools",
    "Incitación a lo repulsivo",
    "Violación del Tos",
    "Selfbot",
    "DDos"
] as const;

export type UbfbReason = typeof UBFB_REASONS[number];
