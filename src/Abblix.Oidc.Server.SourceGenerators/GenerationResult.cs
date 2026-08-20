// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.SourceGenerators;

/// <summary>
/// The rendered output for one model: the hint name, the full source text (or null when generation
/// failed), and the diagnostics to report. A pure value so the driver skips re-emission when
/// nothing changed.
/// </summary>
internal sealed record GenerationResult(
    string HintName,
    string? Source,
    EquatableArray<DiagnosticInfo> Diagnostics);