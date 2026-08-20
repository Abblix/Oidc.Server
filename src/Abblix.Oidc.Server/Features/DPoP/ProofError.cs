// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Describes why a DPoP proof was rejected. <see cref="Reason"/> is a stable token suitable for log filters and
/// metric labels; <see cref="Detail"/> is a human-readable hint that MUST NOT contain attacker-controllable input
/// verbatim, since this string can surface in error responses and operator dashboards.
/// </summary>
/// <param name="Reason">A stable, machine-friendly token (e.g. <c>invalid_typ</c>,
/// <c>signature_invalid</c>, <c>htm_mismatch</c>).</param>
/// <param name="Detail">Optional human-readable diagnostic.</param>
public sealed record ProofError(string Reason, string? Detail = null);
