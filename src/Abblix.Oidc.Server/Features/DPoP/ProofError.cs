// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Describes why a DPoP proof was rejected. <see cref="Reason"/> is a stable token suitable for log
/// filters and metric labels; <see cref="Detail"/> is a human-readable hint.
/// </summary>
/// <remarks>
/// <see cref="Detail"/> CAN carry what the client put in the token: the JWT core writes several of its
/// descriptions by quoting the value it refused - an unhandled <c>crit</c> name, an unregistered
/// algorithm - and this type passes those through unchanged. An earlier version of this summary said
/// the value must not contain such input, which made it read as safe to surface; it was already
/// carrying it.
/// <para>
/// So the library puts it nowhere: no response, no log, no metric label. What a host reads off the
/// <see cref="ProofError"/> its own call returned is its own to sanitise, and a host that copies it
/// into a response is echoing the client's bytes.
/// </para>
/// </remarks>
/// <param name="Reason">A stable, machine-friendly token (e.g. <c>invalid_typ</c>,
/// <c>signature_invalid</c>, <c>htm_mismatch</c>).</param>
/// <param name="Detail">Optional human-readable diagnostic.</param>
public sealed record ProofError(string Reason, string? Detail = null);
