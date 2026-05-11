// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
