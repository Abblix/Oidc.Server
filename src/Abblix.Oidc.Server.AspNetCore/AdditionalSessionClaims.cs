// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Claims;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Carries the additional claims of a session in the cookie <see cref="AuthenticationSchemeAdapter"/> writes, and
/// reads them back.
/// </summary>
internal static class AdditionalSessionClaims
{
    /// <summary>
    /// Claim names the adapter manages itself (the standard OIDC session claims). They are emitted from the typed
    /// <see cref="AuthSession"/> fields, so they must never be re-emitted from <see cref="AuthSession.AdditionalClaims"/>
    /// (a host- or browser-supplied additional claim keyed on one of these must not shadow the managed value), and they
    /// are excluded when reconstructing additional claims on read. A single set keeps the write-skip and the
    /// read-exclude from drifting apart.
    /// </summary>
    private static readonly HashSet<string> ReservedClaimTypes =
    [
        AuthenticationSchemeAdapter.SignedInAtClaimType,
        AuthenticationSchemeAdapter.TenantClaimType,
        JwtClaimTypes.Subject,
        IanaClaimTypes.Sid,
        IanaClaimTypes.AuthTime,
        IanaClaimTypes.Acr,
        IanaClaimTypes.Email,
        IanaClaimTypes.EmailVerified,
        IanaClaimTypes.Amr,
    ];

    /// <summary>
    /// Serializes each additional claim. A claim keyed on a reserved name is skipped so it cannot shadow or duplicate
    /// a managed claim already emitted from the typed <see cref="AuthSession"/> fields.
    /// </summary>
    public static void Write(List<Claim> claims, JsonObject additionalClaims)
    {
        foreach (var (claimType, jsonNode) in additionalClaims)
        {
            if (jsonNode == null || ReservedClaimTypes.Contains(claimType))
                continue;

            claims.Add(JsonClaimValue.ToClaim(claimType, jsonNode));
        }
    }

    /// <summary>
    /// Extracts additional claims from the principal, excluding standard OIDC claims.
    /// Uses claim ValueType to preserve exact type information during round-trip serialization.
    /// </summary>
    public static JsonObject Read(ClaimsPrincipal principal)
    {
        var additionalClaims = new JsonObject();

        foreach (var claim in principal.Claims)
        {
            if (ReservedClaimTypes.Contains(claim.Type))
                continue;

            additionalClaims[claim.Type] = JsonClaimValue.FromClaim(claim);
        }

        return additionalClaims;
    }
}
