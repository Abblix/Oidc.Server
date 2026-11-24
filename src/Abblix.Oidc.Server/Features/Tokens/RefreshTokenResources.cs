// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// The resources of the grant a refresh token continues, kept in a claim of the server's own so the token's audience
/// names only this server.
/// </summary>
/// <remarks>
/// A resource server validating a token checks its issuer, signature and audience (RFC 9068 section 4), and many skip
/// the type check that alone tells an access token from a refresh token of the same grant. A refresh token whose
/// audience held the grant's resources would pass every check such a resource server makes, so its audience is the
/// issuer, the one party that reads it (RFC 7519 section 4.1.3), and the resources travel here. A token issued by 3.0
/// carries no such claim and holds its resources in the audience, which is where they are read from for it.
/// </remarks>
internal static class RefreshTokenResources
{
    /// <summary>
    /// The private claim the resources are kept under. It is one of the server's own claims, never carried from a
    /// refresh token into the access token issued for it, and prefixed so it takes no name a host gives a claim of
    /// its own.
    /// </summary>
    internal const string ClaimType = "abblix_resources";

    /// <summary>
    /// Writes <paramref name="context"/> into the refresh token <paramref name="payload"/>: as into an access token,
    /// except that the audience names the issuer and the resources are kept in the server's claim, as an empty list
    /// where the grant names none, so every token carrying the claim says where its resources are.
    /// </summary>
    public static void ApplyTo(AuthorizationContext context, JsonWebTokenPayload payload)
    {
        context.ApplyTo(payload);
        payload.Audiences = [payload.Issuer.NotNull(nameof(payload.Issuer))];
        payload.Json[ClaimType] = new JsonArray(
            [.. (context.Resources ?? []).Select(resource => (JsonNode?)JsonValue.Create(resource.OriginalString))]);
    }

    /// <summary>
    /// The authorization context of the grant the refresh token <paramref name="payload"/> continues.
    /// </summary>
    /// <remarks>
    /// Three states of the claim: absent, the token holds its resources in the audience, read there as from an
    /// access token; an empty list, the grant names no resource; values, the resources themselves.
    /// </remarks>
    public static AuthorizationContext ToAuthorizationContext(JsonWebTokenPayload payload)
    {
        var context = payload.ToAuthorizationContext();
        if (payload.Json.GetArrayOfStringsOrNull(ClaimType) is not { } values)
            return context;

        Uri[] kept =
        [
            .. values
                .Select(value => Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri : null)
                .OfType<Uri>(),
        ];
        return context with { Resources = kept.Length > 0 ? kept : null };
    }
}
