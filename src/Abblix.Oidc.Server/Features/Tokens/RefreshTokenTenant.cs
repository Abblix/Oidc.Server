// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// The tenant and creation a refresh token was issued at, named in it as the key ring's partition of that tenant is
/// named. What is recorded about a refresh token is kept for that tenant and creation, so a token is accepted only at
/// the one it names (<see cref="Validation.AuthServiceJwtValidator"/>). The server names it while signing the token
/// (<see cref="Formatters.AuthServiceJwtFormatter"/>), so a refresh token issued by a service of the host's own names
/// it too, as long as the token is signed through that formatter.
/// </summary>
internal static class RefreshTokenTenant
{
    /// <summary>
    /// The private claim the tenant is named under. It is one of the server's own claims, never carried from a
    /// refresh token into the access token issued for it, and prefixed so it takes no name a host gives a claim of
    /// its own.
    /// </summary>
    internal const string ClaimType = "abblix_tenant";

    /// <summary>
    /// Names in <paramref name="payload"/> the tenant and creation whose keys live in <paramref name="partition"/>.
    /// </summary>
    public static void Name(JsonWebTokenPayload payload, string partition)
        => payload.Json.SetProperty(ClaimType, partition);

    /// <summary>
    /// Whether <paramref name="payload"/> names the tenant and creation whose keys live in
    /// <paramref name="partition"/>; a refresh token issued before 3.0 names none.
    /// </summary>
    public static bool Names(JsonWebTokenPayload payload, string partition)
        => payload.Json.GetProperty<string>(ClaimType) == partition;
}
