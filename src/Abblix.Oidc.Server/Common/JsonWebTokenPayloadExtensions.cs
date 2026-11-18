// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// What a token this server minted says about the client it was issued to.
/// </summary>
internal static class JsonWebTokenPayloadExtensions
{
    /// <summary>
    /// The client a token names: its <c>client_id</c>, else its <c>azp</c>, else its sole audience.
    /// </summary>
    /// <remarks>
    /// An access or refresh token carries <c>client_id</c>, while an ID token names its client only in <c>azp</c>
    /// or as its audience (OpenID Connect Core 1.0, section 2), so reading <c>client_id</c> alone treats an ID token
    /// as naming no client at all. More than one audience is ambiguous without <c>azp</c>, and names none.
    /// </remarks>
    public static string? NamedClientId(this JsonWebTokenPayload payload)
        => payload.ClientId ?? payload.AuthorizedParty ?? SingleAudience(payload);

    private static string? SingleAudience(JsonWebTokenPayload payload)
    {
        string? single = null;
        foreach (var audience in payload.Audiences)
        {
            if (single is not null)
                return null;

            single = audience;
        }

        return single;
    }
}
