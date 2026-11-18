// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// The scope a token request is served with, read by every step that judges or acts on it, so each sees the same
/// scope whether the request named it or was given the client's default.
/// </summary>
internal static class TokenRequestScope
{
    /// <summary>
    /// The scope <paramref name="context"/>'s request is served with, or null when its client is required to name
    /// one and it names none.
    /// </summary>
    /// <remarks>
    /// Only a grant starting from the client alone serves a request naming no scope with the client's default: a
    /// code, a refresh token, a device code or a backchannel request carries the scope it was granted, and a token
    /// exchange inherits the subject token's. Read once the client is known.
    /// </remarks>
    public static string[]? ServedFor(TokenValidationContext context)
        => context.Request.GrantType is GrantTypes.ClientCredentials or GrantTypes.Password or GrantTypes.JwtBearer
            ? context.ClientInfo.ScopeServedFor(context.Request.Scope)
            : context.Request.Scope;
}
