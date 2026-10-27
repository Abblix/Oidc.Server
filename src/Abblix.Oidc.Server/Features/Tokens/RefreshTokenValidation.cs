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
/// How the server checks a refresh token it reads back.
/// </summary>
internal static class RefreshTokenValidation
{
    /// <summary>
    /// Every check of a token this server issued, except that its audience is not required to name the server.
    /// </summary>
    /// <remarks>
    /// The audience of a refresh token holds the resources of the grant it continues
    /// (<see cref="RefreshTokenService"/>), and names the server only when the grant carries none, whether named or
    /// inferred from its scopes. Only this server reads a refresh token, and its type, issuer and tenant say it is one
    /// this server issued.
    /// </remarks>
    public const ValidationOptions Options = ValidationOptions.Default & ~ValidationOptions.RequireValidAudience;
}
