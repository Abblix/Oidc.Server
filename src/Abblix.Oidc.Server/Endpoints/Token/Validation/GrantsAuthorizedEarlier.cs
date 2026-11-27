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
/// The grants an authorization made before the token request settled: the request may narrow their scope and audience,
/// and nothing is inferred for them. Any other grant type, a host's own included, is one the request itself
/// authorizes, its grant built from what the request names.
/// </summary>
internal static class GrantsAuthorizedEarlier
{
    private static readonly HashSet<string> Types = new(StringComparer.Ordinal)
    {
        GrantTypes.AuthorizationCode,
        GrantTypes.RefreshToken,
        GrantTypes.DeviceAuthorization,
        GrantTypes.Ciba,
    };

    /// <summary>Whether <paramref name="grantType"/> is one an authorization made earlier settled.</summary>
    public static bool Include(string grantType) => Types.Contains(grantType);
}
