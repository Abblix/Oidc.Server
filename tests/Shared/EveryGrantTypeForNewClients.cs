// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Tests.Shared;

/// <summary>
/// Names every grant type for new clients, for a test host that registers its clients openly and drives every flow
/// through them: the default list gives a client only the authorization code and refresh token grants.
/// </summary>
public static class EveryGrantTypeForNewClients
{
    /// <summary>
    /// Every grant type the server can serve.
    /// </summary>
    public static readonly string[] GrantTypes =
    [
        Oidc.GrantTypes.AuthorizationCode,
        Oidc.GrantTypes.RefreshToken,
        Oidc.GrantTypes.Implicit,
        Oidc.GrantTypes.ClientCredentials,
        Oidc.GrantTypes.Password,
        Oidc.GrantTypes.Ciba,
        Oidc.GrantTypes.JwtBearer,
        Oidc.GrantTypes.DeviceAuthorization,
        Oidc.GrantTypes.TokenExchange,
    ];

    /// <summary>
    /// Sets <see cref="GrantTypes"/> as the grant types new clients of <paramref name="options"/> may request.
    /// </summary>
    public static void Apply(OidcOptions options)
        => options.NewClientOptions = options.NewClientOptions with { AllowedGrantTypes = GrantTypes };
}
