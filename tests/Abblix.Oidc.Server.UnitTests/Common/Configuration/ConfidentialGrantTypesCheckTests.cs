// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A tenant's client authenticating with none that may use a grant kept for confidential clients stops the server at
/// startup, while the same client authenticating itself does not, and a public client using the grants an end user
/// takes part in is left alone.
/// </summary>
public class ConfidentialGrantTypesCheckTests
{
    [Theory]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.ClientCredentials, true)]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.Password, true)]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.JwtBearer, true)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost, GrantTypes.ClientCredentials, false)]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.AuthorizationCode, false)]
    public void ATenantsClient_IsRefusedOnlyWhenItMayUseAConfidentialGrantWithoutAuthenticating(
        string authenticationMethod,
        string grantType,
        bool refused)
    {
        var tenant = new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri("https://auth.example.com"),
            Clients =
            [
                new ClientInfo("client")
                {
                    TokenEndpointAuthMethod = authenticationMethod,
                    AllowedGrantTypes = [GrantTypes.AuthorizationCode, grantType],
                },
            ],
        };

        var refusals = new ConfidentialGrantTypesCheck().Check([tenant], new OidcOptions());

        Assert.Equal(refused, refusals.Any());
    }
}
