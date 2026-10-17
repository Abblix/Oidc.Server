// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A configured client that may use backchannel authentication must authenticate itself, so one registered with the
/// method "none" stops the server at startup, while the same client with a method that authenticates does not, and a
/// public client that does not use the flow is left alone.
/// </summary>
public class BackChannelClientAuthenticationValidatorTests
{
    [Theory]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.Ciba, true)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, GrantTypes.Ciba, false)]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.AuthorizationCode, false)]
    public void AConfiguredClient_IsRefusedOnlyWhenItUsesTheFlowWithoutAuthenticating(
        string authenticationMethod,
        string grantType,
        bool refused)
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo("client")
                {
                    TokenEndpointAuthMethod = authenticationMethod,
                    AllowedGrantTypes = [grantType],
                },
            ],
        };

        var result = new BackChannelClientAuthenticationValidator().Validate(null, options);

        Assert.Equal(refused, result.Failed);
    }
}
