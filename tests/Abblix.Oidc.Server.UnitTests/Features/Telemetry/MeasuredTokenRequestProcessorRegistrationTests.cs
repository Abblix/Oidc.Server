// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// The token request processor a server hands out counts its tokens, so every caller of it does - the token
/// endpoint and a CIBA push delivery alike.
/// </summary>
public sealed class MeasuredTokenRequestProcessorRegistrationTests
{
    [Fact]
    public void TheTokenRequestProcessorOfAServer_IsMeasured()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserCredentialsAuthenticator>());
        services.AddSingleton(Mock.Of<IUserInfoProvider>());
        services.AddBackChannelAuthentication();
        services.AddOidcServices(options =>
        {
            options.Issuer = TestConstants.DefaultIssuer.OriginalString;
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)];
        });

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.IsType<MeasuredTokenRequestProcessor>(scope.ServiceProvider.GetRequiredService<ITokenRequestProcessor>());
    }
}
