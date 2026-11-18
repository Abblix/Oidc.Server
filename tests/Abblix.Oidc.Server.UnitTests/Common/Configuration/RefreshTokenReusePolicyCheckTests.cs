// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A tenant's client's refresh token reuse policy is checked at startup, rather than when the client is first
/// issued a refresh token.
/// </summary>
public class RefreshTokenReusePolicyCheckTests
{
    private static TenantDefinition TenantWith(params ClientInfo[] clients) => new()
    {
        Id = "acme",
        Issuer = TestConstants.DefaultIssuer,
        Clients = clients,
    };

    [Fact]
    public void AnUndefinedPolicy_IsRefused()
    {
        var tenant = TenantWith(
            new ClientInfo("web"),
            new ClientInfo("mobile") { RefreshToken = new RefreshTokenOptions { ReusePolicy = (RefreshTokenReusePolicy)42 } });

        var refusal = Assert.Single(new RefreshTokenReusePolicyCheck().Check([tenant], new OidcOptions()));

        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
    }

    /// <summary>
    /// The shipped composition refuses it too, which a check nobody registers would not.
    /// </summary>
    [Fact]
    public void TheComposition_RefusesAnUndefinedPolicy()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddOidcCore(options => options.Tenants.Add(TenantWith(
            new ClientInfo("web")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
                RefreshToken = new RefreshTokenOptions { ReusePolicy = (RefreshTokenReusePolicy)42 },
            })));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Contains(refusal.Failures, failure => failure.Contains(nameof(RefreshTokenOptions.ReusePolicy)));
    }

    [Theory]
    [InlineData(RefreshTokenReusePolicy.WhenSenderConstrained)]
    [InlineData(RefreshTokenReusePolicy.Reuse)]
    [InlineData(RefreshTokenReusePolicy.Rotate)]
    public void ADefinedPolicy_PassesTheCheck(RefreshTokenReusePolicy policy)
    {
        var tenant = TenantWith(new ClientInfo("web") { RefreshToken = new RefreshTokenOptions { ReusePolicy = policy } });

        Assert.Empty(new RefreshTokenReusePolicyCheck().Check([tenant], new OidcOptions()));
    }
}
