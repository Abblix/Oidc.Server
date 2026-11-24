// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// The server refuses a tenant admitting no client authentication method wherever the tenant enters it: one in the
/// settings stops the start, one read from a store is left out while the tenants beside it are served. The check
/// asks the server's own client authenticator, which the server builds in whatever order its parts are first asked
/// for.
/// </summary>
public class TenantAuthenticationMethodsWiringTests
{
    /// <summary>
    /// A FAPI 2.0 tenant in the settings of a server offering a shared secret alone stops the start, and the same
    /// tenant starts where the server offers the private key JWT.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, true)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, false)]
    public void ATenantInTheSettings_AdmittingNoMethod_StopsTheStart(string offered, bool stops)
    {
        var services = ServerWith(ClientSecurityProfile.Fapi2);
        services.AddSingleton(AuthenticatorOffering(offered));
        using var provider = services.BuildServiceProvider();

        var start = Record.Exception(() => _ = provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        if (stops)
            Assert.IsType<OptionsValidationException>(start);
        else
            Assert.Null(start);
    }

    /// <summary>
    /// A tenant read from a store that admits no method the server offers is left out, and the tenant beside it is
    /// served.
    /// </summary>
    [Fact]
    public async Task AStoredTenant_AdmittingNoMethod_IsLeftOut()
    {
        var ct = TestContext.Current.CancellationToken;
        var declared = new OidcOptions
        {
            Tenants =
            [
                new TenantDefinition
                {
                    Id = "fapi",
                    Issuer = new Uri("https://fapi.example.com"),
                    DefaultSecurityProfile = ClientSecurityProfile.Fapi2,
                },
                new TenantDefinition { Id = "plain", Issuer = new Uri("https://plain.example.com") },
            ],
        };
        var check = new TenantAuthenticationMethodsCheck(new ServiceCollection()
            .AddSingleton(AuthenticatorOffering(ClientAuthenticationMethods.ClientSecretBasic))
            .BuildServiceProvider());
        var catalog = new StoreTenantCatalog(
            NullLogger<StoreTenantCatalog>.Instance,
            new OptionsTenantStore(Options.Create(declared)),
            [check],
            [],
            [],
            Options.Create(declared),
            TimeProvider.System);

        await catalog.RefreshAsync(ct);

        Assert.Null(await catalog.FindByIdAsync("fapi", ct));
        Assert.NotNull(await catalog.FindByIdAsync("plain", ct));
    }

    /// <summary>
    /// The server's settings, its client authenticator, its tenants and its budget of failed authentications resolve
    /// whichever of them is asked for first, the check among the settings' checks.
    /// </summary>
    [Theory]
    [InlineData(nameof(IOptions<OidcOptions>))]
    [InlineData(nameof(IClientAuthenticator))]
    [InlineData(nameof(ITenantCatalog))]
    [InlineData(nameof(CallerRateLimiters.AuthenticationFailures))]
    public void TheServer_ResolvesWhicheverPartIsAskedForFirst(string first)
    {
        using var provider = ServerWith(ClientSecurityProfile.Fapi2).BuildServiceProvider();
        Action[] parts =
        [
            () => _ = provider.GetRequiredService<IOptions<OidcOptions>>().Value,
            () => provider.GetRequiredService<IClientAuthenticator>(),
            () => provider.GetRequiredService<ITenantCatalog>(),
            () => provider.GetRequiredKeyedService<PartitionedRateLimiter<string>>(
                CallerRateLimiters.AuthenticationFailures),
        ];
        var firstIndex = first switch
        {
            nameof(IOptions<OidcOptions>) => 0,
            nameof(IClientAuthenticator) => 1,
            nameof(ITenantCatalog) => 2,
            nameof(CallerRateLimiters.AuthenticationFailures) => 3,
            _ => throw new ArgumentOutOfRangeException(nameof(first), first, null),
        };

        Assert.Null(Record.Exception(parts[firstIndex]));
        Assert.All(parts, part => Assert.Null(Record.Exception(part)));
    }

    private static IServiceCollection ServerWith(ClientSecurityProfile profile)
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddOidcServices(options =>
        {
            // Signed with an algorithm FAPI admits, so the tenant is refused only for its authentication methods
            foreach (var token in new[]
                     {
                         options.ServiceTokens.AccessToken, options.ServiceTokens.RefreshToken,
                         options.ServiceTokens.RegistrationAccessToken, options.ServiceTokens.InitialAccessToken,
                     })
            {
                token.Signing.Algorithm = SigningAlgorithms.PS256;
            }

            options.Tenants.Add(new TenantDefinition
            {
                Id = TestIssuer.TenantId,
                Issuer = TestConstants.DefaultIssuer,
                DefaultSecurityProfile = profile,
                ClientSecretEncryption = new ClientSecretEncryptionSettings
                {
                    Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                },
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.PS256)],
            });
        });
        return services;
    }

    private static IClientAuthenticator AuthenticatorOffering(string method)
    {
        var authenticator = new Mock<IClientAuthenticator>();
        authenticator.Setup(a => a.ClientAuthenticationMethodsSupported).Returns([method]);
        return authenticator.Object;
    }
}
