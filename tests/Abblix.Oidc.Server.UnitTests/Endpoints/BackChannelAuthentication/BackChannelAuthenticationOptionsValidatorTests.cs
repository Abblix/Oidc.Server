// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication;

/// <summary>
/// Backchannel authentication lifetimes the server cannot serve a request with are refused when the settings are
/// first read, naming the setting, rather than answered with a server error on every backchannel request.
/// </summary>
/// <remarks>
/// Driven through the container a host builds with backchannel authentication turned on, so the check is held both
/// to its rules and to being registered by that opt-in.
/// </remarks>
public class BackChannelAuthenticationOptionsValidatorTests
{
    private static readonly TimeSpan OneSecond = TimeSpan.FromSeconds(1);

    /// <summary>
    /// A lifetime of no length or below it, a default longer than the maximum a client may ask for, and a maximum
    /// so long that a pending request's retention, its lifetime plus the maximum, cannot be computed or stored.
    /// </summary>
    public static TheoryData<TimeSpan, TimeSpan, string> Refused => new()
    {
        { TimeSpan.Zero, TimeSpan.FromMinutes(30), nameof(BackChannelAuthenticationOptions.DefaultExpiry) },
        { -OneSecond, TimeSpan.FromMinutes(30), nameof(BackChannelAuthenticationOptions.DefaultExpiry) },
        { TimeSpan.FromMinutes(5), TimeSpan.Zero, nameof(BackChannelAuthenticationOptions.MaximumExpiry) },
        { TimeSpan.FromMinutes(5), -OneSecond, nameof(BackChannelAuthenticationOptions.MaximumExpiry) },
        { TimeSpan.FromMinutes(5), TimeSpan.MaxValue, nameof(BackChannelAuthenticationOptions.MaximumExpiry) },
        {
            TimeSpan.FromMinutes(5),
            BackChannelAuthenticationOptionsValidator.LongestMaximumExpiry + TimeSpan.FromTicks(1),
            nameof(BackChannelAuthenticationOptions.MaximumExpiry)
        },
        { TimeSpan.FromMinutes(31), TimeSpan.FromMinutes(30), nameof(BackChannelAuthenticationOptions.DefaultExpiry) },
    };

    [Theory]
    [MemberData(nameof(Refused))]
    public void ALifetimeTheServerCannotServeIsRefusedNamingTheSetting(
        TimeSpan defaultExpiry, TimeSpan maximumExpiry, string named)
    {
        var provider = BuildProvider(defaultExpiry, maximumExpiry);

        var failure = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains(named, failure.Message);
    }

    /// <summary>
    /// The control: the defaults, and a default equal to the maximum, are served.
    /// </summary>
    [Theory]
    [InlineData(5, 30)]
    [InlineData(30, 30)]
    public void ALifetimeTheServerCanServeIsAccepted(int defaultMinutes, int maximumMinutes)
    {
        var provider = BuildProvider(TimeSpan.FromMinutes(defaultMinutes), TimeSpan.FromMinutes(maximumMinutes));

        var settings = provider.GetRequiredService<IOptions<OidcOptions>>().Value.BackChannelAuthentication;
        Assert.Equal(TimeSpan.FromMinutes(maximumMinutes), settings.MaximumExpiry);
    }

    /// <summary>
    /// The longest maximum accepted is served: its retention is a duration the clock and the store hold.
    /// </summary>
    [Fact]
    public void TheLongestMaximumIsAccepted()
    {
        var longest = BackChannelAuthenticationOptionsValidator.LongestMaximumExpiry;
        var provider = BuildProvider(TimeSpan.FromMinutes(5), longest);

        Assert.Equal(
            longest,
            provider.GetRequiredService<IOptions<OidcOptions>>().Value.BackChannelAuthentication.MaximumExpiry);
    }

    private static ServiceProvider BuildProvider(TimeSpan defaultExpiry, TimeSpan maximumExpiry)
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserCredentialsAuthenticator>());
        services.AddSingleton(Mock.Of<IUserInfoProvider>());

        services.AddBackChannelAuthentication();
        services.AddOidcServices(options =>
        {
            options.Tenants.Add(new TenantDefinition
            {
                Id = TestIssuer.TenantId,
                Issuer = TestConstants.DefaultIssuer,
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
            });
            options.RequireInitialAccessToken = false;
            options.BackChannelAuthentication.DefaultExpiry = defaultExpiry;
            options.BackChannelAuthentication.MaximumExpiry = maximumExpiry;
        });

        return services.BuildServiceProvider();
    }
}
