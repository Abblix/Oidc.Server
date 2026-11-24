// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// The token settings the host gives new clients start the host only when a token can be issued and redeemed under
/// them: positive lifetimes, no sliding window or a positive one, and a reuse policy the enumeration defines. A refusal
/// names the setting.
/// </summary>
public class NewClientTokenLifetimesValidatorTests
{
    private const string Section = nameof(OidcOptions.NewClientOptions);
    private const string RefreshToken = $"{Section}.{nameof(NewClientOptions.RefreshToken)}";

    private static ValidateOptionsResult Validate(NewClientOptions newClients)
        => new NewClientTokenLifetimesValidator().Validate(name: null, new OidcOptions { NewClientOptions = newClients });

    [Fact]
    public void TheDefaults_StartTheHost()
        => Assert.True(Validate(new NewClientOptions()).Succeeded);

    [Fact]
    public void NoSlidingWindow_StartsTheHost()
        => Assert.True(Validate(new NewClientOptions { RefreshToken = new() { SlidingExpiresIn = null } }).Succeeded);

    public static TheoryData<NewClientOptions, string> Refused => new()
    {
        { new NewClientOptions { AccessTokenExpiresIn = TimeSpan.Zero }, $"{Section}.{nameof(NewClientOptions.AccessTokenExpiresIn)}" },
        {
            new NewClientOptions { AccessTokenExpiresIn = TimeSpan.FromSeconds(-1) },
            $"{Section}.{nameof(NewClientOptions.AccessTokenExpiresIn)}"
        },
        {
            new NewClientOptions { RefreshToken = new() { AbsoluteExpiresIn = TimeSpan.Zero } },
            $"{RefreshToken}.{nameof(RefreshTokenOptions.AbsoluteExpiresIn)}"
        },
        {
            new NewClientOptions { RefreshToken = new() { SlidingExpiresIn = TimeSpan.Zero } },
            $"{RefreshToken}.{nameof(RefreshTokenOptions.SlidingExpiresIn)}"
        },
        {
            new NewClientOptions { RefreshToken = new() { ReusePolicy = (RefreshTokenReusePolicy)42 } },
            $"{RefreshToken}.{nameof(RefreshTokenOptions.ReusePolicy)}"
        },
    };

    [Theory]
    [MemberData(nameof(Refused))]
    public void ASettingNoTokenCanBeUsedUnder_IsRefusedNamingIt(NewClientOptions newClients, string setting)
    {
        var outcome = Validate(newClients);

        Assert.False(outcome.Succeeded);
        Assert.Contains(setting, outcome.FailureMessage);
    }

    /// <summary>
    /// The server's own validators include this one, so a host never reaches its first registration with such a value.
    /// </summary>
    [Fact]
    public void TheServersValidators_RefuseANewClientLifetimeNoTokenCanBeUsedUnder()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddOidcServices(options => options.NewClientOptions = options.NewClientOptions with
        {
            AccessTokenExpiresIn = TimeSpan.Zero,
        });
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains(
            refusal.Failures,
            failure => failure.Contains($"{Section}.{nameof(NewClientOptions.AccessTokenExpiresIn)}", StringComparison.Ordinal));
    }

    /// <summary>
    /// A host sets these in its configuration, and the refresh token policy binds member by member into the record
    /// held behind an init-only property.
    /// </summary>
    [Fact]
    public void TheTokenSettingsForNewClients_BindFromConfiguration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{Section}:AccessTokenExpiresIn"] = "00:03:00",
            [$"{Section}:SingleResourceAccessTokens"] = "true",
            [$"{Section}:{nameof(NewClientOptions.RefreshToken)}:AbsoluteExpiresIn"] = "02:00:00",
            [$"{Section}:{nameof(NewClientOptions.RefreshToken)}:SlidingExpiresIn"] = "00:30:00",
            [$"{Section}:{nameof(NewClientOptions.RefreshToken)}:ReusePolicy"] = nameof(RefreshTokenReusePolicy.Rotate),
        }).Build();

        var options = new OidcOptions();
        configuration.Bind(options);

        Assert.Equal(TimeSpan.FromMinutes(3), options.NewClientOptions.AccessTokenExpiresIn);
        Assert.True(options.NewClientOptions.SingleResourceAccessTokens);
        Assert.Equal(
            new RefreshTokenOptions
            {
                AbsoluteExpiresIn = TimeSpan.FromHours(2),
                SlidingExpiresIn = TimeSpan.FromMinutes(30),
                ReusePolicy = RefreshTokenReusePolicy.Rotate,
            },
            options.NewClientOptions.RefreshToken);
    }
}
