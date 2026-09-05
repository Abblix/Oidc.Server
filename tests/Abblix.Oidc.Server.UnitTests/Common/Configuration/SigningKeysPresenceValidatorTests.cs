// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Pins when the host is refused at startup for having no signing key. The refusal must fire on
/// exactly one state - the library's own static provider serving an empty
/// <see cref="OidcOptions.SigningKeys"/> - because that host can never sign a token and the fact is
/// fully known before the first request. Every other arrangement must start: a host-supplied
/// provider may read keys from a store that is legitimately unreachable while the host boots, and a
/// half-wired custodian is refused elsewhere with a message naming the missing placement call.
/// Each case goes through the real registration and the options pipeline, so the wiring is part of
/// what is proven - a validator class with passing tests and no registration protects nobody.
/// </summary>
public class SigningKeysPresenceValidatorTests
{
    /// <summary>
    /// The hopeless state: static provider, no custodian, no keys. Without the refusal this host
    /// comes up healthy and publishes an empty JWKS for relying parties to cache.
    /// </summary>
    [Fact]
    public void Value_StaticProviderWithoutKeys_IsRefused()
    {
        using var serviceProvider = BuildHost();

        var exception = Assert.Throws<OptionsValidationException>(
            () => serviceProvider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Contains(nameof(OidcOptions.SigningKeys), exception.Message);
    }

    /// <summary>
    /// One configured key is enough: the static provider will serve it.
    /// </summary>
    [Fact]
    public void Value_StaticProviderWithSigningKey_Starts()
    {
        using var serviceProvider = BuildHost(services => services.Configure<OidcOptions>(
            options => options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)]));

        var options = serviceProvider.GetRequiredService<IOptions<OidcOptions>>().Value;

        Assert.NotEmpty(options.SigningKeys);
    }

    /// <summary>
    /// A host-supplied provider is trusted, not probed: its store may be unreachable during boot,
    /// and a startup probe would turn that into a refusal to start a working deployment.
    /// </summary>
    [Fact]
    public void Value_HostSuppliedProvider_StartsWithoutProbing()
    {
        var provider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);

        using var serviceProvider = BuildHost(
            services => services.AddSingleton(provider.Object));

        _ = serviceProvider.GetRequiredService<IOptions<OidcOptions>>().Value;

        provider.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A registered custodian means external keys are intended; the placement machinery owns that
    /// path and refuses its misconfigurations with a more precise message than this check could.
    /// </summary>
    [Fact]
    public void Value_WithCustodianRegistered_LeavesTheDecisionToPlacement()
    {
        using var serviceProvider = BuildHost(
            services => services.AddSingleton(Mock.Of<IKeyCustodian>()));

        var options = serviceProvider.GetRequiredService<IOptions<OidcOptions>>().Value;

        // No signing key and yet no refusal: with a custodian present the placement machinery,
        // not this validator, is the authority on whether the arrangement is complete.
        Assert.Empty(options.SigningKeys);
    }

    /// <summary>
    /// Builds the service graph the way a host does: the real registration method, plus whatever
    /// the case under test adds. The host-supplied registration runs first, matching a host that
    /// registers its provider before calling the library.
    /// </summary>
    private static ServiceProvider BuildHost(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddOptions();
        configure?.Invoke(services);
        services.AddAuthServiceJwt();
        return services.BuildServiceProvider();
    }
}
