// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Unit tests for <see cref="SecureHttpFetchOptionsValidator"/>, which refuses a named destination that
/// would permit more than its text says.
/// </summary>
public class SecureHttpFetchOptionsValidatorTests
{
    private static SecureHttpFetchOptionsValidator Validator => new();

    private static bool Succeeds(params Uri[] destinations)
        => Validator.Validate(null, new SecureHttpFetchOptions { AllowedDestinations = destinations }).Succeeded;

    [Theory]
    [InlineData("http://localhost:5002")]
    [InlineData("http://localhost:5002/manage/api/signout-backchannel-oidc")]
    [InlineData("https://backend-staging:5001/connect/token")]
    public void Validate_DestinationOfSchemeHostPortAndPath_Succeeds(string destination)
    {
        Assert.True(Succeeds(new Uri(destination)));
    }

    // Matching reads scheme, host, port and path and nothing else, so any component beyond those would sit
    // in the entry unread - the entry would permit every query at that path while appearing to permit one.
    [Theory]
    [InlineData("http://localhost:5002/api?tenant=abblix")]
    [InlineData("http://localhost:5002/api#section")]
    [InlineData("http://user:secret@localhost:5002/api")]
    public void Validate_DestinationCarryingAnUnreadComponent_Fails(string destination)
    {
        Assert.False(Succeeds(new Uri(destination)));
    }

    // A relative entry names no host, so it can never match anything and is a configuration mistake rather
    // than a permission.
    [Fact]
    public void Validate_RelativeDestination_Fails()
    {
        Assert.False(Succeeds(new Uri("/manage/api/signout-backchannel-oidc", UriKind.Relative)));
    }

    // One bad entry is refused even in the company of good ones - otherwise the mistake would be reported
    // only when it happened to sit first.
    [Fact]
    public void Validate_OneBadDestinationAmongGoodOnes_Fails()
    {
        Assert.False(Succeeds(
            new Uri("http://localhost:5002/api"),
            new Uri("http://localhost:5003/api?tenant=abblix"),
            new Uri("https://backend-staging:5001/connect/token")));
    }

    [Fact]
    public void Validate_WithNoDestinations_Succeeds()
    {
        Assert.True(Validator.Validate(null, new SecureHttpFetchOptions()).Succeeded);
        Assert.True(Succeeds());
    }

    /// <summary>
    /// The outbound proxy is judged by the one rule every setting naming a proxy is: a proxy the transport can
    /// reach passes, credentials included, and one it cannot is refused.
    /// </summary>
    [Theory]
    [InlineData("http://user:secret@proxy.example.com:3128", true)]
    [InlineData("socks5://proxy.example.com:1080", true)]
    [InlineData("ftp://proxy.example.com", false)]
    [InlineData("http://proxy.example.com:3128/path", false)]
    public void Validate_OutboundProxy(string proxy, bool succeeds)
        => Assert.Equal(
            succeeds,
            Validator.Validate(null, new SecureHttpFetchOptions { OutboundProxy = new Uri(proxy) }).Succeeded);

    /// <summary>
    /// A proxy no transport can use stops the host from starting, rather than failing the first fetch.
    /// </summary>
    [Fact]
    public async System.Threading.Tasks.Task AnUnusableOutboundProxy_IsRefusedAtStartup()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecureHttpFetch(options => options.OutboundProxy = new Uri("ftp://proxy.example.com"));
        using var provider = services.BuildServiceProvider();

        await Assert.ThrowsAsync<OptionsValidationException>(() => provider.GetRequiredService<IAsyncStartupValidator>()
            .ValidateAsync(TestContext.Current.CancellationToken));
    }
}
