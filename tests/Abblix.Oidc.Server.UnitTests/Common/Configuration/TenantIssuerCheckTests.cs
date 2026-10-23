// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A tenant's issuer is an https URL with no query or fragment (OpenID Connect Core 1.0 section 1.2), judged by
/// <see cref="TenantDefinitionsCheck"/>; an http one is let through only when the deployment allows it for local
/// development.
/// </summary>
public class TenantIssuerCheckTests
{
    private static bool Refused(string issuer, bool allowHttp = false)
        => new TenantDefinitionsCheck()
            .Check(
                [new TenantDefinition { Id = "acme", Issuer = new Uri(issuer, UriKind.RelativeOrAbsolute) }],
                new OidcOptions { AllowHttpIssuer = allowHttp })
            .Any();

    [Theory]
    [InlineData("https://auth.example.com")]
    [InlineData("https://Auth.Example.com:443/tenants/acme")]
    [InlineData("https://auth.example.com/t1")]
    [InlineData("https://auth.example.com/t1/")]
    public void AnHttpsIssuer_IsAccepted(string issuer)
        => Assert.False(Refused(issuer));

    [Theory]
    [InlineData("auth.example.com")]
    [InlineData("/issuer")]
    [InlineData("http://localhost:5000")]
    [InlineData("https://auth.example.com?x=1")]
    [InlineData("https://auth.example.com#x")]
    [InlineData("ftp://auth.example.com")]
    [InlineData("file:///issuer")]
    [InlineData("https://auth.example.com\n")]
    [InlineData(" https://auth.example.com")]
    [InlineData("https://auth.example.com/a b")]
    [InlineData("https://auth.example.com/a\tb")]
    [InlineData("https://user:pw@auth.example.com")]
    [InlineData("https://auth.example.com/a|b")]
    [InlineData("https://auth.example.com/a%zz")]
    public void AnIssuerThatIsNoHttpsUrlWithoutQueryOrFragment_IsRefused(string issuer)
        => Assert.True(Refused(issuer));

    /// <summary>
    /// An issuer whose path holds an empty segment is refused: routing would take the path as it is, while resolving
    /// an address against the host reads a path opening with one as naming another host (RFC 3986 section 4.2).
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com//t1")]
    [InlineData("https://auth.example.com/t1//eu")]
    [InlineData("https://auth.example.com/t1//")]
    [InlineData("https://auth.example.com//")]
    public void AnIssuerWithAnEmptyPathSegment_IsRefused(string issuer)
        => Assert.True(Refused(issuer));

    [Fact]
    public void AnHttpIssuer_IsAccepted_WhenTheDeploymentAllowsIt()
        => Assert.False(Refused("http://localhost:5000", allowHttp: true));

    [Theory]
    [InlineData("ftp://auth.example.com")]
    [InlineData("http://localhost:5000?x=1")]
    public void AllowingHttp_LetsNothingElseThrough(string issuer)
        => Assert.True(Refused(issuer, allowHttp: true));

    /// <summary>
    /// The check is part of what the server registers for its tenants, so an issuer it refuses stops the server when
    /// its settings are read.
    /// </summary>
    [Theory]
    [InlineData("http://localhost:5000")]
    [InlineData("https://auth.example.com//t1")]
    public void TheServerRefusesTheIssuer_WhenItsSettingsAreRead(string issuer)
    {
        using var provider = ServerServing(issuer);

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
    }

    /// <summary>
    /// The same tenant at an https issuer is read without a refusal, so the case above is about the scheme rather
    /// than about a registration that refuses every tenant.
    /// </summary>
    [Fact]
    public void TheServerReadsAnHttpsIssuer_WithoutARefusal()
    {
        using var provider = ServerServing("https://auth.example.com");

        Assert.NotEmpty(provider.GetRequiredService<IOptions<OidcOptions>>().Value.Tenants);
    }

    private static ServiceProvider ServerServing(string issuer)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(
            options => options.Tenants.Add(new TenantDefinition { Id = TestIssuer.TenantId, Issuer = new Uri(issuer) }));
        services.AddTenants();
        return services.BuildServiceProvider();
    }
}
