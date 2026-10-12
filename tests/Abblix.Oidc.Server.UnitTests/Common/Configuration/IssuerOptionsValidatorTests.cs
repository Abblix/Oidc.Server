// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// The configured issuer is an https URL with no query or fragment (OpenID Connect Core 1.0 section 1.2); an http one
/// is let through only when the deployment allows it for local development.
/// </summary>
public class IssuerOptionsValidatorTests
{
    private static bool Refused(string issuer, bool allowHttp = false)
        => new IssuerOptionsValidator()
            .Validate(null, new OidcOptions { Issuer = new Uri(issuer, UriKind.RelativeOrAbsolute), AllowHttpIssuer = allowHttp })
            .Failed;

    [Theory]
    [InlineData("https://auth.example.com")]
    [InlineData("https://Auth.Example.com:443/tenants/acme")]
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
    public void AnIssuerThatIsNoHttpsUrlWithoutQueryOrFragment_IsRefused(string issuer)
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
    /// The check is part of what the server registers, so an http issuer stops it when its settings are read.
    /// </summary>
    [Fact]
    public void TheServerRefusesAnHttpIssuer_WhenItsSettingsAreRead()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options => options.Issuer = new Uri("http://localhost:5000"));
        services.AddIssuer();
        using var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
    }

    /// <summary>
    /// With no issuer configured the server takes it from each request, which the HTTPS gate on every endpoint keeps
    /// to https.
    /// </summary>
    [Fact]
    public void NoIssuer_IsAccepted()
        => Assert.False(new IssuerOptionsValidator().Validate(null, new OidcOptions()).Failed);
}
