// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Pins the scheme allowlist to what a configuration file says. This is an allowlist consumed by
/// SSRF validation, so the failure worth testing is widening: a default held in the property is
/// added to by the configuration binder rather than replaced, and a host that configures plain
/// HTTP would silently keep HTTPS allowed beside it.
/// </summary>
public class SecureHttpFetchOptionsBindingTests
{
    private static SecureHttpFetchOptions Bind(Dictionary<string, string?> values)
        => new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build()
            .GetSection("SecureHttpFetch")
            .Get<SecureHttpFetchOptions>()!;

    /// <summary>
    /// A file that names one scheme gets that one scheme, not the union of the file and the default.
    /// </summary>
    [Fact]
    public void Bind_SchemeList_ReplacesRatherThanExtends()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["SecureHttpFetch:AllowedSchemes:0"] = Uri.UriSchemeHttp,
        });

        Assert.NotNull(options.AllowedSchemes);
        Assert.Equal([Uri.UriSchemeHttp], options.AllowedSchemes);
        Assert.Equal([Uri.UriSchemeHttp], options.EffectiveAllowedSchemes);
    }

    /// <summary>
    /// A file that says nothing leaves the restriction at the library's default, which is HTTPS
    /// alone. The default lives in the effective accessor, because held in the property it would
    /// leak into every bound list.
    /// </summary>
    [Fact]
    public void Bind_WithoutSchemes_KeepsTheHttpsDefault()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["SecureHttpFetch:BlockPrivateNetworks"] = "true",
        });

        Assert.Null(options.AllowedSchemes);
        Assert.Equal([Uri.UriSchemeHttps], options.EffectiveAllowedSchemes);
    }

    /// <summary>
    /// An empty value is a statement, not an omission: it lifts the scheme restriction entirely,
    /// and it is how a file expresses that - null has no spelling in configuration.
    /// </summary>
    [Fact]
    public void Bind_ExplicitlyEmptySchemes_LiftTheRestriction()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["SecureHttpFetch:AllowedSchemes"] = "",
        });

        Assert.NotNull(options.AllowedSchemes);
        Assert.Empty(options.AllowedSchemes);
        Assert.Empty(options.EffectiveAllowedSchemes);
    }

    /// <summary>
    /// The same three statements made in code, because a host that builds its options in C# needs
    /// the identical contract.
    /// </summary>
    [Fact]
    public void ConstructedInCode_FollowsTheSameContract()
    {
        Assert.Equal([Uri.UriSchemeHttps], new SecureHttpFetchOptions().EffectiveAllowedSchemes);
        Assert.Empty(new SecureHttpFetchOptions { AllowedSchemes = [] }.EffectiveAllowedSchemes);
        Assert.Equal(
            [Uri.UriSchemeHttp],
            new SecureHttpFetchOptions { AllowedSchemes = [Uri.UriSchemeHttp] }.EffectiveAllowedSchemes);
    }
}
