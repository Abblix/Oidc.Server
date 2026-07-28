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
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="DefaultResourceIndicatorValidator"/> refuses a default that would put an unusable
/// value in every access token's <c>aud</c> claim, rather than letting it surface later as a resource server
/// rejecting tokens it cannot recognise.
/// </summary>
public class DefaultResourceIndicatorValidatorTests
{
    private static readonly Uri Api = new("https://api.example.com");

    private readonly DefaultResourceIndicatorValidator _validator = new();

    /// <summary>
    /// The shipped default states nothing, so a stock configuration validates and the audience keeps falling
    /// back to the client identifier.
    /// </summary>
    [Fact]
    public void Validate_NoDefaultStated_Succeeds()
    {
        var options = new OidcOptions();

        Assert.Null(options.DefaultResourceIndicator);
        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    /// <summary>
    /// A default naming a registered resource is exactly the configuration this setting exists for.
    /// </summary>
    [Fact]
    public void Validate_DefaultNamesARegisteredResource_Succeeds()
    {
        var options = new OidcOptions
        {
            Resources = [new ResourceDefinition(Api)],
            DefaultResourceIndicator = Api,
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    /// <summary>
    /// A relative URI can never match a request either, so it would sit as a value nothing accepts
    /// (RFC 8707 section 2 requires an absolute URI).
    /// </summary>
    [Fact]
    public void Validate_RelativeUri_Fails()
    {
        var options = new OidcOptions
        {
            Resources = [new ResourceDefinition(Api)],
            DefaultResourceIndicator = new Uri("/api", UriKind.Relative),
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("absolute URI"));
    }

    /// <summary>
    /// A default naming a resource this server does not know produces tokens whose audience no resource server
    /// recognises - and the request that named the same identifier explicitly would be refused as
    /// <c>invalid_target</c>, so the two paths would disagree about one value.
    /// </summary>
    [Fact]
    public void Validate_DefaultNotAmongRegisteredResources_Fails()
    {
        var options = new OidcOptions
        {
            Resources = [new ResourceDefinition(new Uri("https://orders.example.com"))],
            DefaultResourceIndicator = Api,
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(OidcOptions.Resources)));
    }

    /// <summary>
    /// The same refusal applies when no resources are registered at all, which is the likeliest way to reach
    /// this: setting the default and forgetting to declare the resource it names.
    /// </summary>
    [Fact]
    public void Validate_DefaultWithNoResourcesRegistered_Fails()
    {
        var options = new OidcOptions { DefaultResourceIndicator = Api };

        Assert.True(_validator.Validate(null, options).Failed);
    }
}
