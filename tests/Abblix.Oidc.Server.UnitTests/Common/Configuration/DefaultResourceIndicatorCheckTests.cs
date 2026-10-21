// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="DefaultResourceIndicatorCheck"/> refuses a tenant's default that would put an unusable
/// value in every access token's <c>aud</c> claim, rather than letting it surface later as a resource server
/// rejecting tokens it cannot recognize.
/// </summary>
public class DefaultResourceIndicatorCheckTests
{
    private static readonly Uri Api = new("https://api.example.com");

    private readonly DefaultResourceIndicatorCheck _check = new();

    private List<TenantRefusal> RefusalsOf(Uri? defaultResource, ResourceDefinition[]? resources)
        => _check.Check(
            [
                new TenantDefinition
                {
                    Id = "acme",
                    Issuer = new Uri("https://auth.example.com"),
                    Resources = resources,
                    DefaultResourceIndicator = defaultResource,
                },
            ],
            new OidcOptions()).ToList();

    /// <summary>
    /// A tenant states no default unless told to, so a stock definition passes and the audience keeps falling
    /// back to the issuer.
    /// </summary>
    [Fact]
    public void Check_NoDefaultStated_Passes()
    {
        var tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com") };

        Assert.Null(tenant.DefaultResourceIndicator);
        Assert.Empty(_check.Check([tenant], new OidcOptions()));
    }

    /// <summary>
    /// A default naming a registered resource is exactly the configuration this setting exists for.
    /// </summary>
    [Fact]
    public void Check_DefaultNamesARegisteredResource_Passes()
    {
        Assert.Empty(RefusalsOf(Api, [new ResourceDefinition(Api)]));
    }

    /// <summary>
    /// A relative URI can never match a request either, so it would sit as a value nothing accepts
    /// (RFC 8707 section 2 requires an absolute URI).
    /// </summary>
    [Fact]
    public void Check_RelativeUri_Refuses()
    {
        var refusals = RefusalsOf(new Uri("/api", UriKind.Relative), [new ResourceDefinition(Api)]);

        var refusal = Assert.Single(refusals);
        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
        Assert.Contains("absolute URI", refusal.Message);
    }

    /// <summary>
    /// A default naming a resource this tenant does not know produces tokens whose audience no resource server
    /// recognizes - and the request that named the same identifier explicitly would be refused as
    /// <c>invalid_target</c>, so the two paths would disagree about one value.
    /// </summary>
    [Fact]
    public void Check_DefaultNotAmongRegisteredResources_Refuses()
    {
        var refusals = RefusalsOf(Api, [new ResourceDefinition(new Uri("https://orders.example.com"))]);

        Assert.Contains(refusals, refusal => refusal.Message.Contains(nameof(TenantDefinition.Resources)));
    }

    /// <summary>
    /// The same refusal applies when no resources are registered at all, which is the likeliest way to reach
    /// this: setting the default and forgetting to declare the resource it names.
    /// </summary>
    [Fact]
    public void Check_DefaultWithNoResourcesRegistered_Refuses()
    {
        Assert.NotEmpty(RefusalsOf(Api, null));
    }
}
