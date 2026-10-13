// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Mvc.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Filters;

/// <summary>
/// A controller or action marked <see cref="EnabledByAttribute"/> matches a request only while its endpoint is
/// enabled, judged against the options the request's services hold.
/// </summary>
public class EnabledByAttributeTests
{
    [Theory]
    [InlineData(OidcEndpoints.All, true)]
    [InlineData(OidcEndpoints.All & ~OidcEndpoints.RegisterClient, false)]
    [InlineData(OidcEndpoints.RegisterClient, true)]
    public void AnEndpointMatchesOnlyWhileEnabled(OidcEndpoints enabled, bool accepted)
    {
        var services = new ServiceCollection()
            .Configure<OidcOptions>(options => options.EnabledEndpoints = enabled)
            .BuildServiceProvider();

        var context = new ActionConstraintContext
        {
            RouteContext = new RouteContext(new DefaultHttpContext { RequestServices = services }),
            Candidates = [],
            CurrentCandidate = new ActionSelectorCandidate(new ActionDescriptor(), []),
        };

        Assert.Equal(accepted, new EnabledByAttribute(OidcEndpoints.RegisterClient).Accept(context));
    }
}
