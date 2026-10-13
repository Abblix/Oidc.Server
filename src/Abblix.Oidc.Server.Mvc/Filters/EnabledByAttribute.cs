// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Makes a controller or action match a request only while its endpoint is enabled in
/// <see cref="OidcOptions.EnabledEndpoints"/>, so a disabled endpoint answers 404 to a request it would otherwise
/// serve.
/// </summary>
/// <remarks>
/// An action constraint on the controller or action it marks, so it is consulted for this library's endpoints and
/// no others; nothing is registered in the host's MVC options to apply it. Routing checks the method and the media
/// type before any action constraint, so a request with another method or media type still gets 405 or 415.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class EnabledByAttribute : Attribute, IActionConstraint
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EnabledByAttribute"/> class.
    /// </summary>
    /// <param name="endpoint">The OIDC endpoint configuration flag that controls whether this controller/action is enabled.</param>
    public EnabledByAttribute(OidcEndpoints endpoint)
    {
        Endpoint = endpoint;
    }

    /// <summary>
    /// The OIDC endpoint configuration flag.
    /// </summary>
    public OidcEndpoints Endpoint { get; }

    /// <inheritdoc />
    public int Order => 0;

    /// <inheritdoc />
    public bool Accept(ActionConstraintContext context)
        => context.RouteContext.HttpContext.RequestServices.GetRequiredService<IOptions<OidcOptions>>()
            .Value.EnabledEndpoints.HasFlag(Endpoint);
}
