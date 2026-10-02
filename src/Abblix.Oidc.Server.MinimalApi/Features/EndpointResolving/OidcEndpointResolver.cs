// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Frozen;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.MinimalApi.Features.EndpointResolving;

/// <summary>
/// Answers <see cref="IOidcEndpointResolver"/> from the endpoints
/// <see cref="EndpointRouteBuilderExtensions.MapOidcEndpoints(IEndpointRouteBuilder,string)"/> actually mapped,
/// found by the stable name each one carries.
/// </summary>
/// <remarks>
/// Going through <see cref="LinkGenerator"/> rather than reading <see cref="OidcRouteOptions"/> is what makes
/// the answer the truth rather than a reconstruction of it: the generator sees the route as mapped, so a group
/// prefix, the request's scheme and host, and the application's path base are all already in it. A disabled
/// endpoint was never mapped and therefore has no name to find, which is the same null this contract returns
/// for it.
/// </remarks>
public class OidcEndpointResolver(
    IHttpContextAccessor httpContextAccessor,
    LinkGenerator linkGenerator) : IOidcEndpointResolver
{
    /// <inheritdoc />
    public Uri? Resolve(OidcEndpoints endpoint)
    {
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext == null)
            return null;

        if (!NamesByEndpoint.TryGetValue(endpoint, out var endpointName))
            return null;

        var url = linkGenerator.GetUriByName(httpContext, endpointName, values: null);
        return url == null ? null : new Uri(url, UriKind.Absolute);
    }

    /// <summary>
    /// The name each endpoint was mapped under. A flag combination names a set rather than an endpoint and has no
    /// single name, so it has no entry; the client configuration endpoint is answered by the registration endpoint,
    /// since its own route carries a client identifier this contract has no way to supply.
    /// </summary>
    internal static readonly FrozenDictionary<OidcEndpoints, string> NamesByEndpoint =
        new Dictionary<OidcEndpoints, string>
        {
            [OidcEndpoints.Configuration] = EndpointNames.Configuration,
            [OidcEndpoints.Keys] = EndpointNames.Keys,
            [OidcEndpoints.Authorize] = EndpointNames.Authorize,
            [OidcEndpoints.Token] = EndpointNames.Token,
            [OidcEndpoints.UserInfo] = EndpointNames.UserInfo,
            [OidcEndpoints.CheckSession] = EndpointNames.CheckSession,
            [OidcEndpoints.EndSession] = EndpointNames.EndSession,
            [OidcEndpoints.Revocation] = EndpointNames.Revocation,
            [OidcEndpoints.Introspection] = EndpointNames.Introspection,
            [OidcEndpoints.RegisterClient] = EndpointNames.Register,
            [OidcEndpoints.PushedAuthorizationRequest] = EndpointNames.PushedAuthorizationRequest,
            [OidcEndpoints.BackChannelAuthentication] = EndpointNames.BackChannelAuthentication,
            [OidcEndpoints.DeviceAuthorization] = EndpointNames.DeviceAuthorization,
        }.ToFrozenDictionary();
}
