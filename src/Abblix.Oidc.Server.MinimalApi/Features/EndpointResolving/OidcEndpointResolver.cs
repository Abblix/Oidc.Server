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

        var endpointName = NameOf(endpoint);
        if (endpointName == null)
            return null;

        var url = linkGenerator.GetUriByName(httpContext, endpointName, values: null);
        return url == null ? null : new Uri(url, UriKind.Absolute);
    }

    /// <summary>
    /// Maps an endpoint to the name it was mapped under. A flag combination names a set rather than an
    /// endpoint and has no single name; so does the client configuration endpoint, whose route carries a
    /// client identifier this contract has no way to supply.
    /// </summary>
    private static string? NameOf(OidcEndpoints endpoint) => endpoint switch
    {
        OidcEndpoints.Configuration => EndpointNames.Configuration,
        OidcEndpoints.Keys => EndpointNames.Keys,
        OidcEndpoints.Authorize => EndpointNames.Authorize,
        OidcEndpoints.Token => EndpointNames.Token,
        OidcEndpoints.UserInfo => EndpointNames.UserInfo,
        OidcEndpoints.CheckSession => EndpointNames.CheckSession,
        OidcEndpoints.EndSession => EndpointNames.EndSession,
        OidcEndpoints.Revocation => EndpointNames.Revocation,
        OidcEndpoints.Introspection => EndpointNames.Introspection,
        OidcEndpoints.RegisterClient => EndpointNames.Register,
        OidcEndpoints.PushedAuthorizationRequest => EndpointNames.PushedAuthorizationRequest,
        OidcEndpoints.BackChannelAuthentication => EndpointNames.BackChannelAuthentication,
        OidcEndpoints.DeviceAuthorization => EndpointNames.DeviceAuthorization,
        _ => null,
    };
}
