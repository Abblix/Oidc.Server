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
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Features.EndpointResolving;

/// <summary>
/// Answers <see cref="IOidcEndpointResolver"/> from the route templates the OIDC controllers carry, resolved
/// through the same tokenized configuration that decided where they were mapped.
/// </summary>
/// <remarks>
/// The Minimal API adapter registers its own implementation of this contract, so host code that needs one of
/// these URLs is written once and survives a change of adapter. The enabled-endpoint set has to be consulted
/// explicitly here: a route template is a compile-time constant on the controller action and resolves whether
/// or not the endpoint is served, where on the Minimal API side a disabled endpoint was never mapped and has
/// nothing to find. Both then answer null for an endpoint the host does not serve.
/// </remarks>
/// <param name="uriResolver">Turns a route template into an absolute URL for the current request.</param>
/// <param name="options">The enabled-endpoint set, so a disabled endpoint resolves to nothing.</param>
public class OidcEndpointResolver(IUriResolver uriResolver, IOptions<OidcOptions> options)
    : IOidcEndpointResolver
{
    /// <inheritdoc />
    public Uri? Resolve(OidcEndpoints endpoint)
    {
        var template = TemplateOf(endpoint);
        if (template == null || !options.Value.EnabledEndpoints.HasFlag(endpoint))
            return null;

        return uriResolver.Content(template);
    }

    /// <summary>
    /// Maps an endpoint to the route template its controller action carries. A flag combination names a set
    /// rather than an endpoint; so does the client configuration endpoint, whose route carries a client
    /// identifier this contract has no way to supply.
    /// </summary>
    private static string? TemplateOf(OidcEndpoints endpoint) => endpoint switch
    {
        OidcEndpoints.Configuration => Path.Configuration,
        OidcEndpoints.Keys => Path.Keys,
        OidcEndpoints.Authorize => Path.Authorize,
        OidcEndpoints.Token => Path.Token,
        OidcEndpoints.UserInfo => Path.UserInfo,
        OidcEndpoints.CheckSession => Path.CheckSession,
        OidcEndpoints.EndSession => Path.EndSession,
        OidcEndpoints.Revocation => Path.Revocation,
        OidcEndpoints.Introspection => Path.Introspection,
        OidcEndpoints.RegisterClient => Path.Register,
        OidcEndpoints.PushedAuthorizationRequest => Path.PushAuthorizationRequest,
        OidcEndpoints.BackChannelAuthentication => Path.BackChannelAuthentication,
        OidcEndpoints.DeviceAuthorization => Path.DeviceAuthorization,
        _ => null,
    };
}
