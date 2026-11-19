// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Builds the RFC 7592 <c>registration_client_uri</c> - the absolute URL of a client's configuration endpoint - from
/// the configured client-management route, with its address taken from <see cref="TenantEndpointAddresses.Published"/>
/// for the tenant of the request, so it is on the issuer's authority as discovery's registration endpoint is.
/// </summary>
public sealed class RegistrationClientUriBuilder(
    IHttpContextAccessor httpContextAccessor,
    LinkGenerator linkGenerator)
{
    /// <summary>Builds the absolute configuration-endpoint URL for the given client.</summary>
    public Uri Build(string clientId)
    {
        var httpContext = httpContextAccessor.HttpContext.NotNull(nameof(HttpContext));

        // Resolving through the named endpoint keeps the mapping prefix (and PathBase) in the URL and
        // lets LinkGenerator URL-encode the client_id into the {clientId} route slot.
        var url = linkGenerator.GetUriByRouteValues(httpContext, EndpointNames.RegisterClient, new { clientId })
            ?? throw new InvalidOperationException(
                "The client configuration endpoint could not be resolved. " +
                "Ensure the dynamic client registration endpoint is enabled.");
        return httpContext.RequestServices.GetRequiredService<ITenantAccessor>().CurrentTenant()
            .Published(new Uri(url, UriKind.Absolute));
    }
}
