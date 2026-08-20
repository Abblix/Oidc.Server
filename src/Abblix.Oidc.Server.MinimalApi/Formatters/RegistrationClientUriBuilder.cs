// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Builds the RFC 7592 <c>registration_client_uri</c> - the absolute URL of a client's configuration endpoint - from
/// the current request's base URL and the configured client-management route, replacing the MVC integration's
/// <c>IUriResolver</c>.
/// </summary>
public sealed class RegistrationClientUriBuilder(
    IHttpContextAccessor httpContextAccessor,
    LinkGenerator linkGenerator)
{
    /// <summary>Builds the absolute configuration-endpoint URL for the given client.</summary>
    public Uri Build(string clientId)
    {
        var httpContext = httpContextAccessor.HttpContext.NotNull(nameof(HttpContext));

        // Resolving through the named endpoint keeps the MapOidcEndpoints group prefix (and PathBase) in the URL and
        // lets LinkGenerator URL-encode the client_id into the {clientId} route slot.
        var url = linkGenerator.GetUriByName(httpContext, EndpointNames.RegisterClient, new { clientId })
            ?? throw new InvalidOperationException(
                "The client configuration endpoint could not be resolved. " +
                "Ensure the dynamic client registration endpoint is enabled.");
        return new Uri(url, UriKind.Absolute);
    }
}
