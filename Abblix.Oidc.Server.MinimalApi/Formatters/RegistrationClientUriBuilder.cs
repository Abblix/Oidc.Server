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

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Builds the RFC 7592 <c>registration_client_uri</c> — the absolute URL of a client's configuration endpoint — from
/// the current request's base URL and the configured client-management route, replacing the MVC integration's
/// <c>IUriResolver</c>.
/// </summary>
public sealed class RegistrationClientUriBuilder(
    IHttpContextAccessor httpContextAccessor,
    IOptions<OidcRouteOptions> routeOptions)
{
    /// <summary>Builds the absolute configuration-endpoint URL for the given client.</summary>
    public Uri Build(string clientId)
    {
        var request = httpContextAccessor.HttpContext.NotNull(nameof(HttpContext)).Request;
        var path = routeOptions.Value.RegisterClient.Replace("{clientId}", Uri.EscapeDataString(clientId));
        return new Uri(request.GetAppUrl() + path, UriKind.Absolute);
    }
}
