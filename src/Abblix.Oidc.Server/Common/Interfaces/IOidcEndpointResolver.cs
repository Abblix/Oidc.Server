// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Resolves the absolute URL an OIDC endpoint is served at in the running application.
/// </summary>
/// <remarks>
/// Both transport adapters register an implementation, so host code that needs one of these URLs - an external
/// identity provider's callback pointing back at the authorization endpoint, say - is written once and keeps
/// working when the host swaps one adapter for the other. Each adapter answers from what it actually mapped:
/// MVC from its controller routes, Minimal API from its named endpoints, so a route override or a group prefix
/// is reflected without the caller knowing either exists.
/// </remarks>
public interface IOidcEndpointResolver
{
    /// <summary>
    /// Returns the absolute URL of <paramref name="endpoint"/> for the current request.
    /// </summary>
    /// <param name="endpoint">
    /// The endpoint to resolve. Exactly one flag, never a combination: <see cref="OidcEndpoints.All"/> and
    /// <see cref="OidcEndpoints.Base"/> name a set rather than an endpoint and resolve to nothing.
    /// </param>
    /// <returns>
    /// The endpoint's absolute URL, or <c>null</c> when it is not mapped - because the endpoint is disabled in
    /// <see cref="OidcOptions.EnabledEndpoints"/>, or because its route takes parameters this contract cannot
    /// supply, which today is the per-client configuration endpoint of
    /// <see cref="OidcEndpoints.RegisterClient"/>.
    /// </returns>
    Uri? Resolve(OidcEndpoints endpoint);
}
