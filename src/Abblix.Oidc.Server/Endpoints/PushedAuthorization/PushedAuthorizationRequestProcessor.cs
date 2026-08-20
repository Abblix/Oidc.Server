// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization;

/// <summary>
/// Processes pushed authorization requests by storing them and generating a response
/// that includes the request URI and expiration information.
/// </summary>
public class PushedAuthorizationRequestProcessor(
    IAuthorizationRequestStorage storage,
    IOptionsSnapshot<OidcOptions> options) : IPushedAuthorizationRequestProcessor
{
    /// <summary>
    /// Asynchronously processes a valid pushed authorization request by storing it and returning a response
    /// that includes the request URI for later retrieval and the duration for which the request is valid.
    /// </summary>
    /// <param name="request">The valid pushed authorization request to process.</param>
    /// <returns>A task that resolves to an <see cref="AuthorizationResponse"/> containing
    /// the request URI and expiration information.</returns>
    public async Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request)
        => await storage.StoreAsync(request.Model, options.Value.PushedAuthorizationRequestExpiresIn);
}
