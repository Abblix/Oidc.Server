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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization;

/// <summary>
/// Processes pushed authorization requests by storing them and generating a response
/// that includes the request URI and expiration information.
/// </summary>
public class PushedAuthorizationRequestProcessor : IPushedAuthorizationRequestProcessor
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PushedAuthorizationRequestProcessor"/> class
    /// with a specified authorization request storage.
    /// </summary>
    /// <param name="storage">The storage used to keep the authorization requests.</param>
    /// <param name="options"></param>
    public PushedAuthorizationRequestProcessor(
        IAuthorizationRequestStorage storage,
        IOptionsSnapshot<OidcOptions> options)
    {
        _storage = storage;
        _options = options;
    }

    private readonly IAuthorizationRequestStorage _storage;
    private readonly IOptionsSnapshot<OidcOptions> _options;

    /// <summary>
    /// Asynchronously processes a valid pushed authorization request by storing it and returning a response
    /// that includes the request URI for later retrieval and the duration for which the request is valid.
    /// </summary>
    /// <param name="request">The valid pushed authorization request to process.</param>
    /// <returns>A task that resolves to an <see cref="AuthorizationResponse"/> containing
    /// the request URI and expiration information.</returns>
    public async Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request)
        => await _storage.StoreAsync(request.Model,_options.Value.PushedAuthorizationRequestExpiresIn);
}
