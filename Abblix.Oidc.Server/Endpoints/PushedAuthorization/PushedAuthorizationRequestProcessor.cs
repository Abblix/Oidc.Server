// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
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
