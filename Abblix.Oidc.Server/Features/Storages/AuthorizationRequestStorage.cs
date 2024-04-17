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

using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides storage and retrieval services for OAuth 2.0 authorization requests using a distributed cache.
/// This class is designed to handle the storage of <see cref="AuthorizationRequest"/> objects and facilitate
/// their retrieval using unique request URIs, supporting scenarios such as the OAuth 2.0 Pushed Authorization Requests
/// (PAR).
/// </summary>
public class AuthorizationRequestStorage : IAuthorizationRequestStorage
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationRequestStorage"/> class,
    /// setting up necessary dependencies for storing and retrieving authorization requests.
    /// </summary>
    /// <param name="authorizationRequestUriGenerator">The generator used to create unique URIs for each authorization
    /// request.</param>
    /// <param name="storage">The persistent storage mechanism where authorization requests are stored.</param>
    public AuthorizationRequestStorage(
       IAuthorizationRequestUriGenerator authorizationRequestUriGenerator,
       IEntityStorage storage)
    {
        _authorizationRequestUriGenerator = authorizationRequestUriGenerator;
        _storage = storage;
    }

    private readonly IAuthorizationRequestUriGenerator _authorizationRequestUriGenerator;
    private readonly IEntityStorage _storage;

    /// <summary>
    /// Stores an authorization request in the distributed cache with a generated URI and a specified expiration time.
    /// </summary>
    /// <param name="request">The authorization request to store.</param>
    /// <param name="expiresIn">The duration after which the stored request will expire and no longer be valid. This
    /// duration is typically dictated by the OAuth 2.0 server's configuration and the nature of the client's request.
    /// </param>
    /// <returns>A task that resolves to a <see cref="PushedAuthorizationResponse"/>, which includes the stored request
    /// and its unique URI. This response is used to facilitate subsequent authorization processes that may require
    /// accessing the request via its URI.</returns>
    public async Task<PushedAuthorizationResponse> StoreAsync(AuthorizationRequest request, TimeSpan expiresIn)
    {
        var requestUri = _authorizationRequestUriGenerator.GenerateRequestUri();

        await _storage.SetAsync(
            requestUri.OriginalString,
            request,
            new StorageOptions { AbsoluteExpirationRelativeToNow = expiresIn });

        return new PushedAuthorizationResponse(request, requestUri, expiresIn);
    }

    /// <summary>
    /// Attempts to retrieve an authorization request from the distributed cache using its unique URI.
    /// Optionally removes the request from the cache depending on the <paramref name="shouldRemove"/> parameter.
    /// </summary>
    /// <param name="requestUri">The URI associated with the authorization request.</param>
    /// <param name="shouldRemove">Whether to remove the request from the cache after retrieving it. This is typically
    /// true for operations where the request is intended for single retrieval, such as after redirecting a client
    /// to an authorization endpoint.</param>
    /// <returns>A task that resolves to the retrieved <see cref="AuthorizationRequest"/> if found; otherwise, null.
    /// If the request is not found, it may have expired or been removed from the cache previously.</returns>
    public Task<AuthorizationRequest?> TryGetAsync(Uri requestUri, bool shouldRemove)
        => _storage.GetAsync<AuthorizationRequest>(requestUri.OriginalString, shouldRemove);
}
