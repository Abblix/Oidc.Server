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
/// <param name="authorizationRequestUriGenerator">The generator used to create unique URIs for each authorization
/// request.</param>
/// <param name="storage">The persistent storage mechanism where authorization requests are stored.</param>
public class AuthorizationRequestStorage(
   IAuthorizationRequestUriGenerator authorizationRequestUriGenerator,
   IEntityStorage storage) : IAuthorizationRequestStorage
{
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
        var requestUri = authorizationRequestUriGenerator.GenerateRequestUri();

        await storage.SetAsync(
            ToKeyString(requestUri),
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
        => storage.GetAsync<AuthorizationRequest>(ToKeyString(requestUri), shouldRemove);

    private static string ToKeyString(Uri requestUri) => requestUri.OriginalString;
}
