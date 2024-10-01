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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Fetches pushed authorization request objects identified by a URN (Uniform Resource Name) from a storage system.
/// </summary>
public class PushedRequestFetcher : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PushedRequestFetcher"/> class.
    /// </summary>
    /// <param name="options">
    /// Provides configuration options for the OIDC server, such as whether PAR is required.</param>
    /// <param name="authorizationRequestStorage">
    /// The storage system used to retrieve pushed authorization request objects.</param>
    public PushedRequestFetcher(
        IOptionsSnapshot<OidcOptions> options,
        IAuthorizationRequestStorage authorizationRequestStorage)
    {
        _options = options;
        _authorizationRequestStorage = authorizationRequestStorage;
    }

    private readonly IOptionsSnapshot<OidcOptions> _options;
    private readonly IAuthorizationRequestStorage _authorizationRequestStorage;

    /// <summary>
    /// Asynchronously retrieves the pushed authorization request object associated with the specified URN.
    /// </summary>
    /// <param name="request">
    /// The authorization request containing a URN from which to fetch the stored pushed authorization request object.
    /// </param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains the fetched pushed authorization
    /// request object or an error if not found.
    /// </returns>
    /// <remarks>
    /// This method checks if the provided authorization request contains a URN that references a pushed authorization
    /// request stored in the system. If the URN is valid and corresponds to a stored request, the method retrieves
    /// and returns the request object. If the request object cannot be found or the URN is invalid,
    /// an error is returned.
    /// Additionally, it checks the server configuration to enforce the Pushed Authorization Request (PAR) requirement.
    /// </remarks>
    public async Task<FetchResult> FetchAsync(AuthorizationRequest request)
    {
        // If the request contains a URN, attempt to retrieve the pushed authorization request from storage
        if (request is { RequestUri: { } requestUrn } &&
            requestUrn.OriginalString.StartsWith(RequestUrn.Prefix))
        {
            var requestObject = await _authorizationRequestStorage.TryGetAsync(requestUrn, true);
            return requestObject switch
            {
                null => ErrorFactory.InvalidRequestUri($"Can't find a request by {requestUrn}"),
                _ => requestObject,
            };
        }

        // If PAR is required by server configuration, return an error if no pushed authorization request is provided
        if (_options.Value.RequirePushedAuthorizationRequests)
        {
            return ErrorFactory.InvalidRequestObject("The Pushed Authorization Request (PAR) is required");
        }

        // If no URN is provided and PAR is not required, return the original request
        return request;
    }
}
