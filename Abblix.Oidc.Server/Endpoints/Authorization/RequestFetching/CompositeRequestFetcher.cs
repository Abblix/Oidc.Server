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

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// A composite fetcher that combines multiple <see cref="IAuthorizationRequestFetcher"/> instances.
/// It iterates through each fetcher to process an authorization request, allowing for a flexible and
/// extensible mechanism to fetch and validate authorization requests from different sources or formats.
/// </summary>
public class CompositeRequestFetcher : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CompositeRequestFetcher"/> class with an array of fetchers.
    /// </summary>
    /// <param name="fetchers">An array of <see cref="IAuthorizationRequestFetcher"/> instances that will be used
    /// to fetch and validate the authorization request.</param>
    public CompositeRequestFetcher(IAuthorizationRequestFetcher[] fetchers)
    {
        _fetchers = fetchers;
    }

    private readonly IAuthorizationRequestFetcher[] _fetchers;

    /// <summary>
    /// Iterates through the configured fetchers to process the authorization request. Each fetcher in the array
    /// has the opportunity to handle the request. If a fetcher returns a fault, the process stops and
    /// the fault is returned. If all fetchers succeed, the method returns the final successful result.
    /// </summary>
    /// <param name="request">The authorization request to be processed.</param>
    /// <returns>A <see cref="FetchResult"/> that represents the outcome of the fetching process. It could be a success,
    /// fault, or an unexpected type error if the result is not handled correctly.</returns>
    public async Task<FetchResult> FetchAsync(AuthorizationRequest request)
    {
        foreach (var fetcher in _fetchers)
        {
            var result = await fetcher.FetchAsync(request);
            switch (result)
            {
                case FetchResult.Success success:
                    request = success.Request;
                    continue;

                case FetchResult.Fault fault:
                    return fault;

                default:
                    throw new UnexpectedTypeException(nameof(result), result.GetType());
            }
        }

        return request;
    }
}
