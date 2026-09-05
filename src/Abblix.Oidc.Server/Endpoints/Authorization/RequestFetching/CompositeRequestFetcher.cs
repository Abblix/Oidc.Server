// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// A composite fetcher that combines multiple <see cref="IAuthorizationRequestFetcher"/> instances.
/// It iterates through each fetcher to process an authorization request, allowing for a flexible and
/// extensible mechanism to fetch and validate authorization requests from different sources or formats.
/// </summary>
/// <param name="fetchers">An array of <see cref="IAuthorizationRequestFetcher"/> instances that will be used
/// to fetch and validate the authorization request.</param>
public class CompositeRequestFetcher(IAuthorizationRequestFetcher[] fetchers) : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Iterates through the configured fetchers to process the authorization request. Each fetcher in the array
    /// has the opportunity to handle the request. If a fetcher returns a fault, the process stops and
    /// the fault is returned. If all fetchers succeed, the method returns the final successful result.
    /// </summary>
    /// <param name="request">The authorization request to be processed.</param>
    /// <returns>A <see cref="Result{TSuccess,TFailure}"/> of <see cref="AuthorizationRequest"/> on success or
    /// <see cref="AuthorizationRequestValidationError"/> on failure, representing the outcome of the fetching
    /// process. If a fetcher returns a fault, that fault is propagated; otherwise the final successful request is
    /// returned.</returns>
    public async Task<Result<AuthorizationRequest, AuthorizationRequestValidationError>> FetchAsync(AuthorizationRequest request)
    {
        foreach (var fetcher in fetchers)
        {
            var result = await fetcher.FetchAsync(request);

            if (result.TryGetFailure(out var error))
                return error;

            request = result.GetSuccess();
        }

        return request;
    }
}
