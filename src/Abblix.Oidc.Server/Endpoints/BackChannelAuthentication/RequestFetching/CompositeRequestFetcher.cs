// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;

/// <summary>
/// Chains multiple <see cref="IBackChannelAuthenticationRequestFetcher"/> instances, feeding each one's
/// output into the next so that distinct sources or formats (for example, the signed Request Object) can
/// progressively enrich the request. Returns the first failure without invoking the remaining fetchers.
/// </summary>
public class CompositeRequestFetcher(IBackChannelAuthenticationRequestFetcher[] fetchers) : IBackChannelAuthenticationRequestFetcher
{
    /// <summary>
    /// Iterates through the configured fetchers to process the backchannel authentication request.
    /// Each fetcher in the array has the opportunity to handle the request. If a fetcher returns a fault,
    /// the process stops and the fault is returned.
    /// If all fetchers succeed, the method returns the final successful result.
    /// </summary>
    /// <param name="request">The backchannel authentication request to be processed.</param>
    /// <returns>A <see cref="Result{BackChannelAuthenticationRequest, AuthError}"/> that represents the outcome of the fetching process.</returns>
    public async Task<Result<BackChannelAuthenticationRequest, OidcError>> FetchAsync(BackChannelAuthenticationRequest request)
    {
        foreach (var fetcher in fetchers)
        {
            var result = await fetcher.FetchAsync(request);
            if (result.TryGetFailure(out var error))
            {
                return error;
            }
            request = result.GetSuccess();
        }

        return request;
    }
}
