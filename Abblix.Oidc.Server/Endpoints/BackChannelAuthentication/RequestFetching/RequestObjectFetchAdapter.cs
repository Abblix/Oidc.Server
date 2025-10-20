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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;

/// <summary>
/// Adapter class that implements <see cref="IBackChannelAuthenticationRequestFetcher"/> to delegate the
/// fetching and processing of request objects to an instance of <see cref="IRequestObjectFetcher"/>.
/// </summary>
/// <param name="requestObjectFetcher">The request object fetcher responsible for fetching and processing
/// the JWT request object.</param>
public class RequestObjectFetchAdapter(IRequestObjectFetcher requestObjectFetcher) : IBackChannelAuthenticationRequestFetcher
{
    /// <summary>
    /// Fetches and processes the backchannel authentication request by delegating to the request object fetcher.
    /// </summary>
    /// <param name="request">The backchannel authentication request to be processed.</param>
    /// <returns>
    /// A task that returns a BackChannelAuthenticationRequest or error.
    /// The task result contains a <see cref="Result{BackChannelAuthenticationRequest, RequestError}"/>
    /// that either represents a successfully processed request or an error indicating issues with the JWT validation.
    /// </returns>
    public Task<Result<BackChannelAuthenticationRequest, RequestError>> FetchAsync(BackChannelAuthenticationRequest request)
        => requestObjectFetcher.FetchAsync(request, request.Request);
}
