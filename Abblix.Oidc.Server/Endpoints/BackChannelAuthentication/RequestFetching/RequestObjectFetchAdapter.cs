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
/// Adapts the generic <see cref="IRequestObjectFetcher"/> (signed-JWT Request Object handling) to the
/// CIBA-specific <see cref="IBackChannelAuthenticationRequestFetcher"/> contract, passing the request's
/// <c>request</c> parameter through unchanged for JWT validation and parameter merging.
/// </summary>
/// <param name="requestObjectFetcher">Validates the JWT Request Object and merges its claims into the
/// outer request model.</param>
public class RequestObjectFetchAdapter(IRequestObjectFetcher requestObjectFetcher) : IBackChannelAuthenticationRequestFetcher
{
    /// <summary>
    /// Delegates to the underlying request-object fetcher, passing <c>request.Request</c> as the JWT to
    /// be validated and merged into the outer model.
    /// </summary>
    public Task<Result<BackChannelAuthenticationRequest, OidcError>> FetchAsync(BackChannelAuthenticationRequest request)
        => requestObjectFetcher.FetchAsync(request, request.Request);
}
