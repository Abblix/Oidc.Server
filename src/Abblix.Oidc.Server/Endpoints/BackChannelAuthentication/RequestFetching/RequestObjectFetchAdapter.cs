// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
        => requestObjectFetcher.FetchAsync(
            request, request.Request, client => client.BackChannelAuthenticationRequestSigningAlg);
}
