// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
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
/// <param name="jwtAlgorithms">The signing algorithms the server advertises for a backchannel authentication
/// request, which are the asymmetric ones.</param>
public class RequestObjectFetchAdapter(
    IRequestObjectFetcher requestObjectFetcher,
    IJwtAlgorithmsProvider jwtAlgorithms) : IBackChannelAuthenticationRequestFetcher
{
    /// <summary>
    /// Delegates to the underlying request-object fetcher, passing <c>request.Request</c> as the JWT to
    /// be validated and merged into the outer model.
    /// </summary>
    public async Task<Result<BackChannelAuthenticationRequest, OidcError>> FetchAsync(
        TenantDefinition tenant,
        ClientInfo client,
        BackChannelAuthenticationRequest request)
    {
        // RFC 9101 section 4 forbids request and request_uri inside an authorization request's object; this endpoint
        // forbids no member of its own
        var result = await requestObjectFetcher.FetchAsync(tenant,
            client, request, request.Request, signer => signer.BackChannelAuthenticationRequestSigningAlg, [],
            token => SignedAuthenticationRequestRules.WhyRefused(
                token, tenant.Issuer, jwtAlgorithms.BackChannelAuthenticationRequestSigningAlgValuesSupported));

        // CIBA Core 1.0 section 13: the error is "A single ASCII error code from one present in the list below", which
        // does not hold invalid_request_object, and lists invalid_request for a request that "includes an invalid
        // parameter value ... or is otherwise malformed", which a request parameter carrying an unacceptable signed
        // authentication request is
        return result.MapFailure(error => new OidcError(ErrorCodes.InvalidRequest, error.ErrorDescription));
    }
}
