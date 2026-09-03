// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;

/// <summary>
/// Default <see cref="IBackChannelAuthenticationHandler"/> implementation that drives the CIBA endpoint
/// pipeline as fetch (request object resolution) -&gt; validation -&gt; processing, short-circuiting on the
/// first error so that subsequent stages never see invalid input.
/// </summary>
/// <param name="fetcher">Resolves the effective request, in particular substituting parameters carried in
/// a signed Request Object per CIBA Core 1.0 section 7.1.1.</param>
/// <param name="validator">Validates the resolved request against client metadata and protocol rules.</param>
/// <param name="processor">Persists the authentication request and produces the
/// <c>auth_req_id</c>/<c>expires_in</c>/<c>interval</c> response.</param>
public class BackChannelAuthenticationHandler(
    IBackChannelAuthenticationRequestFetcher fetcher,
    IBackChannelAuthenticationRequestValidator validator,
    IBackChannelAuthenticationRequestProcessor processor) : IBackChannelAuthenticationHandler
{
    /// <summary>
    /// Runs the fetch-validate-process pipeline for a CIBA request and returns the resulting success
    /// payload or an <see cref="OidcError"/> from the first failing stage.
    /// </summary>
    /// <param name="request">The parsed CIBA authentication request as received on the wire.</param>
    /// <param name="clientRequest">Transport metadata used for client authentication and validation.</param>
    public async Task<Result<BackChannelAuthenticationSuccess, OidcError>> HandleAsync(
        BackChannelAuthenticationRequest request,
        ClientRequest clientRequest)
    {
        var fetchResult = await fetcher.FetchAsync(request);
        if (fetchResult.TryGetSuccess(out var fetchedRequest))
        {
            request = fetchedRequest;
        }
        else if (fetchResult.TryGetFailure(out var error))
        {
            return new OidcError(error.Error, error.ErrorDescription);
        }

        var validationResult = await validator.ValidateAsync(request, clientRequest);
        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
