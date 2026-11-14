// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.PushedAuthorization;

/// <summary>
/// Enforces single-use of a pushed authorization <c>request_uri</c> (RFC 9126 section 7.3) by decorating the
/// authorization request processor. Once processing yields a terminal success - an authorization code or
/// token has been minted - the <c>request_uri</c> is removed from storage so it cannot be replayed within
/// its remaining time-to-live. Interactive continuations (login, consent, account selection) leave it in
/// place so the user agent can re-enter the authorization endpoint with the same <c>request_uri</c>, except
/// the one a request came back with from the login or account-creation page, which it is done with. A success
/// also ends the flow, under the <c>request_uri</c> it began with, so the other pages of the flow are refused while
/// they could still be presented, and a page whose flow another page ended first is answered with an error.
/// </summary>
/// <param name="inner">The authorization request processor being decorated.</param>
/// <param name="authorizationRequestStorage">The storage backing pushed authorization requests, from which
/// the consumed <c>request_uri</c> is removed on a terminal success.</param>
/// <param name="consumedRequestUris">Records the flows that ended, so the other pages of one are refused.</param>
/// <param name="options">How long a page of a flow can be presented.</param>
/// <param name="timeProvider">Dates the end of a flow.</param>
public class PushedAuthorizationRequestProcessorDecorator(
    IAuthorizationRequestProcessor inner,
    IAuthorizationRequestStorage authorizationRequestStorage,
    IConsumedRequestUriRegistry consumedRequestUris,
    IOptions<OidcOptions> options,
    TimeProvider timeProvider) : IAuthorizationRequestProcessor
{
    /// <summary>
    /// Delegates to the wrapped processor and consumes the <c>request_uri</c> values the request is done with: on a
    /// successful authentication the one it came by and the one it was first fetched under, and on any answer the
    /// one it came back with from a page its prompt sent the end user to.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="request">The validated authorization request to process.</param>
    /// <returns>The inner processor's <see cref="AuthorizationResponse"/>, or an error when it issued a code or token
    /// for a flow another page had already ended.</returns>
    public async Task<AuthorizationResponse> ProcessAsync(TenantDefinition tenant, ValidAuthorizationRequest request)
    {
        var response = await EndFlowAsync(tenant, request, await inner.ProcessAsync(tenant, request));

        // PushedRequestFetcher carries the URN forward onto the resolved request (surfaced as
        // ValidAuthorizationRequest.RequestUri) and deliberately does not consume on fetch, so multi-step UI re-reads
        // the same URN until a code or token is issued here. A request coming back from a page its prompt sent the
        // end user to is done with the request_uri it came back with whatever it is answered: a next page
        // gets a request_uri of its own, and this one would let the end user's browser come back past signing in
        // until it expires.
        if ((response is SuccessfullyAuthenticated || request.Model.Prompted is { Count: > 0 }) &&
            request.RequestUri is { } requestUri &&
            requestUri.OriginalString.StartsWith(RequestUrn.Prefix))
        {
            await authorizationRequestStorage.TryGetAsync(tenant, requestUri, shouldRemove: true);
        }

        // The URN the request was first fetched under - usually the one the client pushed - outlives the pages the
        // request went through, and is done with once a code or token is issued. So are the pages it led to that the
        // code did not come by, as a refresh of one made: each carries this URN, and the record of the ended flow
        // refuses them above while a page can still be presented.
        if (response is SuccessfullyAuthenticated &&
            request.Model.OriginRequestUri is { } originRequestUri &&
            originRequestUri != request.RequestUri)
        {
            await authorizationRequestStorage.TryGetAsync(tenant, originRequestUri, shouldRemove: true);
        }

        return response;
    }

    /// <summary>
    /// Ends the flow <paramref name="request"/> belongs to when <paramref name="response"/> issued a code or token,
    /// answering with an error instead when the flow had ended already.
    /// </summary>
    /// <remarks>
    /// The flow ends with the first code or token, so of two of its pages reaching one together only the first is
    /// answered with what was issued. What the other was issued before this, a code and in a hybrid flow its
    /// tokens, never leaves the server.
    /// </remarks>
    private async Task<AuthorizationResponse> EndFlowAsync(
        TenantDefinition tenant,
        ValidAuthorizationRequest request,
        AuthorizationResponse response)
    {
        if (response is not SuccessfullyAuthenticated ||
            request.Model.OriginRequestUri is not { } flowRequestUri ||
            await consumedRequestUris.TryConsumeAsync(
                tenant,
                flowRequestUri,
                timeProvider.GetUtcNow() + options.Value.AuthenticationRequestExpiresIn))
        {
            return response;
        }

        return new AuthorizationError(
            request.Model,
            ErrorCodes.InvalidRequestUri,
            $"The request by {flowRequestUri} has already been used",
            request.ResponseMode,
            request.Model.RedirectUri);
    }
}
