// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Features.PushedAuthorization;

/// <summary>
/// Enforces single-use of a pushed authorization <c>request_uri</c> (RFC 9126 section 7.3) by decorating the
/// authorization request processor. Once processing yields a terminal success - an authorization code or
/// token has been minted - the <c>request_uri</c> is removed from storage so it cannot be replayed within
/// its remaining time-to-live. Interactive continuations (login, consent, account selection) leave it in
/// place so the user agent can re-enter the authorization endpoint with the same <c>request_uri</c>.
/// </summary>
/// <param name="inner">The authorization request processor being decorated.</param>
/// <param name="authorizationRequestStorage">The storage backing pushed authorization requests, from which
/// the consumed <c>request_uri</c> is removed on a terminal success.</param>
public class PushedAuthorizationRequestProcessorDecorator(
    IAuthorizationRequestProcessor inner,
    IAuthorizationRequestStorage authorizationRequestStorage) : IAuthorizationRequestProcessor
{
    /// <summary>
    /// Delegates to the wrapped processor and, when the outcome is a successful authentication originating
    /// from a pushed request, consumes the originating <c>request_uri</c> to enforce single use.
    /// </summary>
    /// <param name="request">The validated authorization request to process.</param>
    /// <returns>The inner processor's <see cref="AuthorizationResponse"/>, unchanged.</returns>
    public async Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request)
    {
        var response = await inner.ProcessAsync(request);

        // Consume the request_uri only on a terminal success: PushedRequestFetcher carries the URN forward
        // onto the resolved request (surfaced as ValidAuthorizationRequest.RequestUri) and deliberately does
        // not consume on fetch, so multi-step UI re-reads the same URN until a code or token is issued here.
        if (response is SuccessfullyAuthenticated &&
            request.RequestUri is { } requestUri &&
            requestUri.OriginalString.StartsWith(RequestUrn.Prefix))
        {
            await authorizationRequestStorage.TryGetAsync(requestUri, shouldRemove: true);
        }

        return response;
    }
}
