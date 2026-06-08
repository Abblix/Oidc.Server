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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Features.PushedAuthorization;

/// <summary>
/// Enforces single-use of a pushed authorization <c>request_uri</c> (RFC 9126 §6) by decorating the
/// authorization request processor. Once processing yields a terminal success — an authorization code or
/// token has been minted — the <c>request_uri</c> is removed from storage so it cannot be replayed within
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
