// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Handles authorization requests by fetching, validating, processing and encoding the response.
/// </summary>
/// <param name="fetcher">Resolves the effective authorization request, including dereferencing pushed
/// (RFC 9126) or request-object (OIDC Core section 6) variants.</param>
/// <param name="validator">Performs protocol-level validation of the resolved request prior to processing.</param>
/// <param name="processor">Produces the validated authorization result projected onto the wire.</param>
/// <param name="responseEncoder">Applies iss/scope gating and, for a JARM request, packs the response
/// parameters into the response JWT, at the single convergence point for success and every error variant.</param>
/// <param name="clientInfoProvider">The client store, which every step of one request asks through one
/// <see cref="RequestScopedClientInfoProvider"/>, so the request finds its client once.</param>
/// <param name="redirectUriTrust">Decides whether an authorization error may be redirected to the client.</param>
/// <param name="authSessionService">The host's sessions, which tell whether the end user is authenticated before an
/// error is redirected.</param>
/// <param name="cutoffChecker">The revocation cutoffs, so a session the server no longer honors counts as nobody
/// signed in.</param>
[SuppressMessage("SonarQube", "S107:Methods should not have too many parameters",
    Justification = "Every dependency decides a different step of one request: the client store, the fetch, the validation, the processing, the encoding, the trust in the client's redirect URIs and the two that tell whether the end user is authenticated.")]
public class AuthorizationHandler(
    IClientInfoProvider clientInfoProvider,
    IAuthorizationRequestFetcher fetcher,
    IAuthorizationRequestValidator validator,
    IAuthorizationRequestProcessor processor,
    IAuthorizationResponseEncoder responseEncoder,
    IRedirectUriTrustPolicy redirectUriTrust,
    IAuthSessionService authSessionService,
    IRevocationCutoffChecker cutoffChecker)
    : IAuthorizationHandler
{
    private readonly UnrevokedSessions _unrevoked = new(cutoffChecker);

    /// <summary>
    /// Asynchronously handles an authorization request by first fetching the request if necessary,
    /// validating the request and then processing it to generate an authorization response.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="request">The authorization request to be handled. This can be a direct request or a reference
    /// to an external request that needs to be fetched.</param>
    /// <returns>A task that returns an <see cref="AuthorizationResponse"/>.
    /// This response can be either an authorization success response or an error response based on the fetching,
    /// validation and processing outcomes.</returns>
    /// <exception cref="UnexpectedTypeException">Thrown if the validation result is of an unexpected type.</exception>
    /// <remarks>
    /// The handling process involves three main steps:
    /// 1. Fetching of the authorization request if specified by a request or request_uri parameter.
    /// 2. Validation of the authorization request against predefined criteria to ensure its legitimacy and completeness.
    /// 3. Processing of the validated request to generate an authorization response, which could involve user
    ///    authentication, consent handling, and token issuance.
    ///
    /// This method ensures that only requests meeting the necessary validation criteria are processed,
    /// maintaining the integrity and security of the authorization flow.
    /// </remarks>
    public async Task<AuthorizationResponse> HandleAsync(TenantDefinition tenant, Model.AuthorizationRequest request)
    {
        // Produce the response through the full processing chain (including the session-management
        // decorator that sets session_state), then let the encoder apply iss/scope gating and - for a
        // JARM request - pack the parameters into the response JWT. Encoding happens here, at the single
        // convergence point for success and every error variant, after session_state is finalised.
        var clients = new RequestScopedClientInfoProvider(clientInfoProvider);
        var response = await ProduceResponseAsync(tenant, request, clients);
        if (await AuthenticationOwedAsync(tenant, response) is { } login)
            return login;

        var encoded = await responseEncoder.EncodeAsync(tenant, response, clients);
        return await KeptAtTheServerUnlessTrustedAsync(tenant, encoded, clients);
    }

    /// <summary>
    /// The login an authorization error owes before it is redirected, when nobody is signed in. RFC 9700 section
    /// 4.11.2: "The authorization server MUST always authenticate the user first and, with the exception of the silent
    /// authentication use case, prompt the user for credentials when needed, before redirecting the user."
    /// </summary>
    /// <remarks>
    /// The end user goes to the login page as a valid request without a session does, the request stored for the page
    /// as it was fetched. The page sends it back by its request_uri, the request fails the same check again, and the
    /// error then goes on as one with a session: redirected to a trusted client, answered at the server for another. A
    /// silent request (<c>prompt=none</c>) cannot show a login page, so its error is answered at once, and an error
    /// without a redirect URI is answered by the server anyway.
    /// </remarks>
    private async Task<LoginRequired?> AuthenticationOwedAsync(TenantDefinition tenant, AuthorizationResponse response)
    {
        if (response is not AuthorizationError { RedirectUri: not null, Model: var model } ||
            PromptPages.Asks(model, Prompts.None))
        {
            return null;
        }

        return await _unrevoked.AnyAsync(tenant, authSessionService.GetAvailableAuthSessions())
            ? null
            : new LoginRequired(model);
    }

    /// <summary>
    /// An authorization error for a client whose redirect URIs are not trusted, answered by the server rather than at
    /// the client's redirect URI. RFC 9700 section 4.11.2 has the server "only automatically redirect the user agent if
    /// it trusts the redirection URI", while every error reaches the user agent without the end user choosing that
    /// client: a refused request, a declined consent, a silent request. Decided once, after encoding, so an error the encoder
    /// itself makes of a response it could not pack is held to it too, and a packed one is answered without its JWT.
    /// </summary>
    private async Task<AuthorizationResponse> KeptAtTheServerUnlessTrustedAsync(
        TenantDefinition tenant,
        AuthorizationResponse response,
        IClientInfoProvider clients)
    {
        if (response is not AuthorizationError { RedirectUri: not null, Model.ClientId: { } clientId } error)
            return response;

        var found = await clients.FindClientAsync(tenant, clientId);
        if (found.TryGetSuccess(out var client) && await redirectUriTrust.IsTrustedAsync(tenant, client))
            return error;

        return error with { RedirectUri = null, ResponseJwt = null };
    }

    private async Task<AuthorizationResponse> ProduceResponseAsync(
        TenantDefinition tenant,
        Model.AuthorizationRequest request,
        IClientInfoProvider clients)
    {
        var fetchResult = await fetcher.FetchAsync(tenant, request, clients);

        if (fetchResult.TryGetFailure(out var fetchError))
            return new AuthorizationError(request, fetchError);

        request = fetchResult.GetSuccess();

        var validationResult = await validator.ValidateAsync(tenant, request, clients);

        return await validationResult.MatchAsync(
            onSuccess: valid => processor.ProcessAsync(tenant, valid),
            onFailure: error => Task.FromResult<AuthorizationResponse>(new AuthorizationError(request, error)));
    }
}
