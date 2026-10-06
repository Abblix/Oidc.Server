// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

/// <summary>
/// Adapter class that implements <see cref="IAuthorizationRequestFetcher"/> to delegate the
/// fetching and processing of request objects to an instance of <see cref="IRequestObjectFetcher"/>.
/// </summary>
/// <param name="requestObjectFetcher">The request object fetcher responsible for fetching and processing
/// the JWT request object.</param>
public class RequestObjectFetchAdapter(IRequestObjectFetcher requestObjectFetcher) : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Fetches and processes the authorization request by delegating to the request object fetcher.
    /// The request object JWT is validated and its claims are merged into the authorization request.
    /// Client identification is performed using the request parameter, JWT issuer claim, or JWT client_id claim,
    /// with validation ensuring all present sources match.
    /// </summary>
    /// <param name="request">The authorization request to be processed.</param>
    /// <returns>
    /// A task that returns a <see cref="Result{AuthorizationRequest, AuthorizationRequestValidationError}"/>
    /// which either represents a successfully processed request with merged JWT claims or an error indicating
    /// issues with the request object validation (invalid JWT, client identification failure, or claim mismatch).
    /// </returns>
    public async Task<Result<AuthorizationRequest, AuthorizationRequestValidationError>> FetchAsync(
        AuthorizationRequest request)
    {
        var fetchResult = await requestObjectFetcher.FetchAsync(
            request, request.Request, client => client.RequestObjectSigningAlgorithm);

        // The merge rebuilds the request from its wire form, which leaves out what the server set on the request it
        // stored: carried over, or a pushed request_uri is never consumed and a stored request never learns the end
        // user was sent to log in
        return fetchResult
            .Bind(merged => ValidateMergedParameters(request, merged with
            {
                PushedRequestUri = request.PushedRequestUri,
                OriginRequestUri = request.OriginRequestUri,
                PromptedAt = request.PromptedAt,
            }))
            .MapFailure(error => ErrorFactory.ValidationError(error.Error, error.ErrorDescription));
    }

    /// <summary>
    /// The <c>prompt</c> values the request model declares supported.
    /// </summary>
    private static readonly string[] SupportedPrompts = typeof(AuthorizationRequest)
        .GetProperty(nameof(AuthorizationRequest.Prompt))!
        .GetCustomAttribute<AllowedValuesAttribute>()!
        .AllowedValues;

    /// <summary>
    /// OIDC Core section 6.1: the response_type and client_id values passed in the OAuth request syntax
    /// MUST match the ones inside the request object when the object carries them. The merge gives
    /// the request object's values precedence, so a mismatch surfaces as the merged value differing
    /// from the outer one - without this check an attacker-supplied object could silently swap the
    /// flow or the client identity relative to what the plain OAuth parameters declared. A prompt value outside
    /// <see cref="SupportedPrompts"/> is refused with invalid_request, as the same value is in the query.
    /// </summary>
    private static Result<AuthorizationRequest, OidcError> ValidateMergedParameters(
        AuthorizationRequest outer,
        AuthorizationRequest merged)
    {
        if (outer.ClientId != null && merged.ClientId != outer.ClientId)
        {
            return new OidcError(
                ErrorCodes.InvalidRequestObject,
                $"The {AuthorizationRequest.Parameters.ClientId} inside the request object " +
                "does not match the one outside of it");
        }

        if (outer.ResponseType != null && merged.ResponseType != null &&
            !outer.ResponseType.ToHashSet(StringComparer.Ordinal).SetEquals(merged.ResponseType))
        {
            return new OidcError(
                ErrorCodes.InvalidRequestObject,
                $"The {AuthorizationRequest.Parameters.ResponseType} inside the request object " +
                "does not match the one outside of it");
        }

        // After the two bindings above: a request object rebinding the request is the graver fault, and the client
        // is told about that one first
        // The request object is read past the adapters' models, whose declared value list refuses an unsupported
        // prompt in the query, so the same list refuses it here
        if (merged.Prompt?.FirstOrDefault(value => !SupportedPrompts.Contains(value, StringComparer.Ordinal))
            is { } unsupported)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The {AuthorizationRequest.Parameters.Prompt} value '{unsupported}' inside the request object " +
                "is not supported");
        }

        return merged;
    }
}
