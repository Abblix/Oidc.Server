// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using System.Reflection;
using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Oidc.Server.Features.MultiTenancy;
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
/// <param name="clientInfoProvider">Finds the client the request names outside the object.</param>
public class RequestObjectFetchAdapter(
    IRequestObjectFetcher requestObjectFetcher,
    IClientInfoProvider clientInfoProvider) : IAuthorizationRequestFetcher
{
    /// <summary>
    /// Fetches and processes the authorization request by delegating to the request object fetcher.
    /// The request object JWT is validated and its claims are merged into the authorization request.
    /// Client identification is performed using the request parameter, JWT issuer claim, or JWT client_id claim,
    /// with validation ensuring all present sources match.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="request">The authorization request to be processed.</param>
    /// <returns>
    /// A task that returns a <see cref="Result{AuthorizationRequest, AuthorizationRequestValidationError}"/>
    /// which either represents a successfully processed request with merged JWT claims or an error indicating
    /// issues with the request object validation (invalid JWT, client identification failure, or claim mismatch).
    /// </returns>
    public async Task<Result<AuthorizationRequest, AuthorizationRequestValidationError>> FetchAsync(
        TenantDefinition tenant,
        AuthorizationRequest request)
    {
        // A request read back from storage had its object validated and applied before it was stored, and carries what
        // the server set on it since: the URN it is consumed under, the pages the end user was sent to, the DPoP key the
        // code is bound to. Applying the object again would rebuild the request without them under strict processing,
        // and would refuse an end user returning from a slow login once the object expired
        if (request.PushedRequestUri is not null)
            return request;

        // RFC 9101 section 5: "client_id REQUIRED. OAuth 2.0 [RFC6749] "client_id". The value MUST match the "request"
        // or "request_uri" Request Object's (Section 2.1) "client_id"", and section 6.3 has a failed client ID check
        // answered as "specified in Section 5.2 of [RFC6749]". So the client is known before the object
        // is read, and the object is held to its profile up front
        ClientInfo? namedClient = null;
        if (request.Request is not null)
        {
            if (request.ClientId is not { Length: > 0 } clientId)
            {
                return ErrorFactory.ValidationError(
                    ErrorCodes.InvalidRequest,
                    $"The {AuthorizationRequest.Parameters.ClientId} parameter is required beside a request object");
            }

            namedClient = await clientInfoProvider.TryFindClientAsync(tenant, clientId);
        }

        // RFC 9101 section 6.3: "The client ID values in the "client_id" request parameter and in the Request Object
        // "client_id" claim MUST be identical", and section 4 has the object contain every parameter but "request" and
        // "request_uri". The outer client_id is left out of what the object is merged over, so the comparison below
        // refuses an object naming no client as it refuses one naming another
        var mergedOver = request.Request.HasValue() ? request with { ClientId = null } : request;
        var fetchResult = await requestObjectFetcher.FetchAsync(tenant,
            namedClient, mergedOver, request.Request, client => client.RequestObjectSigningAlgorithm, ForbiddenMembers,
            _ => null);

        // Strict processing (RFC 9101 section 6.3) rebuilds the request from the object alone, which drops the request
        // parameter carrying that object, so the validated object is carried on: without it a client required to sign
        // its request objects is refused for having sent one. A response mode that is empty or whitespace alone is
        // none, as both hosts read the same value in the query
        return fetchResult
            .Bind(merged => ValidateMergedParameters(request, merged with
            {
                Request = request.Request,
                ResponseMode = string.IsNullOrWhiteSpace(merged.ResponseMode) ? null : merged.ResponseMode,
            }))
            .MapFailure(error => ErrorFactory.ValidationError(error.Error, error.ErrorDescription));
    }

    /// <summary>
    /// RFC 9101 section 4: ""request" and "request_uri" parameters MUST NOT be included in Request Objects", and
    /// section 7 has "invalid_request_object The request parameter contains an invalid Request Object". Refused for
    /// an object by value and for one fetched from a request_uri alike. The pushed authorization request endpoint
    /// reads its object through this adapter too, since RFC 9126 section 2.1 step 3 has the server "Validate the pushed
    /// request as it would an authorization request sent to the authorization endpoint" and section 3 has "The rules
    /// for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply".
    /// </summary>
    private static readonly string[] ForbiddenMembers =
    [
        AuthorizationRequest.Parameters.Request,
        AuthorizationRequest.Parameters.RequestUri,
    ];

    /// <summary>
    /// The <c>prompt</c> values the request model declares supported.
    /// </summary>
    private static readonly string[] SupportedPrompts = DeclaredValuesOf(nameof(AuthorizationRequest.Prompt));

    /// <summary>
    /// The <c>response_mode</c> values the request model declares supported.
    /// </summary>
    private static readonly string[] SupportedResponseModes =
        DeclaredValuesOf(nameof(AuthorizationRequest.ResponseMode));

    /// <summary>
    /// The value list the request model declares on a property, which refuses a value outside it in the query.
    /// </summary>
    private static string[] DeclaredValuesOf(string property) => typeof(AuthorizationRequest)
        .GetProperty(property)!
        .GetCustomAttribute<AllowedValuesAttribute>()!
        .AllowedValues;

    /// <summary>
    /// OIDC Core section 6.1: the response_type and client_id values passed in the OAuth request syntax
    /// MUST match the ones inside the request object when the object carries them. The merge gives
    /// the request object's values precedence, so a mismatch surfaces as the merged value differing
    /// from the outer one - without this check an attacker-supplied object could silently swap the
    /// flow or the client identity relative to what the plain OAuth parameters declared. The object is merged over a
    /// request without its client_id, so an object carrying none is refused as well (RFC 9101 section 6.3). A prompt
    /// value outside <see cref="SupportedPrompts"/>, or a response mode outside <see cref="SupportedResponseModes"/>,
    /// is refused with invalid_request, as the same value is in the query.
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
        if (merged.Prompt?.Any(value => !SupportedPrompts.Contains(value, StringComparer.Ordinal)) == true)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The {AuthorizationRequest.Parameters.Prompt} inside the request object has a value that is " +
                "not supported");
        }

        if (merged.ResponseMode is { } responseMode &&
            !SupportedResponseModes.Contains(responseMode, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The {AuthorizationRequest.Parameters.ResponseMode} inside the request object has a value that is " +
                "not supported");
        }

        return merged;
    }
}
