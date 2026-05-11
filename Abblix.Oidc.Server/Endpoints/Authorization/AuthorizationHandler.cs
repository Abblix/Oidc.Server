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
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Handles authorization requests by fetching, validating, and delegating processing.
/// Aggregates <c>response_types_supported</c> and <c>grant_types_supported</c> for discovery
/// from the registered set of <see cref="IAuthorizationResponseBuilder"/>: each processor
/// declares the response-type it owns and (via <see cref="IGrantTypeInformer"/>) the
/// grant-type it exposes, so the handler is no longer the source of truth for the mapping
/// — adding a new processor automatically extends both discovery lists.
/// </summary>
/// <remarks>
/// The class deliberately uses an explicit constructor instead of a primary constructor: a
/// single pass over <see cref="IEnumerable{IAuthorizationResponseBuilder}"/> populates
/// both supported-response-types and supported-grant-types sets, while a primary-ctor body
/// would either iterate the enumerable twice (one Select for response types, one SelectMany
/// for grant types) or store the enumerable itself and risk re-enumerating on every read.
/// Single-pass is the cheapest correct shape; the cost is dropping the primary-ctor form.
/// </remarks>
public class AuthorizationHandler : IAuthorizationHandler
{
    /// <summary>
    /// Initialises a new <see cref="AuthorizationHandler"/> and computes the discovery
    /// metadata (<c>response_types_supported</c> and <c>grant_types_supported</c>) in a
    /// single pass over the supplied response builders.
    /// </summary>
    /// <param name="fetcher">Resolves the effective authorization request, including
    /// dereferencing pushed (RFC 9126) or request-object (OIDC Core §6) variants.</param>
    /// <param name="validator">Performs protocol-level validation of the resolved
    /// request prior to processing.</param>
    /// <param name="processor">Produces the validated authorization result that the
    /// selected response builder then projects onto the wire.</param>
    /// <param name="responseBuilders">The set of registered response builders. Each
    /// declares the response-type it owns and the grant-types it exposes, so adding a
    /// builder automatically extends both discovery lists.</param>
    public AuthorizationHandler(
        IAuthorizationRequestFetcher fetcher,
        IAuthorizationRequestValidator validator,
        IAuthorizationRequestProcessor processor,
        IEnumerable<IAuthorizationResponseBuilder> responseBuilders)
    {
        _fetcher = fetcher;
        _validator = validator;
        _processor = processor;

        // RFC 6749 §3.1.1 declares response_type values case-sensitive; OIDC Core §3 inherits
        // the same casing rules. We compare with Ordinal so a host-supplied processor that
        // declares a non-canonical case (e.g. "Code") is correctly rejected as an unsupported
        // response type rather than silently merged with the spec-defined "code".
        var supportedResponseTypes = new HashSet<string>(StringComparer.Ordinal);

        // RFC 6749 §3.2.1 fixes grant_type parameter values as lowercase literals
        // ("authorization_code", "password", "client_credentials", "refresh_token", and
        // "implicit" inherited from the §1.3.2 mapping). Same Ordinal comparer for the same
        // reason as response_type — a non-canonical-case host registration is treated as
        // unsupported, not silently aliased to the spec value.
        var grantTypesSupported = new HashSet<string>(StringComparer.Ordinal);

        foreach (var responseProcessor in responseBuilders)
        {
            supportedResponseTypes.Add(responseProcessor.ResponseType);

            foreach (var grantType in responseProcessor.GrantTypesSupported)
                grantTypesSupported.Add(grantType);
        }

        GrantTypesSupported = grantTypesSupported;

        string[][] canonicalResponseTypeCombinations =
        [
            [ResponseTypes.Code],
            [ResponseTypes.Token],
            [ResponseTypes.IdToken],
            [ResponseTypes.Code, ResponseTypes.Token],
            [ResponseTypes.Code, ResponseTypes.IdToken],
            [ResponseTypes.Token, ResponseTypes.IdToken],
            [ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken],
        ];

        var responseTypesSupported = canonicalResponseTypeCombinations
            .Where(combo => Array.TrueForAll(combo, supportedResponseTypes.Contains))
            .Select(combo => string.Join(' ', combo))
            .ToList();

        Metadata = new()
        {
            RequestParameterSupported = true,
            ClaimsParameterSupported = true,
            ResponseTypesSupported = responseTypesSupported,
        };
    }

    private readonly IAuthorizationRequestFetcher _fetcher;
    private readonly IAuthorizationRequestValidator _validator;
    private readonly IAuthorizationRequestProcessor _processor;

    /// <inheritdoc />
    public AuthorizationEndpointMetadata Metadata { get; }

    /// <summary>
    /// Grant types contributed by the authorization endpoint to the
    /// <c>grant_types_supported</c> discovery list, aggregated from every registered
    /// <see cref="IAuthorizationResponseBuilder"/>: the <c>code</c> processor yields
    /// <c>authorization_code</c>, the <c>token</c> / <c>id_token</c> processors yield
    /// <c>implicit</c>. The handler does not encode the response-type ↔ grant-type mapping
    /// itself — each processor declares its own grant via
    /// <see cref="IGrantTypeInformer.GrantTypesSupported"/>.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported { get; }

    /// <summary>
    /// Asynchronously handles an authorization request by first fetching the request if necessary,
    /// validating the request and then processing it to generate an authorization response.
    /// </summary>
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
    public async Task<AuthorizationResponse> HandleAsync(AuthorizationRequest request)
    {
        var fetchResult = await _fetcher.FetchAsync(request);

        if (fetchResult.TryGetFailure(out var fetchError))
            return new AuthorizationError(request, fetchError);

        request = fetchResult.GetSuccess();

        var validationResult = await _validator.ValidateAsync(request);

        return await validationResult.MatchAsync(
            onSuccess: _processor.ProcessAsync,
            onFailure: error => Task.FromResult<AuthorizationResponse>(new AuthorizationError(request, error)));
    }
}
