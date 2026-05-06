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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Handles the processing of authorization requests by validating and then processing these requests based
/// on defined business logic. It also includes the fetching of authorization requests when necessary.
/// </summary>
/// <param name="fetcher">The service responsible for fetching external authorization requests when
/// specified by a request or request_uri parameter.</param>
/// <param name="validator">The service responsible for validating authorization requests.</param>
/// <param name="processor">The service responsible for processing validated authorization requests.</param>
/// <param name="responseProcessors">The set of registered authorization response processors. The
/// supported response types and grant types contributed to discovery are derived from this set:
/// without <c>EnableImplicitFlow()</c> the <c>token</c> / <c>id_token</c> processors are absent and
/// the discovery document advertises only the Code Flow as supported.</param>
public class AuthorizationHandler(
    IAuthorizationRequestFetcher fetcher,
    IAuthorizationRequestValidator validator,
    IAuthorizationRequestProcessor processor,
    IEnumerable<IAuthorizationResponseProcessor> responseProcessors) : IAuthorizationHandler
{
    /// <summary>
    /// Canonical response-type combinations defined across OAuth 2.0 / OIDC. A combination is
    /// advertised in discovery only if every one of its parts has a registered response processor.
    /// </summary>
    private static readonly string[][] CanonicalResponseTypeCombinations =
    [
        [ResponseTypes.Code],
        [ResponseTypes.Token],
        [ResponseTypes.IdToken],
        [ResponseTypes.Code, ResponseTypes.Token],
        [ResponseTypes.Code, ResponseTypes.IdToken],
        [ResponseTypes.Token, ResponseTypes.IdToken],
        [ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken],
    ];

    // OrdinalIgnoreCase mirrors the codebase's historical tolerance for response_type case
    // variations (FlowTypeValidator does the same).
    private readonly IReadOnlySet<string> _supportedResponseTypeParts =
        responseProcessors.Select(b => b.ResponseType).ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public AuthorizationEndpointMetadata Metadata => new()
    {
        RequestParameterSupported = true,
        ClaimsParameterSupported = true,
        ResponseTypesSupported = CanonicalResponseTypeCombinations
            .Where(combo => Array.TrueForAll(combo, _supportedResponseTypeParts.Contains))
            .Select(combo => string.Join(' ', combo))
            .ToList(),
    };

    /// <summary>
    /// Grant types contributed by the authorization endpoint to the <c>grant_types_supported</c>
    /// discovery list. The <c>implicit</c> grant is advertised only when at least one of the
    /// implicit response-type processors (<c>token</c> or <c>id_token</c>) is registered, i.e. when
    /// the host called <c>EnableImplicitFlow()</c>. The <c>authorization_code</c> grant is
    /// contributed instead by the token endpoint.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get
        {
            if (_supportedResponseTypeParts.Contains(ResponseTypes.Token) ||
                _supportedResponseTypeParts.Contains(ResponseTypes.IdToken))
            {
                yield return GrantTypes.Implicit;
            }
        }
    }

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
        var fetchResult = await fetcher.FetchAsync(request);

        if (fetchResult.TryGetFailure(out var fetchError))
            return new AuthorizationError(request, fetchError);

        request = fetchResult.GetSuccess();

        var validationResult = await validator.ValidateAsync(request);

        return await validationResult.MatchAsync(
            onSuccess: processor.ProcessAsync,
            onFailure: error => Task.FromResult<AuthorizationResponse>(new AuthorizationError(request, error)));
    }
}
