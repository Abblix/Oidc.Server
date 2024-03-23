// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Handles the processing of authorization requests by validating and then processing these requests based
/// on defined business logic. It also includes the fetching of authorization requests when necessary.
/// </summary>
public class AuthorizationHandler : IAuthorizationHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationHandler"/> class with the specified request fetcher,
    /// validator and processor.
    /// </summary>
    /// <param name="fetcher">The service responsible for fetching external authorization requests when
    /// specified by a request or request_uri parameter.</param>
    /// <param name="validator">The service responsible for validating authorization requests.</param>
    /// <param name="processor">The service responsible for processing validated authorization requests.</param>
    public AuthorizationHandler(
        IAuthorizationRequestFetcher fetcher,
        IAuthorizationRequestValidator validator,
        IAuthorizationRequestProcessor processor)
    {
        _fetcher = fetcher;
        _validator = validator;
        _processor = processor;
    }

    private readonly IAuthorizationRequestFetcher _fetcher;
    private readonly IAuthorizationRequestValidator _validator;
    private readonly IAuthorizationRequestProcessor _processor;

    public AuthorizationEndpointMetadata Metadata => new()
    {
        RequestParameterSupported = true,
        ClaimsParameterSupported = true,
    };

    /// <summary>
    /// Asynchronously handles an authorization request by first fetching the request if necessary,
    /// validating the request and then processing it to generate an authorization response.
    /// </summary>
    /// <param name="request">The authorization request to be handled. This can be a direct request or a reference
    /// to an external request that needs to be fetched.</param>
    /// <returns>A task that represents the asynchronous operation, resulting in an <see cref="AuthorizationResponse"/>.
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
        switch (fetchResult)
        {
            case FetchResult.Success success:
                request = success.Request;
                break;

            case FetchResult.Fault { Error: var error }:
                return new AuthorizationError(request, error);
        }

        var validationResult = await _validator.ValidateAsync(request);
        return validationResult switch
        {
            ValidAuthorizationRequest validRequest => await _processor.ProcessAsync(validRequest),
            AuthorizationRequestValidationError error => new AuthorizationError(request, error),
            _ => throw new UnexpectedTypeException(nameof(validationResult), validationResult.GetType()),
        };
    }
}
