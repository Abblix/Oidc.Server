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
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Introspection;

/// <summary>
/// Manages the processing of token introspection requests according to OAuth 2.0 specifications, facilitating
/// the validation and introspection of tokens to determine their current state and metadata.
/// </summary>
public class IntrospectionHandler : IIntrospectionHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IntrospectionHandler"/> class, equipping it with the necessary
    /// components to validate and process introspection requests.
    /// </summary>
    /// <param name="validator">An implementation of <see cref="IIntrospectionRequestValidator"/> tasked with
    /// validating introspection requests against OAuth 2.0 standards.</param>
    /// <param name="processor">An implementation of <see cref="IIntrospectionRequestProcessor"/> responsible
    /// for processing validated introspection requests and retrieving token information.</param>
    public IntrospectionHandler(
        IIntrospectionRequestValidator validator,
        IIntrospectionRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly IIntrospectionRequestValidator _validator;
    private readonly IIntrospectionRequestProcessor _processor;

    /// <summary>
    /// Asynchronously handles an introspection request by validating the request and, if valid, processing it to
    /// return the state and metadata of the specified token.
    /// </summary>
    /// <param name="introspectionRequest">The introspection request containing the token to be introspected and
    /// other relevant parameters.</param>
    /// <param name="clientRequest">Supplementary information about the client making the request,
    /// useful for contextual validation.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to an <see cref="IntrospectionResponse"/>, which includes the token's
    /// active status and potentially other metadata, or an error response if the request is invalid.
    /// </returns>
    /// <remarks>
    /// Implementations of this method are crucial for maintaining the integrity and security of token-based
    /// authentication systems by allowing resource servers and other entities to verify the validity
    /// and attributes of tokens.
    /// </remarks>
    public async Task<IntrospectionResponse> HandleAsync(
        IntrospectionRequest introspectionRequest,
        ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(introspectionRequest, clientRequest);

        return validationResult switch
        {
            ValidIntrospectionRequest validRequest => await _processor.ProcessAsync(validRequest),

            IntrospectionRequestValidationError { Error: var error, ErrorDescription: var description }
                => new IntrospectionErrorResponse(error, description),

            _ => throw new UnexpectedTypeException(nameof(validationResult), validationResult.GetType())
        };
    }
}
