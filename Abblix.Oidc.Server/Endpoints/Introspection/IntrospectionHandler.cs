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
