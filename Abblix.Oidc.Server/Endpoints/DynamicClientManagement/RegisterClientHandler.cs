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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles dynamic registration of clients in accordance with OAuth 2.0 and OpenID Connect specifications.
/// This class validates and processes incoming client registration requests, issuing client identifiers and
/// client secrets as appropriate.
/// </summary>
public class RegisterClientHandler : IRegisterClientHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RegisterClientHandler"/> class with the specified validator
    /// and processor.
    /// </summary>
    /// <param name="validator">The validator responsible for ensuring that client registration requests meet
    /// the required criteria.</param>
    /// <param name="processor">The processor responsible for the actual registration of the client,
    /// generating client identifiers and secrets.</param>
    public RegisterClientHandler(
        IRegisterClientRequestValidator validator,
        IRegisterClientRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly IRegisterClientRequestValidator _validator;
    private readonly IRegisterClientRequestProcessor _processor;

    /// <summary>
    /// Asynchronously handles a client registration request, validating the request and processing it to register
    /// the client.
    /// </summary>
    /// <param name="clientRegistrationRequest">The client registration request containing the necessary information
    /// for registering a new client.</param>
    /// <returns>A task that results in a <see cref="ClientRegistrationResponse"/>, encapsulating the outcome of
    /// the registration process.
    /// This could be a successful response with client details or an error response indicating the reasons for failure.
    /// </returns>
    /// <exception cref="UnexpectedTypeException">Thrown if the validation result is of an unexpected type,
    /// indicating an implementation error.</exception>
    /// <remarks>
    /// This method is central to the dynamic client registration feature, allowing clients to register themselves
    /// with the authorization server without direct administrative intervention. It supports the OpenID Connect
    /// Dynamic Client Registration specification, ensuring compliance and interoperability.
    /// </remarks>

    public async Task<ClientRegistrationResponse> HandleAsync(Model.ClientRegistrationRequest clientRegistrationRequest)
    {
        var validationResult = await _validator.ValidateAsync(clientRegistrationRequest);

        return validationResult switch
        {
            ValidClientRegistrationRequest validRequest => await _processor.ProcessAsync(validRequest),

            ClientRegistrationValidationError { Error: var error, ErrorDescription: var description }
                => new ClientRegistrationErrorResponse(error, description),

            _ => throw new UnexpectedTypeException(nameof(validationResult), validationResult.GetType())
        };
    }
}
