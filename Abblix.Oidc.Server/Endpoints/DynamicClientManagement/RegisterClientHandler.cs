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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Utils;

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
    /// <returns>A task that results in a Result containing the outcome of
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
    public async Task<Result<ClientRegistrationSuccessResponse, AuthError>> HandleAsync(Model.ClientRegistrationRequest clientRegistrationRequest)
    {
        var validationResult = await _validator.ValidateAsync(clientRegistrationRequest);
        return await validationResult.BindAsync(_processor.ProcessAsync);
    }
}
