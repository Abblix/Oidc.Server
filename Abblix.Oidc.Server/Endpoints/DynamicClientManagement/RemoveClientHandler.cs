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
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Manages the removal of registered clients from the authorization server, ensuring that requests for client
/// unregistration are handled securely and in accordance with OAuth 2.0 and OpenID Connect standards.
/// </summary>
public class RemoveClientHandler : IRemoveClientHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RemoveClientHandler"/> class with the specified validator
    /// and processor services.
    /// </summary>
    /// <param name="validator">The service used to validate incoming client removal requests.</param>
    /// <param name="processor">The service responsible for processing validated removal requests and unregistering
    /// the client.</param>
    public RemoveClientHandler(
        IClientRequestValidator validator,
        IRemoveClientRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly IClientRequestValidator _validator;
    private readonly IRemoveClientRequestProcessor _processor;

    /// <summary>
    /// Asynchronously processes a request to remove a registered client, ensuring the request is valid and authorized
    /// before proceeding with client unregistration.
    /// </summary>
    /// <param name="clientRequest">The client request containing necessary information for identifying and removing
    /// the specified client.</param>
    /// <returns>A task that results in a <see cref="RemoveClientResponse"/>, which encapsulates the outcome of
    /// the removal process, including success or error information.</returns>
    /// <exception cref="UnexpectedTypeException">
    /// Thrown if the result of the validation process is of an unexpected type, indicating a potential issue
    /// in the request handling pipeline.</exception>
    /// <remarks>
    /// This method follows a two-step process: first, validating the removal request to ensure it meets all
    /// required criteria and is authorized; second, if validation succeeds, processing the request to unregister
    /// the client from the system. This approach ensures that client removal is managed securely and aligns with
    /// best practices in client management within OAuth 2.0 and OpenID Connect frameworks.
    /// </remarks>
    public async Task<RemoveClientResponse> HandleAsync(ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(clientRequest);

        var response = validationResult switch
        {
            ValidClientRequest validRequest => await _processor.ProcessAsync(validRequest),

            ClientRequestValidationError { Error: var error, ErrorDescription: var description }
                => new RemoveClientErrorResponse(error, description),

            _ => throw new UnexpectedTypeException(nameof(validationResult), validationResult.GetType())
        };
        return response;
    }
}
