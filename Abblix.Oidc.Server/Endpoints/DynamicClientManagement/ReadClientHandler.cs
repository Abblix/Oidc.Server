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
/// Handles requests for reading client configurations from the authorization server.
/// Validates and processes requests to retrieve information about registered clients.
/// </summary>
public class ReadClientHandler : IReadClientHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ReadClientHandler"/> class with specified validator and processor
    /// services.
    /// </summary>
    /// <param name="validator">The service used to validate client information requests.</param>
    /// <param name="processor">The service responsible for processing valid client information requests and retrieving
    /// client data.</param>
    public ReadClientHandler(
        IClientRequestValidator validator,
        IReadClientRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly IClientRequestValidator _validator;
    private readonly IReadClientRequestProcessor _processor;

    /// <summary>
    /// Asynchronously handles a request to read client information, validating the request and processing it to return
    /// the requested client data.
    /// </summary>
    /// <param name="clientRequest">The client request containing details necessary for fetching the client information,
    /// such as the client identifier.</param>
    /// <returns>A task that results in a <see cref="ReadClientResponse"/>, which could be the requested client data or
    /// an error response.</returns>
    /// <exception cref="UnexpectedTypeException">Thrown if the validation result does not match expected types.
    /// </exception>
    /// <remarks>
    /// This method serves as a critical part of dynamic client management, allowing for the secure retrieval of client
    /// configurations. It ensures that only valid requests are processed, safeguarding against unauthorized access
    /// to client information.
    /// </remarks>
    public async Task<ReadClientResponse> HandleAsync(Model.ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(clientRequest);

        return validationResult switch
        {
            ValidClientRequest validRequest => await _processor.ProcessAsync(validRequest),

            ClientRequestValidationError { Error: var error, ErrorDescription: var description }
                => new ReadClientErrorResponse(error, description),

            _ => throw new UnexpectedTypeException(nameof(validationResult), validationResult.GetType()),
        };
    }
}
